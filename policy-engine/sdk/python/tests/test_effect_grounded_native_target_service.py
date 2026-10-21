"""Native ACS decisions committed by a separate process, with signed snapshots.

This test crosses a process/IPC boundary, NOT an independent administrative or
privilege boundary. The CI runner owns both processes, starts the target, reads
its bootstrap public key, and could edit the fixture SQLite file. A separately
administered real deployment must pin the target key out of band and isolate
the data store. The target's observation is a snapshot, not a global execution
completeness guarantee.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:
    # The ordinary SDK test environment omits this research-only dependency.
    # The dedicated native workflow installs it and fails on skipped tests.
    raise unittest.SkipTest("research-only Ed25519 dependency unavailable") from exc
from test_effect_grounded_native_signed_target import Action, NATIVE
from test_effect_grounded_native_dual_attestation import (
    TwoKeyTarget, decode, encode,
)
from test_effect_grounded_native_provisioned_identity import (
    NativeProvisionedWorkloadTests,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "research"))
from effect_target_protocol import (  # noqa: E402
    action_sha256, appraise_observation, signed_observation,
)


def serve_target(path, issuer_key_raw, decision_key_raw, identity_key_raw):
    """Fixture target owns commits and signatures; keys are externally pinned."""
    target = TwoKeyTarget(
        path,
        Ed25519PublicKey.from_public_bytes(decode(issuer_key_raw)),
        Ed25519PublicKey.from_public_bytes(decode(decision_key_raw)),
        identity_key=Ed25519PublicKey.from_public_bytes(decode(identity_key_raw)),
    )
    observation_key = Ed25519PrivateKey.generate()
    public = observation_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    # The test trusts this *bootstrap* output because it launches the process.
    # A real networked deployment must provision/pin the key independently.
    print(json.dumps({"ready": True, "observation_public_key": encode(public)}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if type(request) is not dict or type(request.get("op")) is not str:
                raise ValueError("invalid request")
            if request["op"] == "commit":
                if set(request) != {"op", "action", "grant", "proof", "identity"}:
                    raise ValueError("commit request schema mismatch")
                grant = request["grant"]
                if type(grant) is not dict or set(grant) != {"payload", "signature"}:
                    raise PermissionError("invalid grant envelope")
                issuer_grant = {
                    "payload": grant["payload"], "signature": decode(grant["signature"]),
                }
                action = Action(**request["action"])
                result = target.commit(
                    action, issuer_grant, request["proof"],
                    identity=request["identity"],
                )
                reply = {"result": result}
            elif request["op"] == "observe":
                if set(request) != {"op", "action_id", "nonce"}:
                    raise ValueError("observe request schema mismatch")
                action_id, nonce = request["action_id"], request["nonce"]
                if type(action_id) is not str or not action_id:
                    raise ValueError("invalid action id")
                if type(nonce) is not str or len(nonce) < 16:
                    raise ValueError("observation requires a fresh nonce")
                # A new read transaction samples the target's authoritative
                # committed state after its previous commit transaction exits.
                with sqlite3.connect(target.path) as db:
                    row = db.execute(
                        "SELECT action_bytes FROM effects WHERE action_id=?",
                        (action_id,),
                    ).fetchone()
                reply = signed_observation(
                    observation_key, action_id=action_id, nonce=nonce,
                    state="committed" if row is not None else "absent",
                    action_digest=sha256(row[0]).hexdigest() if row else None,
                )
            else:
                raise ValueError("unknown operation")
        except Exception as exc:
            reply = {"error": type(exc).__name__}
        print(json.dumps(reply), flush=True)


@unittest.skipUnless(NATIVE, "compiled native ACS is mandatory")
class TargetServiceBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Reuse the native signed-policy fixture, not a mocked policy verdict.
        # Its keys and target are *test harness* material, not independent custody.
        self.native = NativeProvisionedWorkloadTests(
            methodName="test_three_valid_signatures_commit_one_effect",
        )
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db_path = str(Path(self.tmp.name) / "target.sqlite3")
        raw = lambda key: encode(key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        self.server = subprocess.Popen(
            [
                sys.executable, "-u", str(Path(__file__).resolve()),
                "--target-server", db_path,
                raw(self.native.issuer.public),
                raw(self.native.policy_public),
                raw(self.native.identity.public),
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.addCleanup(self.close_server)
        hello_line = self.server.stdout.readline()
        if not hello_line:
            raise RuntimeError("target service failed to start")
        hello = json.loads(hello_line)
        if set(hello) != {"ready", "observation_public_key"} or hello["ready"] is not True:
            raise RuntimeError("unexpected target bootstrap")
        self.observation_key = Ed25519PublicKey.from_public_bytes(
            decode(hello["observation_public_key"]),
        )
        self.action = self.native.action

    def close_server(self):
        if self.server.poll() is None:
            self.server.stdin.close()
            self.server.wait(timeout=5)
        self.server.stdout.close()
        self.server.stderr.close()

    def rpc(self, request):
        if self.server.poll() is not None:
            raise RuntimeError("target service exited")
        self.server.stdin.write(json.dumps(request) + "\n")
        self.server.stdin.flush()
        line = self.server.stdout.readline()
        if not line:
            raise RuntimeError("target service unavailable")
        return json.loads(line)

    def authorization(self, action=None):
        action = self.action if action is None else action
        identity = self.native.identity.issue(action)
        decision = self.native.evaluate(action, identity)
        grant = self.native.issuer.sign(action)
        return {
            "op": "commit", "action": action.args(),
            "grant": {
                "payload": grant["payload"],
                "signature": encode(grant["signature"]),
            },
            "proof": decision, "identity": identity,
        }

    def observe(self, action=None, nonce=None):
        action = self.action if action is None else action
        nonce = uuid4().hex if nonce is None else nonce
        receipt = self.rpc({
            "op": "observe", "action_id": action.action_id, "nonce": nonce,
        })
        return (
            appraise_observation(
                receipt, self.observation_key, action=action.args(), nonce=nonce,
            ),
            receipt,
            nonce,
        )

    def test_authorized_three_signature_commit_has_signed_target_evidence(self):
        self.assertEqual(self.rpc(self.authorization()), {"result": "committed"})
        verdict, receipt, _ = self.observe()
        self.assertEqual(verdict, "established")
        self.assertEqual(receipt["payload"]["action_sha256"],
                         action_sha256(self.action.args()))

    def test_no_commit_is_refuted_only_for_target_snapshot(self):
        verdict, receipt, _ = self.observe()
        self.assertEqual(verdict, "refuted")
        self.assertEqual(receipt["payload"]["state"], "absent")

    def test_unsigned_direct_bypass_is_rejected_by_target(self):
        request = {
            "op": "commit", "action": self.action.args(),
            "grant": {}, "proof": {}, "identity": {},
        }
        self.assertEqual(self.rpc(request), {"error": "PermissionError"})
        self.assertEqual(self.observe()[0], "refuted")

    def test_modified_resource_after_policy_evaluation_is_rejected(self):
        request = self.authorization()
        request["action"] = Action(
            self.action.action_id, self.action.subject, self.action.tenant,
            "/granted/other", self.action.value,
        ).args()
        self.assertEqual(self.rpc(request), {"error": "PermissionError"})
        self.assertEqual(self.observe()[0], "refuted")

    def test_exact_request_replay_is_idempotent(self):
        request = self.authorization()
        self.assertEqual(self.rpc(request), {"result": "committed"})
        self.assertEqual(self.rpc(request), {"result": "already_committed"})
        self.assertEqual(self.observe()[0], "established")

    def test_host_success_without_target_commit_is_refuted(self):
        # The host's claimed success string is untrusted evidence.
        reported = {"reported_result": "success"}
        self.assertEqual(reported["reported_result"], "success")
        self.assertEqual(self.observe()[0], "refuted")

    def test_tampered_signed_observation_is_undetermined(self):
        self.assertEqual(self.rpc(self.authorization()), {"result": "committed"})
        verdict, receipt, nonce = self.observe()
        self.assertEqual(verdict, "established")
        receipt["payload"]["state"] = "absent"
        receipt["payload"]["action_sha256"] = None
        self.assertEqual(
            appraise_observation(
                receipt, self.observation_key, action=self.action.args(),
                nonce=nonce,
            ), "undetermined",
        )

    def test_wrong_or_missing_observation_is_undetermined(self):
        self.assertEqual(self.rpc(self.authorization()), {"result": "committed"})
        verdict, receipt, nonce = self.observe()
        self.assertEqual(verdict, "established")
        self.assertEqual(appraise_observation(
            receipt, self.observation_key, action=self.action.args(),
            nonce=nonce + "x",
        ), "undetermined")
        self.assertEqual(appraise_observation(
            None, self.observation_key, action=self.action.args(), nonce=nonce,
        ), "undetermined")

    def test_wrong_action_content_refutes_exact_claim(self):
        self.assertEqual(self.rpc(self.authorization()), {"result": "committed"})
        different = Action(
            self.action.action_id, self.action.subject, self.action.tenant,
            self.action.resource, "different-payload",
        )
        self.assertEqual(self.observe(different)[0], "refuted")


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--target-server":
        serve_target(*sys.argv[2:])
    else:
        unittest.main()
