"""Native ACS with separately pinned signer and action-bound workload credential.

This is a bounded research fixture. The signer receives a private key by file
provisioning, while the target independently receives its public key. A
separately keyed identity authority issues action-specific bearer credentials.
All processes still share the CI runner's operating-system principal.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError as exc:
    # Keep the existing SDK test environment compatible with optional research crypto.
    # The dedicated mandatory native gate cannot silently skip this module.
    raise unittest.SkipTest("research-only Ed25519 dependency unavailable") from exc
from agent_control_specification import AgentControl, Decision, EnforcementMode, InterventionPoint, action_identity

from test_effect_grounded_native_signed_target import Action, CustomPolicy, MANIFEST, NATIVE, TestIssuer, canonical
from test_effect_grounded_native_dual_attestation import (
    AUDIENCE, DECISION_DOMAIN, IDENTITY_DOMAIN, IDENTITY_FIELDS, POLICY_HASH,
    TwoKeyTarget, encode, decode,
)


class WorkloadAuthority:
    def __init__(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def issue(self, action, *, credential_id=None, subject=None, audiences=None,
              issued_at=None, expires_at=None, epoch=1):
        now = int(time.time())
        issued = now if issued_at is None else issued_at
        claims = {
            "credential_id": credential_id or str(uuid4()),
            "subject": action.subject if subject is None else subject,
            "tenant": action.tenant,
            "action_sha256": sha256(canonical(action.args())).hexdigest(),
            "audiences": (
                ["acs-policy-signer", AUDIENCE] if audiences is None else audiences
            ),
            "epoch": epoch, "issued_at": issued,
            "expires_at": issued + 60 if expires_at is None else expires_at,
        }
        return {
            "claims": claims,
            "signature": encode(self.private.sign(IDENTITY_DOMAIN + canonical(claims))),
        }


def verify_workload_credential(action, assertion, key):
    """A signer-side check; the target repeats checks under its DB lock."""
    if type(assertion) is not dict or set(assertion) != {"claims", "signature"}:
        raise PermissionError("missing workload credential")
    claims = assertion["claims"]
    if type(claims) is not dict or set(claims) != IDENTITY_FIELDS:
        raise PermissionError("invalid workload credential schema")
    try:
        signature = decode(assertion["signature"])
        key.verify(signature, IDENTITY_DOMAIN + canonical(claims))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PermissionError("invalid workload signature") from exc
    now = int(time.time())
    if (type(claims["credential_id"]) is not str or not claims["credential_id"]
            or claims["subject"] != action.subject
            or claims["tenant"] != action.tenant
            or claims["action_sha256"] != sha256(canonical(action.args())).hexdigest()
            or claims["audiences"] != ["acs-policy-signer", AUDIENCE]
            or type(claims["epoch"]) is not int or claims["epoch"] != 1
            or type(claims["issued_at"]) is not int
            or type(claims["expires_at"]) is not int
            or not claims["issued_at"] <= now < claims["expires_at"]
            or claims["issued_at"] > now + 5
            or claims["expires_at"] - claims["issued_at"] > 60):
        raise PermissionError("identity scope, action, or freshness mismatch")
    return sha256(canonical(claims) + signature).hexdigest()


def signer_process(private_key_path, identity_public_key_path):
    """Execute real native ACS; do not announce a public verification key."""
    decision_key = Ed25519PrivateKey.from_private_bytes(
        Path(private_key_path).read_bytes(),
    )
    identity_key = Ed25519PublicKey.from_public_bytes(
        Path(identity_public_key_path).read_bytes(),
    )
    control = AgentControl.from_native(MANIFEST, None, CustomPolicy())
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if type(request) is not dict or set(request) != {"action", "credential"}:
                raise PermissionError("unexpected request shape")
            action = Action(**request["action"])
            credential = request["credential"]
            credential_hash = verify_workload_credential(action, credential, identity_key)
            principal = credential["claims"]
            snapshot = {
                "tool_call": {
                    "id": action.action_id, "name": "write_record",
                    "args": action.args(),
                },
                "principal": {
                    "subject": principal["subject"],
                    "tenant": principal["tenant"],
                },
            }

            async def evaluate():
                return await control.evaluate_intervention_point(
                    InterventionPoint.PRE_TOOL_CALL,
                    snapshot, EnforcementMode.ENFORCE,
                )

            result = asyncio.run(evaluate())
            if result.verdict.decision != Decision.ALLOW:
                raise PermissionError("native policy denial")
            if result.transformed_policy_target_applied or result.transformed_policy_target is not None:
                raise PermissionError("unsupported action transformation")
            pi = result.policy_input
            if (type(pi) is not dict
                    or type(pi.get("policy_target")) is not dict
                    or pi["policy_target"].get("value") != action.args()):
                raise PermissionError("native input does not match action")
            identity = action_identity(pi)
            if result.input_identity != identity or result.enforced_identity != identity:
                raise PermissionError("ACS input identity mismatch")
            now = int(time.time())
            body = {
                "action": action.args(),
                "policy_input": pi,
                "input_identity": identity,
                "enforced_identity": identity,
                "evaluation_id": str(uuid4()),
                "issued_at": now,
                "expires_at": now + 60,
                "epoch": 1,
                "audience": AUDIENCE,
                "decision": "allow",
                "policy_sha256": POLICY_HASH,
                "credential_sha256": credential_hash,
            }
            print(json.dumps({
                "body": body,
                "signature": encode(decision_key.sign(
                    DECISION_DOMAIN + canonical(body),
                )),
            }), flush=True)
        except Exception as exc:
            print(json.dumps({"error": type(exc).__name__}), flush=True)


@unittest.skipUnless(NATIVE, "compiled ACS extension required")
class NativeProvisionedWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        # CI models trusted provisioning. The harness knows this test private
        # key; a real deployment must prohibit host access to it.
        self.policy_private = Ed25519PrivateKey.generate()
        self.policy_public = self.policy_private.public_key()
        self.identity = WorkloadAuthority()
        decision_path = folder / "decision_private_key"
        identity_path = folder / "workload_authority_public"
        decision_path.write_bytes(self.policy_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        decision_path.chmod(0o600)
        identity_path.write_bytes(self.identity.public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        self.process = subprocess.Popen(
            [sys.executable, "-u", str(Path(__file__).resolve()),
             "--signer", str(decision_path), str(identity_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.addCleanup(self.close_process)
        # Readiness only. No signer-controlled public key is trusted here.
        self.hello = json.loads(self.process.stdout.readline())
        self.issuer = TestIssuer()
        self.target = TwoKeyTarget(
            folder / "protected.sqlite3",
            self.issuer.public, self.policy_public,
            identity_key=self.identity.public,
        )
        self.action = Action("record-1", "agent-1", "tenant-a", "/granted/report", "v1")

    def close_process(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()

    def evaluate(self, action=None, credential=None):
        action = self.action if action is None else action
        credential = self.identity.issue(action) if credential is None else credential
        self.process.stdin.write(json.dumps({
            "action": action.args(), "credential": credential,
        }) + "\n")
        self.process.stdin.flush()
        reply = json.loads(self.process.stdout.readline())
        if "error" in reply:
            raise PermissionError(reply["error"])
        return reply

    def commit(self, action=None, credential=None, proof=None, grant=None):
        action = self.action if action is None else action
        credential = self.identity.issue(action) if credential is None else credential
        proof = self.evaluate(action, credential) if proof is None else proof
        grant = self.issuer.sign(action) if grant is None else grant
        return self.target.commit(action, grant, proof, identity=credential)

    def effects(self):
        with sqlite3.connect(
            "file:" + str(self.target.path.resolve()) + "?mode=ro", uri=True,
        ) as db:
            return list(db.execute(
                "SELECT action_id, value FROM effects ORDER BY action_id",
            ))

    def test_three_valid_signatures_commit_one_effect(self):
        self.assertEqual(self.hello, {"ready": True})
        self.assertEqual(self.commit(), "committed")
        self.assertEqual(self.effects(), [("record-1", "v1")])

    def test_missing_credential_signer_denies(self):
        with self.assertRaises(PermissionError):
            self.evaluate(credential={})
        self.assertEqual(self.effects(), [])

    def test_fake_identity_authority_signer_denies(self):
        token = self.identity.issue(self.action)
        other_key = Ed25519PrivateKey.generate()
        token["signature"] = encode(other_key.sign(
            IDENTITY_DOMAIN + canonical(token["claims"]),
        ))
        with self.assertRaises(PermissionError):
            self.evaluate(credential=token)
        self.assertEqual(self.effects(), [])

    def test_credential_for_other_action_signer_denies(self):
        credential = self.identity.issue(self.action)
        changed = replace(self.action, value="substitute")
        with self.assertRaises(PermissionError):
            self.evaluate(changed, credential)
        self.assertEqual(self.effects(), [])

    def test_credential_subject_impersonation_signer_denies(self):
        credential = self.identity.issue(self.action, subject="attacker")
        with self.assertRaises(PermissionError):
            self.evaluate(credential=credential)
        self.assertEqual(self.effects(), [])

    def test_expired_but_validly_signed_credential_signer_denies(self):
        old = int(time.time()) - 120
        credential = self.identity.issue(self.action, issued_at=old,
                                         expires_at=old + 30)
        with self.assertRaises(PermissionError):
            self.evaluate(credential=credential)
        self.assertEqual(self.effects(), [])

    def test_wrong_audience_signer_denies(self):
        credential = self.identity.issue(self.action, audiences=["other"])
        with self.assertRaises(PermissionError):
            self.evaluate(credential=credential)
        self.assertEqual(self.effects(), [])

    def test_signer_key_is_pinned_not_bootstrapped(self):
        self.assertEqual(self.hello, {"ready": True})
        self.target.decision_key = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(PermissionError):
            self.commit()
        self.assertEqual(self.effects(), [])

    def test_wrong_target_identity_key_denies_valid_credential(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        self.target.identity_key = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(PermissionError):
            self.commit(credential=credential, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_credential_replacement_after_policy_evaluation_denied(self):
        original = self.identity.issue(self.action)
        proof = self.evaluate(credential=original)
        different = self.identity.issue(self.action)
        with self.assertRaises(PermissionError):
            self.commit(credential=different, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_revocation_before_three_signature_commit_denied(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        grant = self.issuer.sign(self.action)
        self.target.revoke(grant["payload"]["authorization_id"])
        with self.assertRaises(PermissionError):
            self.commit(credential=credential, proof=proof, grant=grant)
        self.assertEqual(self.effects(), [])

    def test_advance_epoch_denies_existing_credentials_and_evidence(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        grant = self.issuer.sign(self.action)
        self.target.set_epoch(2)
        with self.assertRaises(PermissionError):
            self.commit(credential=credential, proof=proof, grant=grant)
        self.assertEqual(self.effects(), [])

    def test_idempotent_exact_three_signature_replay(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        grant = self.issuer.sign(self.action)
        self.assertEqual(self.commit(credential=credential, proof=proof, grant=grant),
                         "committed")
        self.assertEqual(self.commit(credential=credential, proof=proof, grant=grant),
                         "already_committed")
        self.assertEqual(self.effects(), [("record-1", "v1")])

    def test_identity_credential_id_cannot_commit_two_actions(self):
        id_value = str(uuid4())
        first = self.action
        second = replace(self.action, action_id="record-2")
        first_identity = self.identity.issue(first, credential_id=id_value)
        second_identity = self.identity.issue(second, credential_id=id_value)
        self.commit(first, credential=first_identity)
        with self.assertRaises(PermissionError):
            self.commit(second, credential=second_identity)
        self.assertEqual(self.effects(), [("record-1", "v1")])

    def test_missing_target_credential_denied_after_native_allow(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        with self.assertRaises(PermissionError):
            self.target.commit(
                self.action, self.issuer.sign(self.action), proof, identity=None,
            )
        self.assertEqual(self.effects(), [])

    def test_forged_policy_decision_signing_key_rejected(self):
        credential = self.identity.issue(self.action)
        proof = self.evaluate(credential=credential)
        attacker = Ed25519PrivateKey.generate()
        proof["signature"] = encode(attacker.sign(
            DECISION_DOMAIN + canonical(proof["body"]),
        ))
        with self.assertRaises(PermissionError):
            self.commit(credential=credential, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_authorized_workload_cannot_expand_issuer_scope(self):
        broad = replace(self.action, resource="/granted-insecure/report")
        credential = self.identity.issue(broad)
        proof = self.evaluate(broad, credential)
        self.assertEqual(proof["body"]["decision"], "allow")
        with self.assertRaises(PermissionError):
            self.issuer.sign(broad)
        self.assertEqual(self.effects(), [])

    def test_read_only_process_observes_effect(self):
        self.commit()
        script = (
            "import json,sqlite3,sys; "
            "db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); "
            "print(json.dumps(list(db.execute('SELECT action_id FROM effects'))))"
        )
        observed = subprocess.run(
            [sys.executable, "-c", script, str(self.target.path.resolve())],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(json.loads(observed.stdout), [["record-1"]])


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--signer":
        signer_process(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
