"""Native ACS signed decision and issuer grant, verified at target commit.

Research-only threat model: the decision signer executes in a separate process;
the test harness pins its Ed25519 public key. The signer and target are still
under one administrative identity in CI. Caller identity and key provisioning
are trusted premises, NOT experimentally established independent roots.
"""
from __future__ import annotations
import asyncio
import base64
from dataclasses import replace
from hashlib import sha256
import inspect
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
    # The SDK's ordinary test job does not install this experimental dependency.
    # The dedicated native gate explicitly requires it and fails if it is missing.
    raise unittest.SkipTest("research-only Ed25519 dependency unavailable") from exc
from agent_control_specification import AgentControl, Decision, EnforcementMode, InterventionPoint, action_identity
from test_effect_grounded_native_signed_target import (
    Action, CustomPolicy, DOMAIN as ISSUER_DOMAIN, FIELDS as ISSUER_FIELDS,
    MANIFEST, NATIVE, TestIssuer, canonical,
)

DECISION_DOMAIN = b"NATIVE-ACS-POLICY-DECISION-RESEARCH-v1\0"
IDENTITY_DOMAIN = b"ACS-ACTION-BOUND-WORKLOAD-CREDENTIAL-v1\0"
IDENTITY_FIELDS = frozenset({
    "credential_id", "subject", "tenant", "action_sha256", "audiences",
    "epoch", "issued_at", "expires_at",
})
AUDIENCE = "research-dual-target"
POLICY_SOURCE_DOMAIN = b"ACS-RESEARCH-POLICY-SOURCE-v1\0"


def fixture_policy_commitment(manifest: str, adapter_source: str) -> str:
    """Commit to the exact manifest and source text of the test's policy adapter.

    This binds neither transitive dependencies nor independently provisioned code.
    The signer and target share the same source in this single-runner experiment.
    """
    if not isinstance(manifest, str) or not isinstance(adapter_source, str):
        raise TypeError("policy commitment inputs must be source strings")
    return sha256(
        POLICY_SOURCE_DOMAIN
        + canonical({"manifest": manifest, "adapter_source": adapter_source})
    ).hexdigest()


POLICY_HASH = fixture_policy_commitment(MANIFEST, inspect.getsource(CustomPolicy))
DECISION_KEYS = frozenset({
    "action", "policy_input", "input_identity", "enforced_identity",
    "evaluation_id", "issued_at", "expires_at", "epoch",
    "audience", "decision", "policy_sha256",
})


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def decode(text):
    return base64.b64decode(text, validate=True)


def signer_service():
    """Evaluate with the native SDK, sign exact normalized input, retain key."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    acs = AgentControl.from_native(MANIFEST, None, CustomPolicy())
    print(json.dumps({"public_key": encode(pub)}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if type(request) is not dict or set(request) != {"action"}:
                raise ValueError("invalid request")
            action = Action(**request["action"])
            # Fixed principal is a test premise, NOT an authenticated user session.
            if action.subject != "agent-1" or action.tenant != "tenant-a":
                raise PermissionError("principal mismatch")
            snapshot = {
                "tool_call": {"id": action.action_id, "name": "write_record", "args": action.args()},
                "principal": {"subject": "agent-1", "tenant": "tenant-a"},
            }

            async def evaluate():
                return await acs.evaluate_intervention_point(
                    InterventionPoint.PRE_TOOL_CALL, snapshot, EnforcementMode.ENFORCE,
                )

            result = asyncio.run(evaluate())
            if result.verdict.decision != Decision.ALLOW:
                raise PermissionError("native ACS denied")
            if result.transformed_policy_target_applied or result.transformed_policy_target is not None:
                raise PermissionError("unsupported transformation")
            pi = result.policy_input
            if (not isinstance(pi, dict)
                    or not isinstance(pi.get("policy_target"), dict)
                    or pi["policy_target"].get("value") != action.args()):
                raise PermissionError("native target mismatch")
            identity = action_identity(pi)
            if identity != result.input_identity or identity != result.enforced_identity:
                raise PermissionError("native identity mismatch")
            now = int(time.time())
            body = {
                "action": action.args(), "policy_input": pi,
                "input_identity": identity, "enforced_identity": identity,
                "evaluation_id": str(uuid4()), "issued_at": now,
                "expires_at": now + 60, "epoch": 1,
                "audience": AUDIENCE, "decision": "allow", "policy_sha256": POLICY_HASH,
            }
            print(json.dumps({
                "body": body,
                "signature": encode(key.sign(DECISION_DOMAIN + canonical(body))),
            }), flush=True)
        except Exception as exc:
            print(json.dumps({"error": type(exc).__name__}), flush=True)


class TwoKeyTarget:
    """One IMMEDIATE transaction checks both signatures and inserts effect."""

    def __init__(self, path, issuer_key, decision_key, policy_hash=POLICY_HASH,
                 identity_key=None, clock=None):
        # Clock injection makes commit-boundary validity independently testable.
        self.clock = clock if clock is not None else time.time
        self.path = Path(path)
        self.issuer_key = issuer_key
        self.decision_key = decision_key
        self.policy_hash = policy_hash
        # If configured, a separately pinned workload-identity authority is mandatory.
        self.identity_key = identity_key
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE state(epoch INTEGER NOT NULL)")
            db.execute("INSERT INTO state VALUES(1)")
            db.execute("CREATE TABLE revoked(authorization_id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE credential_uses(credential_id TEXT PRIMARY KEY, action_id TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE effects(action_id TEXT PRIMARY KEY, "
                "authorization_id TEXT NOT NULL UNIQUE, "
                "evaluation_id TEXT NOT NULL UNIQUE, "
                "action_bytes BLOB NOT NULL, evidence_hash TEXT NOT NULL, value TEXT NOT NULL)"
            )

    def set_epoch(self, epoch):
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT epoch FROM state").fetchone()[0]
            if type(epoch) is not int or epoch <= current:
                raise ValueError("nonmonotone epoch")
            db.execute("UPDATE state SET epoch=?", (epoch,))
            db.execute("COMMIT")

    def revoke(self, grant_id):
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO revoked VALUES(?)", (grant_id,))
            db.execute("COMMIT")

    def commit(self, action, grant, proof, identity=None):
        with sqlite3.connect(self.path, isolation_level=None, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                epoch = db.execute("SELECT epoch FROM state").fetchone()[0]
                if type(proof) is not dict or set(proof) != {"body", "signature"}:
                    raise PermissionError("invalid attestation envelope")
                body = proof["body"]
                expected_fields = DECISION_KEYS | (
                    {"credential_sha256"} if self.identity_key is not None else set()
                )
                if type(body) is not dict or set(body) != expected_fields:
                    raise PermissionError("invalid attestation schema")
                try:
                    self.decision_key.verify(
                        decode(proof["signature"]), DECISION_DOMAIN + canonical(body),
                    )
                except (InvalidSignature, ValueError, TypeError) as exc:
                    raise PermissionError("invalid decision signature") from exc
                now = int(self.clock())
                if (body["decision"] != "allow"
                        or body["audience"] != AUDIENCE
                        or body["policy_sha256"] != self.policy_hash
                        or type(body["epoch"]) is not int or body["epoch"] != epoch
                        or type(body["issued_at"]) is not int
                        or type(body["expires_at"]) is not int
                        or not body["issued_at"] <= now < body["expires_at"]
                        or body["issued_at"] > now + 5
                        or body["expires_at"] - body["issued_at"] > 60):
                    raise PermissionError("invalid decision context")
                if body["action"] != action.args():
                    raise PermissionError("decision/action mismatch")
                if self.identity_key is not None:
                    if type(identity) is not dict or set(identity) != {"claims", "signature"}:
                        raise PermissionError("missing or malformed workload credential")
                    claims = identity["claims"]
                    if type(claims) is not dict or set(claims) != IDENTITY_FIELDS:
                        raise PermissionError("invalid credential schema")
                    try:
                        identity_signature = decode(identity["signature"])
                        self.identity_key.verify(
                            identity_signature, IDENTITY_DOMAIN + canonical(claims),
                        )
                    except (InvalidSignature, ValueError, TypeError) as exc:
                        raise PermissionError("invalid workload identity signature") from exc
                    if (type(claims["credential_id"]) is not str
                            or not claims["credential_id"]
                            or claims["subject"] != action.subject
                            or claims["tenant"] != action.tenant
                            or claims["audiences"] != ["acs-policy-signer", AUDIENCE]
                            or claims["action_sha256"] != sha256(canonical(action.args())).hexdigest()
                            or type(claims["epoch"]) is not int
                            or claims["epoch"] != epoch
                            or type(claims["issued_at"]) is not int
                            or type(claims["expires_at"]) is not int
                            or not claims["issued_at"] <= now < claims["expires_at"]
                            or claims["issued_at"] > now + 5
                            or claims["expires_at"] - claims["issued_at"] > 60):
                        raise PermissionError("invalid workload identity context")
                    credential_digest = sha256(
                        canonical(claims) + identity_signature,
                    ).hexdigest()
                    if body["credential_sha256"] != credential_digest:
                        raise PermissionError("native decision not bound to workload credential")
                pi = body["policy_input"]
                if (type(pi) is not dict
                        or type(pi.get("policy_target")) is not dict
                        or pi["policy_target"].get("value") != action.args()):
                    raise PermissionError("policy target/action mismatch")
                expected = action_identity(pi)
                if body["input_identity"] != expected or body["enforced_identity"] != expected:
                    raise PermissionError("inconsistent signed identity")
                if type(grant) is not dict or set(grant) != {"payload", "signature"}:
                    raise PermissionError("invalid issuer envelope")
                g = grant["payload"]
                if type(g) is not dict or set(g) != ISSUER_FIELDS:
                    raise PermissionError("invalid issuer schema")
                if (g["action_id"] != action.action_id
                        or g["subject"] != action.subject
                        or g["tenant"] != action.tenant
                        or g["resource"] != action.resource
                        or g["operation"] != action.operation
                        or g["value_hash"] != sha256(action.value.encode("utf-8")).hexdigest()
                        or g["audience"] != "research-ledger"
                        or type(g["epoch"]) is not int or g["epoch"] != epoch
                        or type(g["issued_at"]) is not int
                        or type(g["expires_at"]) is not int
                        or not g["issued_at"] <= now < g["expires_at"]
                        or g["expires_at"] - g["issued_at"] > 60):
                    raise PermissionError("issuer context mismatch")
                try:
                    self.issuer_key.verify(
                        grant["signature"], ISSUER_DOMAIN + canonical(g),
                    )
                except (InvalidSignature, ValueError, TypeError) as exc:
                    raise PermissionError("invalid issuer signature") from exc
                if db.execute(
                    "SELECT 1 FROM revoked WHERE authorization_id=?",
                    (g["authorization_id"],),
                ).fetchone():
                    raise PermissionError("revoked grant")
                operation = canonical(action.args())
                evidence = sha256(
                    canonical(body) + decode(proof["signature"])
                    + canonical(g) + grant["signature"]
                ).hexdigest()
                row = db.execute(
                    "SELECT action_bytes, evidence_hash FROM effects WHERE action_id=?",
                    (action.action_id,),
                ).fetchone()
                if row is not None:
                    if row != (operation, evidence):
                        raise PermissionError("conflicting committed action")
                    db.execute("COMMIT")
                    return "already_committed"
                try:
                    if self.identity_key is not None:
                        db.execute(
                            "INSERT INTO credential_uses VALUES(?,?)",
                            (claims["credential_id"], action.action_id),
                        )
                    db.execute(
                        "INSERT INTO effects VALUES(?,?,?,?,?,?)",
                        (action.action_id, g["authorization_id"], body["evaluation_id"],
                         operation, evidence, action.value),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PermissionError("consumed grant, evaluation, or workload credential") from exc
                db.execute("COMMIT")
                return "committed"
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise


@unittest.skipUnless(NATIVE, "native ACS extension is mandatory")
class NativeDualAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.signer = subprocess.Popen(
            [sys.executable, "-u", str(Path(__file__).resolve()), "--signer"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.addCleanup(self.close_signer)
        hello = json.loads(self.signer.stdout.readline())
        decision_key = Ed25519PublicKey.from_public_bytes(decode(hello["public_key"]))
        self.issuer = TestIssuer()
        self.target = TwoKeyTarget(
            Path(self.temp.name) / "effects.sqlite3", self.issuer.public, decision_key,
        )
        self.action = Action(
            "a-1", "agent-1", "tenant-a", "/granted/report", "value-1",
        )

    def close_signer(self):
        if self.signer.poll() is None:
            self.signer.stdin.close()
            self.signer.wait(timeout=5)
        self.signer.stdout.close()
        self.signer.stderr.close()

    def evaluate(self, action=None):
        action = action or self.action
        self.signer.stdin.write(json.dumps({"action": action.args()}) + "\n")
        self.signer.stdin.flush()
        response = json.loads(self.signer.stdout.readline())
        if "error" in response:
            raise PermissionError(response["error"])
        return response

    def commit(self, action=None, grant=None, proof=None):
        action = action or self.action
        proof = proof if proof is not None else self.evaluate(action)
        grant = grant if grant is not None else self.issuer.sign(action)
        return self.target.commit(action, grant, proof)

    def effects(self):
        with sqlite3.connect(
            "file:" + str(self.target.path.resolve()) + "?mode=ro", uri=True,
        ) as db:
            return db.execute(
                "SELECT action_id,value FROM effects ORDER BY action_id"
            ).fetchall()

    def test_native_allow_and_both_signatures_commit(self):
        self.assertEqual(self.commit(), "committed")
        self.assertEqual(self.effects(), [("a-1", "value-1")])

    def test_native_deny_does_not_sign(self):
        with self.assertRaises(PermissionError):
            self.evaluate(replace(self.action, resource="/secret/file"))
        self.assertEqual(self.effects(), [])

    def test_resource_changed_after_evaluation(self):
        proof = self.evaluate()
        changed = replace(self.action, resource="/granted/altered")
        with self.assertRaises(PermissionError):
            self.commit(changed, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_value_changed_after_evaluation(self):
        proof = self.evaluate()
        changed = replace(self.action, value="altered")
        with self.assertRaises(PermissionError):
            self.commit(changed, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_fabricated_host_report_rejected(self):
        proof = self.evaluate()
        proof["body"]["action"]["value"] = "fabricated"
        with self.assertRaises(PermissionError):
            self.commit(proof=proof)
        self.assertEqual(self.effects(), [])

    def test_substituted_policy_signature_rejected(self):
        proof = self.evaluate()
        proof["signature"] = encode(Ed25519PrivateKey.generate().sign(
            DECISION_DOMAIN + canonical(proof["body"]),
        ))
        with self.assertRaises(PermissionError):
            self.commit(proof=proof)
        self.assertEqual(self.effects(), [])

    def test_wrong_pinned_policy_key_rejected(self):
        self.target.decision_key = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(PermissionError):
            self.commit()
        self.assertEqual(self.effects(), [])

    def test_missing_policy_attestation_rejected(self):
        with self.assertRaises(PermissionError):
            self.commit(proof={})
        self.assertEqual(self.effects(), [])

    def test_issuer_denies_broader_acs_allowed_resource(self):
        broad = replace(self.action, resource="/granted-insecure/resource")
        proof = self.evaluate(broad)
        self.assertEqual(proof["body"]["decision"], "allow")
        with self.assertRaises(PermissionError):
            self.issuer.sign(broad)
        self.assertEqual(self.effects(), [])

    def test_invalid_issuer_signature_rejected(self):
        token = self.issuer.sign(self.action)
        token["signature"] = Ed25519PrivateKey.generate().sign(
            ISSUER_DOMAIN + canonical(token["payload"]),
        )
        with self.assertRaises(PermissionError):
            self.commit(grant=token)
        self.assertEqual(self.effects(), [])

    def test_revoke_before_commit_rejects(self):
        token = self.issuer.sign(self.action)
        self.target.revoke(token["payload"]["authorization_id"])
        with self.assertRaises(PermissionError):
            self.commit(grant=token)
        self.assertEqual(self.effects(), [])

    def test_epoch_change_rejects_existing_evidence(self):
        proof = self.evaluate()
        token = self.issuer.sign(self.action)
        self.target.set_epoch(2)
        with self.assertRaises(PermissionError):
            self.commit(grant=token, proof=proof)
        self.assertEqual(self.effects(), [])

    def test_same_evidence_idempotent(self):
        proof = self.evaluate()
        token = self.issuer.sign(self.action)
        self.assertEqual(self.commit(grant=token, proof=proof), "committed")
        self.assertEqual(self.commit(grant=token, proof=proof), "already_committed")
        self.assertEqual(self.effects(), [("a-1", "value-1")])

    def test_evaluation_replay_for_different_action_rejected(self):
        proof = self.evaluate()
        self.commit(grant=self.issuer.sign(self.action), proof=proof)
        second = replace(self.action, action_id="a-2")
        with self.assertRaises(PermissionError):
            self.commit(second, proof=proof)
        self.assertEqual(self.effects(), [("a-1", "value-1")])

    def test_policy_revision_mismatch_rejects_real_signature(self):
        self.target.policy_hash = "0" * 64
        with self.assertRaises(PermissionError):
            self.commit()
        self.assertEqual(self.effects(), [])



    def test_future_issuer_grant_rejected_at_dual_target(self):
        """A valid issuer signature is insufficient before the signed start."""
        frozen_now = int(self.target.clock())
        self.target.clock = lambda: frozen_now
        grant = self.issuer.sign(self.action)
        grant["payload"]["issued_at"] = frozen_now + 120
        grant["payload"]["expires_at"] = frozen_now + 180
        grant["signature"] = self.issuer.key.sign(
            ISSUER_DOMAIN + canonical(grant["payload"])
        )
        with self.assertRaises(PermissionError):
            self.commit(grant=grant)
        self.assertEqual(self.effects(), [])

    def test_overlong_signed_issuer_grant_rejected_at_dual_target(self):
        """The dual-signature target independently enforces the issuer TTL."""
        frozen_now = int(self.target.clock())
        self.target.clock = lambda: frozen_now
        grant = self.issuer.sign(self.action)
        grant["payload"]["expires_at"] = grant["payload"]["issued_at"] + 61
        grant["signature"] = self.issuer.key.sign(
            ISSUER_DOMAIN + canonical(grant["payload"])
        )
        with self.assertRaises(PermissionError):
            self.commit(grant=grant)
        self.assertEqual(self.effects(), [])

    def test_policy_adapter_source_changes_commitment(self):
        """A stable manifest does not hide changed custom policy source text."""
        source = inspect.getsource(CustomPolicy)
        changed = source.replace('startswith("/granted")', 'startswith("/other")')
        self.assertNotEqual(changed, source)
        self.assertEqual(POLICY_HASH, fixture_policy_commitment(MANIFEST, source))
        self.assertNotEqual(POLICY_HASH, fixture_policy_commitment(MANIFEST, changed))

    def test_changed_policy_source_pin_rejects_valid_decision_signature(self):
        """A mismatched target pin rejects the signer even with a valid key."""
        source = inspect.getsource(CustomPolicy)
        changed = source.replace('startswith("/granted")', 'startswith("/other")')
        self.assertNotEqual(changed, source)
        self.target.policy_hash = fixture_policy_commitment(MANIFEST, changed)
        with self.assertRaises(PermissionError):
            self.commit()
        self.assertEqual(self.effects(), [])

    def test_other_process_reads_persisted_effect(self):
        self.commit()
        script = (
            "import sqlite3,json,sys; "
            "db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); "
            "print(json.dumps(list(db.execute('SELECT action_id FROM effects'))))"
        )
        response = subprocess.run(
            [sys.executable, "-c", script, str(self.target.path.resolve())],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(json.loads(response.stdout), [["a-1"]])


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--signer":
        signer_service()
    else:
        unittest.main()
