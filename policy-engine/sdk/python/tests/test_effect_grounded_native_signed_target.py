"""Native ACS + action-bound Ed25519 target: bounded research conformance.

A real ACS pre-tool verdict, a separate issuer's signed grant, transactional
target authorization, and a read-only SQLite observer are deliberately distinct.
This is a single-host test model, not complete mediation or external attestation.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from agent_control_specification import (
    AgentControl, AgentControlBlocked, EnforcementMode,
)

try:
    from agent_control_specification import _native  # noqa: F401
except (ImportError, OSError):
    NATIVE = False
else:
    NATIVE = True

CRYPTO = importlib.util.find_spec("cryptography") is not None
if CRYPTO:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN = b"ACS-TARGET-RESEARCH-SIGNED-ACTION-v1\0"
TIME = 1790000000
FIELDS = frozenset({
    "action_id", "subject", "tenant", "resource", "operation", "value_hash",
    "authorization_id", "epoch", "audience", "expires_at",
})
MANIFEST = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: signed-target-research
policies:
  test_policy:
    type: custom
    adapter: research_dispatcher
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: test_policy
  post_tool_call:
    policy_target: $.tool_result
    policy_target_kind: tool_result
    tool_name_from: $.tool_call.name
    policy:
      id: test_policy
tools:
  write_record:
    type: Tool
    id: write_record
    clearance: internal
"""


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class Action:
    action_id: str
    subject: str
    tenant: str
    resource: str
    value: str
    operation: str = "write"

    def args(self):
        return {
            "action_id": self.action_id, "subject": self.subject,
            "tenant": self.tenant, "resource": self.resource,
            "value": self.value, "operation": self.operation,
        }


class TestIssuer:
    """Independent authorization gate with an exact research resource prefix."""

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key()

    def sign(self, action, authorization_id=None):
        if (action.subject != "agent-1" or action.tenant != "tenant-a"
                or action.operation != "write"
                or not action.resource.startswith("/granted/")):
            raise PermissionError("issuer rule rejects action")
        payload = {
            "action_id": action.action_id,
            "subject": action.subject, "tenant": action.tenant,
            "resource": action.resource, "operation": action.operation,
            "value_hash": sha256(action.value.encode("utf-8")).hexdigest(),
            "authorization_id": authorization_id or "grant-" + action.action_id,
            "epoch": 1, "audience": "research-ledger",
            "expires_at": TIME + 60,
        }
        return {"payload": payload, "signature": self.key.sign(DOMAIN + canonical(payload))}


class ProtectedLedger:
    """Commit-time verifier and durable effect ledger, no unverified write API."""

    def __init__(self, path, pinned_public_key):
        self.path = Path(path)
        self.pinned_public_key = pinned_public_key
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE state(epoch INTEGER NOT NULL)")
            db.execute("INSERT INTO state VALUES(1)")
            db.execute("CREATE TABLE revocations(token_id TEXT PRIMARY KEY)")
            db.execute(
                "CREATE TABLE effects(action_id TEXT PRIMARY KEY,"
                "authorization_id TEXT NOT NULL UNIQUE,"
                "payload BLOB NOT NULL, committed_value TEXT NOT NULL)"
            )

    def set_epoch(self, next_epoch):
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT epoch FROM state").fetchone()[0]
            if type(next_epoch) is not int or next_epoch <= old:
                raise ValueError("nonmonotone epoch")
            db.execute("UPDATE state SET epoch=?", (next_epoch,))
            db.execute("COMMIT")

    def revoke(self, token_id):
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO revocations VALUES(?)", (token_id,))
            db.execute("COMMIT")

    def commit(self, action, token):
        # The authorization context is locked for the duration of verification
        # and insert. It is not chosen by the untrusted caller.
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if not isinstance(token, dict) or set(token) != {"payload", "signature"}:
                    raise PermissionError("invalid authorization envelope")
                p = token["payload"]
                if not isinstance(p, dict) or set(p) != FIELDS:
                    raise PermissionError("unexpected signed fields")
                if (p["subject"] != action.subject
                        or p["tenant"] != action.tenant
                        or p["resource"] != action.resource
                        or p["operation"] != action.operation
                        or p["action_id"] != action.action_id
                        or p["value_hash"] != sha256(action.value.encode("utf-8")).hexdigest()):
                    raise PermissionError("action differs from signed authorization")
                if (p["audience"] != "research-ledger"
                        or type(p["epoch"]) is not int
                        or p["epoch"] != db.execute("SELECT epoch FROM state").fetchone()[0]
                        or type(p["expires_at"]) is not int
                        or TIME >= p["expires_at"]):
                    raise PermissionError("incorrect audience, epoch, or expiry")
                if db.execute(
                    "SELECT 1 FROM revocations WHERE token_id=?",
                    (p["authorization_id"],),
                ).fetchone():
                    raise PermissionError("authorization revoked")
                try:
                    self.pinned_public_key.verify(token["signature"], DOMAIN + canonical(p))
                except (InvalidSignature, ValueError, TypeError) as exc:
                    raise PermissionError("invalid signature") from exc
                existing = db.execute(
                    "SELECT payload, committed_value FROM effects WHERE action_id=?",
                    (action.action_id,),
                ).fetchone()
                payload = canonical(action.args())
                if existing is not None:
                    if existing != (payload, action.value):
                        raise PermissionError("conflicting idempotency key")
                    db.execute("COMMIT")
                    return "already_committed"
                try:
                    db.execute(
                        "INSERT INTO effects VALUES(?,?,?,?)",
                        (action.action_id, p["authorization_id"], payload, action.value),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PermissionError("authorization consumed") from exc
                db.execute("COMMIT")
                return "committed"
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise


class CustomPolicy:
    """Native dispatcher intentionally accepts a wider scope than the issuer."""

    def __init__(self):
        self.pre = 0
        self.post = 0

    def evaluate(self, invocation):
        args = invocation["input"]["policy_target"]["value"]
        if "reported_result" in args:
            self.post += 1
            return {"decision": "deny" if args.get("post_reject") else "allow"}
        self.pre += 1
        allowed = (
            args.get("subject") == "agent-1"
            and args.get("tenant") == "tenant-a"
            and args.get("operation") == "write"
            and isinstance(args.get("resource"), str)
            and args["resource"].startswith("/granted")
        )
        return {"decision": "allow" if allowed else "deny"}


@unittest.skipUnless(NATIVE and CRYPTO, "native ACS extension and Ed25519 dependency required")
class NativeSignedTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.issuer = TestIssuer()
        self.target = ProtectedLedger(Path(self.tmp.name) / "effects.sqlite3", self.issuer.public)
        self.policy = CustomPolicy()
        self.acs = AgentControl.from_native(MANIFEST, None, self.policy)
        self.callback_calls = 0

    def action(self, action_id="a1", resource="/granted/report", value="v1"):
        return Action(action_id, "agent-1", "tenant-a", resource, value)

    def effects(self):
        with sqlite3.connect(
            "file:" + str(self.target.path.resolve()) + "?mode=ro", uri=True
        ) as db:
            return db.execute(
                "SELECT action_id, committed_value FROM effects ORDER BY action_id"
            ).fetchall()

    def invoke(self, action, *, mutate=None, post_reject=False,
               false_report=False, revoke=False, rotate=False):
        # Harness-provisioned actor identity is a premise, not inferred from args.
        if action.subject != "agent-1" or action.tenant != "tenant-a":
            raise PermissionError("host-authenticated identity mismatch")

        async def execute(effective_args):
            self.callback_calls += 1
            if effective_args != action.args():
                raise PermissionError("ACS/host argument substitution")
            if false_report:
                return {"reported_result": "success", "post_reject": post_reject}
            signed = self.issuer.sign(action)
            if revoke:
                self.target.revoke(signed["payload"]["authorization_id"])
            if rotate:
                self.target.set_epoch(2)
            self.target.commit(mutate or action, signed)
            return {"reported_result": "success", "post_reject": post_reject}

        async def run():
            return await self.acs.run_tool(
                "write_record", action.args(), execute,
                tool_call_id=action.action_id, mode=EnforcementMode.ENFORCE,
                snapshot={"principal": {"subject": "agent-1", "tenant": "tenant-a"}},
            )
        return asyncio.run(run())

    def test_valid_policy_issuer_signature_and_effect(self):
        action = self.action()
        output = self.invoke(action)
        self.assertEqual(output.value["reported_result"], "success")
        self.assertEqual(self.effects(), [("a1", "v1")])
        self.assertEqual(self.policy.pre, 1)
        self.assertEqual(self.policy.post, 1)
        self.assertTrue(output.pre_tool_call_result.input_identity)
        self.assertEqual(
            output.pre_tool_call_result.input_identity,
            output.pre_tool_call_result.enforced_identity,
        )

    def test_acs_pre_denial_prevents_callback(self):
        with self.assertRaises(AgentControlBlocked):
            self.invoke(self.action(resource="/secret"))
        self.assertEqual(self.callback_calls, 0)
        self.assertEqual(self.effects(), [])

    def test_acs_allow_does_not_expand_issuer_grants(self):
        with self.assertRaises(PermissionError):
            self.invoke(self.action(resource="/granted-insecure/report"))
        self.assertEqual(self.policy.pre, 1)
        self.assertEqual(self.effects(), [])

    def test_signed_resource_mutation_rejected_at_commit(self):
        with self.assertRaises(PermissionError):
            self.invoke(self.action(), mutate=self.action(resource="/granted/other"))
        self.assertEqual(self.effects(), [])

    def test_signed_value_mutation_rejected_at_commit(self):
        with self.assertRaises(PermissionError):
            self.invoke(self.action(), mutate=self.action(value="modified"))
        self.assertEqual(self.effects(), [])

    def test_revocation_between_verdict_and_commit(self):
        with self.assertRaises(PermissionError):
            self.invoke(self.action(), revoke=True)
        self.assertEqual(self.effects(), [])

    def test_policy_epoch_advance_before_commit(self):
        with self.assertRaises(PermissionError):
            self.invoke(self.action(), rotate=True)
        self.assertEqual(self.effects(), [])

    def test_post_denial_does_not_undo_committed_effect(self):
        with self.assertRaises(AgentControlBlocked):
            self.invoke(self.action(), post_reject=True)
        self.assertEqual(self.effects(), [("a1", "v1")])

    def test_success_receipt_is_not_effect_evidence(self):
        result = self.invoke(self.action(), false_report=True)
        self.assertEqual(result.value["reported_result"], "success")
        self.assertEqual(self.effects(), [])

    def test_same_action_exact_replay_is_idempotent(self):
        self.invoke(self.action())
        self.invoke(self.action())
        self.assertEqual(self.effects(), [("a1", "v1")])

    def test_authorization_reuse_for_second_action_fails(self):
        a = self.action("first")
        b = self.action("second")
        first = self.issuer.sign(a, authorization_id="shared")
        second = self.issuer.sign(b, authorization_id="shared")
        self.target.commit(a, first)
        with self.assertRaises(PermissionError):
            self.target.commit(b, second)
        self.assertEqual(self.effects(), [("first", "v1")])

    def test_signature_substitution_fails_closed(self):
        a = self.action()
        token = self.issuer.sign(a)
        token["signature"] = Ed25519PrivateKey.generate().sign(
            DOMAIN + canonical(token["payload"])
        )
        with self.assertRaises(PermissionError):
            self.target.commit(a, token)
        self.assertEqual(self.effects(), [])

    def test_expired_token_fails_closed(self):
        a = self.action()
        token = self.issuer.sign(a)
        token["payload"]["expires_at"] = TIME
        # Re-sign the expired payload so expiry is the sole rejection reason.
        token["signature"] = self.issuer.key.sign(DOMAIN + canonical(token["payload"]))
        with self.assertRaises(PermissionError):
            self.target.commit(a, token)
        self.assertEqual(self.effects(), [])

    def test_separate_read_only_process_observes_commit(self):
        self.invoke(self.action())
        script = (
            "import json,sqlite3,sys; "
            "db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); "
            "print(json.dumps(list(db.execute('SELECT action_id FROM effects'))))"
        )
        seen = subprocess.run(
            [sys.executable, "-c", script, str(self.target.path.resolve())],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(json.loads(seen.stdout), [["a1"]])


    def test_wrong_audience_rejected_with_valid_signature(self):
        action = self.action()
        token = self.issuer.sign(action)
        token["payload"]["audience"] = "unrelated-service"
        token["signature"] = self.issuer.key.sign(DOMAIN + canonical(token["payload"]))
        with self.assertRaises(PermissionError):
            self.target.commit(action, token)
        self.assertEqual(self.effects(), [])

    def test_conflicting_action_id_rejected_after_commit(self):
        original = self.action("collision", value="first-value")
        altered = self.action("collision", value="second-value")
        self.target.commit(original, self.issuer.sign(original))
        with self.assertRaises(PermissionError):
            self.target.commit(altered, self.issuer.sign(altered))
        self.assertEqual(self.effects(), [("collision", "first-value")])

    def test_revocation_after_commit_preserves_effect_and_rejects_replay(self):
        action = self.action()
        token = self.issuer.sign(action)
        self.target.commit(action, token)
        self.target.revoke(token["payload"]["authorization_id"])
        with self.assertRaises(PermissionError):
            self.target.commit(action, token)
        self.assertEqual(self.effects(), [("a1", "v1")])

    def test_textual_resource_scope_is_not_filesystem_path_safety(self):
        # Both policies use literal string prefixes. This counterexample is
        # intentionally ACCEPTED by the model, while a file service might
        # resolve its components differently; no path-safety claim follows.
        alias = self.action("path-alias", resource="/granted/../secret")
        self.invoke(alias)
        self.assertEqual(self.effects(), [("path-alias", "v1")])


if __name__ == "__main__":
    unittest.main()
