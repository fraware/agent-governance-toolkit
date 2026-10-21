"""Native ACS policy-input/action correspondence, with an explicit forgery control.

A host derives whether the exact action sent to its independent issuer was
evaluated by the native ACS policy interface. Equality of normalized input
and native SDK identities catches host pipeline substitution, but is not
cryptographic ACS attestation: a dishonest host can fabricate both.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from collections.abc import Mapping
import copy
import unittest

from agent_control_specification import (
    AgentControl, AgentControlBlocked, Decision, EnforcementMode,
    InterventionPoint, Verdict, action_identity,
)
from test_effect_grounded_native_signed_target import (
    Action, CRYPTO, NATIVE, CustomPolicy, ProtectedLedger, TestIssuer, canonical,
)
from pathlib import Path
import tempfile


def require_exact_native_binding(result, operation: Action) -> str:
    """Fail closed for any mismatch in the native-result/dispatch boundary.

    This validates consistency of an *untrusted-to-the-target host report*.
    It does not establish origin or cryptographic authenticity of that report.
    """
    if result.verdict.decision != Decision.ALLOW:
        raise PermissionError("non-allow verdict")
    if result.transformed_policy_target_applied or result.transformed_policy_target is not None:
        raise PermissionError("unadjudicated transformed operation")
    data = result.policy_input
    if not isinstance(data, Mapping):
        raise PermissionError("missing normalized ACS policy input")
    target = data.get("policy_target")
    if not isinstance(target, Mapping):
        raise PermissionError("missing ACS policy target")
    actual_args = target.get("value")
    if not isinstance(actual_args, Mapping):
        raise PermissionError("normalized ACS target is not an action mapping")
    try:
        if canonical(actual_args) != canonical(operation.args()):
            raise PermissionError("operation differs from ACS policy target")
        expected = action_identity(data)
    except (ValueError, TypeError, OverflowError) as exc:
        raise PermissionError("malformed policy input") from exc
    if not isinstance(result.input_identity, str) or result.input_identity != expected:
        raise PermissionError("ACS input identity mismatch")
    if not isinstance(result.enforced_identity, str) or result.enforced_identity != expected:
        raise PermissionError("ACS enforced identity mismatch")
    return expected


@unittest.skipUnless(NATIVE and CRYPTO, "native ACS and Ed25519 are mandatory")
class NativeExactActionBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.issuer = TestIssuer()
        self.target = ProtectedLedger(Path(self.tmp.name) / "bound.sqlite3", self.issuer.public)
        self.policy = CustomPolicy()
        self.acs = AgentControl.from_native(
            __import__("test_effect_grounded_native_signed_target").MANIFEST,
            None, self.policy,
        )
        self.issued = 0

    def action(self, id="a1", resource="/granted/report", value="v1"):
        return Action(id, "agent-1", "tenant-a", resource, value)

    async def evaluate(self, action):
        result = await self.acs.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL,
            {"tool_call": {"id": action.action_id, "name": "write_record",
                           "args": action.args()},
             "principal": {"subject": "agent-1", "tenant": "tenant-a"}},
            EnforcementMode.ENFORCE,
        )
        await self.acs.enforce(InterventionPoint.PRE_TOOL_CALL, result,
                               EnforcementMode.ENFORCE)
        return result

    def submit(self, sent_action, *, evaluated_action=None, rewrite=None):
        async def go():
            original = await self.evaluate(evaluated_action or sent_action)
            claim = rewrite(original) if rewrite else original
            native_id = require_exact_native_binding(claim, sent_action)
            self.issued += 1
            receipt = self.issuer.sign(sent_action)
            result = self.target.commit(sent_action, receipt)
            return native_id, result
        return asyncio.run(go())

    def effects(self):
        import sqlite3
        with sqlite3.connect("file:" + str(self.target.path.resolve()) + "?mode=ro",
                             uri=True) as db:
            return db.execute(
                "SELECT action_id, committed_value FROM effects ORDER BY action_id"
            ).fetchall()

    def test_native_policy_input_identity_matches_executed_action(self):
        acs_id, result = self.submit(self.action())
        self.assertTrue(acs_id.startswith("sha256:"))
        self.assertEqual(result, "committed")
        self.assertEqual(self.issued, 1)
        self.assertEqual(self.effects(), [("a1", "v1")])

    def test_value_changed_after_evaluation_is_rejected_before_issuance(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(value="v2"),
                        evaluated_action=self.action(value="v1"))
        self.assertEqual(self.issued, 0)
        self.assertEqual(self.effects(), [])

    def test_resource_changed_after_evaluation_is_rejected_before_issuance(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(resource="/granted/other"),
                        evaluated_action=self.action(resource="/granted/report"))
        self.assertEqual(self.issued, 0)
        self.assertEqual(self.effects(), [])

    def test_extra_argument_after_evaluation_is_rejected(self):
        def rewrite(r):
            altered = copy.deepcopy(r.policy_input)
            altered["policy_target"]["value"]["extra"] = "hidden"
            return replace(r, policy_input=altered)
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=rewrite)
        self.assertEqual(self.effects(), [])

    def test_identity_substitution_rejected(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=lambda r: replace(
                r, input_identity="sha256:" + "0" * 64))
        self.assertEqual(self.effects(), [])

    def test_missing_input_identity_rejected(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=lambda r: replace(
                r, input_identity=None))
        self.assertEqual(self.effects(), [])

    def test_enforced_identity_substitution_rejected(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=lambda r: replace(
                r, enforced_identity="sha256:" + "f" * 64))
        self.assertEqual(self.effects(), [])

    def test_missing_normalized_target_rejected(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=lambda r: replace(
                r, policy_input={"policy_target": None}))
        self.assertEqual(self.effects(), [])

    def test_transformed_result_rejected_by_untransformed_host_contract(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(), rewrite=lambda r: replace(
                r, verdict=Verdict(Decision.TRANSFORM),
                transformed_policy_target={"resource": "/granted/other"},
                transformed_policy_target_applied=True))
        self.assertEqual(self.effects(), [])

    def test_native_denial_never_reaches_issuer(self):
        with self.assertRaises(AgentControlBlocked):
            self.submit(self.action(resource="/forbidden/file"))
        self.assertEqual(self.issued, 0)
        self.assertEqual(self.effects(), [])

    def test_narrower_issuer_blocks_broader_acs_allow(self):
        with self.assertRaises(PermissionError):
            self.submit(self.action(resource="/granted-unprotected/file"))
        self.assertEqual(self.issued, 1)
        self.assertEqual(self.effects(), [])

    def test_entire_fabricated_claim_can_defeat_untrusted_host_boundary(self):
        """Counterexample: internal hash consistency never proves ACS origin.

        ACS evaluates v1; a dishonest host fabricates *both* the policy input
        and matching identities for v2 and passes the checks. The issuer only
        authenticates its own grant; it has no ACS-signed decision to verify.
        """
        original = self.action(value="v1")
        forged_action = self.action(value="v2")

        def counterfeit(real):
            altered = copy.deepcopy(real.policy_input)
            altered["policy_target"]["value"] = forged_action.args()
            forged_id = action_identity(altered)
            return replace(real, policy_input=altered,
                           input_identity=forged_id, enforced_identity=forged_id)

        self.submit(forged_action, evaluated_action=original, rewrite=counterfeit)
        self.assertEqual(self.effects(), [("a1", "v2")])
        self.assertEqual(self.policy.pre, 1)


if __name__ == "__main__":
    unittest.main()
