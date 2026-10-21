"""Native ACS decision-boundary conformance tests, not effect attestations."""
from __future__ import annotations
import asyncio
import unittest
from agent_control_specification import (
    AgentControl, AgentControlBlocked, Decision, EnforcementMode, InterventionPoint,
)
try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    NATIVE_AVAILABLE = False
else:
    NATIVE_AVAILABLE = True

MANIFEST = """agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: effect-grounded-conformance
policies:
  scoped_write:
    type: custom
    adapter: exact_action_policy
intervention_points:
  pre_tool_call:
    policy_target_kind: tool_args
    policy_target: $.tool_call.args
    tool_name_from: $.tool_call.name
    policy:
      id: scoped_write
tools:
  write_record:
    type: Tool
    id: write_record
    clearance: internal
"""

class ScopedPolicy:
    def __init__(self):
        self.seen = []

    def evaluate(self, invocation):
        data = invocation["input"]["policy_target"]["value"]
        self.seen.append(dict(data))
        allowed = (
            data.get("subject") == "agent-1"
            and data.get("tenant") == "tenant-a"
            and data.get("operation") == "write"
            and isinstance(data.get("resource"), str)
            and data["resource"].startswith("/allowed/")
        )
        return {"decision": "allow" if allowed else "deny",
                "reason": "scope_allow" if allowed else "scope_deny"}

def snapshot(resource, subject="agent-1"):
    return {"tool_call": {
        "id": "call-1", "name": "write_record",
        "args": {"subject": subject, "tenant": "tenant-a",
                 "resource": resource, "operation": "write", "value": "x"},
    }, "principal": {"subject": subject, "tenant": "tenant-a"}}

@unittest.skipUnless(NATIVE_AVAILABLE, "ACS Rust-backed _native extension unavailable")
class NativeEffectBoundaryTests(unittest.TestCase):
    def test_native_allow_deny_and_input_identity(self):
        policy = ScopedPolicy()
        control = AgentControl.from_native(MANIFEST, None, policy)
        async def run():
            allow = await control.evaluate_intervention_point(
                InterventionPoint.PRE_TOOL_CALL, snapshot("/allowed/report"))
            deny = await control.evaluate_intervention_point(
                InterventionPoint.PRE_TOOL_CALL, snapshot("/secret/report"))
            return allow, deny
        allow, deny = asyncio.run(run())
        self.assertEqual(allow.verdict.decision, Decision.ALLOW)
        self.assertEqual(deny.verdict.decision, Decision.DENY)
        self.assertNotEqual(allow.input_identity, deny.input_identity)
        self.assertEqual([x["resource"] for x in policy.seen],
                         ["/allowed/report", "/secret/report"])
        for result in (allow, deny):
            self.assertTrue(result.input_identity)
            self.assertEqual(result.input_identity, result.enforced_identity)

    def test_reported_subject_is_not_authority(self):
        policy = ScopedPolicy()
        control = AgentControl.from_native(MANIFEST, None, policy)
        result = asyncio.run(control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL,
            snapshot("/allowed/report", subject="attacker")))
        self.assertEqual(result.verdict.decision, Decision.DENY)
        self.assertEqual(policy.seen[0]["subject"], "attacker")

    def test_native_host_enforcement_blocks_callback_before_effect(self):
        """The host, rather than the policy verdict alone, prevents the operation."""
        policy = ScopedPolicy()
        control = AgentControl.from_native(MANIFEST, None, policy)
        applied = []

        async def guarded(resource):
            result = await control.evaluate_intervention_point(
                InterventionPoint.PRE_TOOL_CALL, snapshot(resource), EnforcementMode.ENFORCE
            )
            await control.enforce(
                InterventionPoint.PRE_TOOL_CALL, result, EnforcementMode.ENFORCE
            )
            applied.append(resource)

        async def run():
            await guarded('/allowed/report')
            with self.assertRaises(AgentControlBlocked):
                await guarded('/secret/report')

        asyncio.run(run())
        self.assertEqual(applied, ['/allowed/report'])

    def test_untrusted_subject_can_be_spoofed_without_host_binding(self):
        """Negative control: matching metadata alone never authenticates a caller."""
        control = AgentControl.from_native(MANIFEST, None, ScopedPolicy())
        maliciously_claimed_subject = 'agent-1'
        result = asyncio.run(control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL,
            snapshot('/allowed/report', subject=maliciously_claimed_subject),
        ))
        self.assertEqual(result.verdict.decision, Decision.ALLOW)
        # This is a deliberate identity-spoofing counterexample. The surrounding
        # host must bind 'subject' to an independently authenticated identity.


# Ground-truth control: persistent target ledger, not a tool return message.
# Separate-process SQLite reads demonstrate disk persistence, not a separately
# administered witness or cryptographic independence.
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


MANIFEST_PRE_POST = MANIFEST.replace(
    "tools:\n",
    "  post_tool_call:\n"
    "    policy_target_kind: tool_result\n"
    "    policy_target: $.tool_result\n"
    "    tool_name_from: $.tool_call.name\n"
    "    policy:\n"
    "      id: scoped_write\n"
    "tools:\n",
)


class PrePostPolicy:
    def __init__(self):
        self.observed_targets = []

    def evaluate(self, invocation):
        target = invocation["input"]["policy_target"]["value"]
        self.observed_targets.append(target)
        if "post_block" in target:
            return {
                "decision": "deny" if target["post_block"] else "allow",
                "reason": "post_result_rejected" if target["post_block"] else "post_ok",
            }
        allowed = (
            target.get("subject") == "agent-1"
            and target.get("tenant") == "tenant-a"
            and target.get("operation") == "write"
            and target.get("resource", "").startswith("/allowed/")
        )
        return {"decision": "allow" if allowed else "deny"}


def _read_committed_records_from_other_process(db_path):
    script = (
        "import json, sqlite3, sys; "
        "db = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True); "
        "print(json.dumps(list(db.execute('SELECT resource FROM effects ORDER BY id'))))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, str(db_path)],
        check=True, text=True, capture_output=True,
    )
    import json
    return [entry[0] for entry in json.loads(proc.stdout)]


@unittest.skipUnless(NATIVE_AVAILABLE, "ACS Rust-backed _native extension unavailable")
class NativeCommittedEffectTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_path = Path(self.directory.name) / "target.sqlite"
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "CREATE TABLE effects (id INTEGER PRIMARY KEY, resource TEXT NOT NULL)"
            )
        self.policy = PrePostPolicy()
        self.control = AgentControl.from_native(MANIFEST_PRE_POST, None, self.policy)
        self.executed = []

    async def _execute(self, args):
        self.executed.append(dict(args))
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO effects(resource) VALUES (?)", (args["resource"],))
        return {"post_block": bool(args.get("post_block", False)), "reported": "success"}

    async def _run(self, resource, *, post_block=False):
        args = snapshot(resource)["tool_call"]["args"].copy()
        args["post_block"] = post_block
        return await self.control.run_tool(
            "write_record", args, self._execute, tool_call_id="conformance-tool-call",
            mode=EnforcementMode.ENFORCE,
        )

    def test_native_pre_denial_leaves_target_unchanged(self):
        async def run():
            with self.assertRaises(AgentControlBlocked):
                await self._run("/secret/report")
        asyncio.run(run())
        self.assertEqual(self.executed, [])
        self.assertEqual(_read_committed_records_from_other_process(self.db_path), [])

    def test_native_post_denial_does_not_undo_committed_write(self):
        async def run():
            with self.assertRaises(AgentControlBlocked):
                await self._run("/allowed/report", post_block=True)
        asyncio.run(run())
        self.assertEqual(len(self.executed), 1)
        self.assertEqual(
            _read_committed_records_from_other_process(self.db_path),
            ["/allowed/report"],
        )

    def test_native_pre_and_post_allow_commit_once(self):
        result = asyncio.run(self._run("/allowed/ok"))
        self.assertEqual(result.value["reported"], "success")
        self.assertFalse(result.value["post_block"])
        self.assertEqual(len(self.executed), 1)
        self.assertEqual(
            _read_committed_records_from_other_process(self.db_path), ["/allowed/ok"]
        )

    def test_unmediated_host_callback_bypasses_all_acs_policy(self):
        args = snapshot("/secret/unmediated")["tool_call"]["args"]
        asyncio.run(self._execute(args))
        self.assertEqual(self.policy.observed_targets, [])
        self.assertEqual(
            _read_committed_records_from_other_process(self.db_path),
            ["/secret/unmediated"],
        )
