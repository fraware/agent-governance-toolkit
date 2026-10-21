"""Standalone verifier tests: no ACS SDK, target service, or model API required."""
from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from effect_target_protocol import (
    action_sha256, appraise_observation, signed_observation,
)


class TargetObservationProtocolTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key()
        self.action = {
            "action_id": "a1", "subject": "agent-1",
            "tenant": "tenant-a", "resource": "/granted/report",
            "operation": "write", "value": "v1",
        }
        self.nonce = "fresh-independent-request-nonce-1234"

    def observe(self, state="committed", digest=None):
        if state == "committed" and digest is None:
            digest = action_sha256(self.action)
        return signed_observation(
            self.signer, action_id=self.action["action_id"],
            nonce=self.nonce, state=state, action_digest=digest,
            observed_at=1790000000,
        )

    def appraise(self, evidence, *, nonce=None, public=None):
        return appraise_observation(
            evidence, self.public if public is None else public,
            action=self.action, nonce=self.nonce if nonce is None else nonce,
        )

    def test_signed_exact_commit_established(self):
        self.assertEqual(self.appraise(self.observe()), "established")

    def test_signed_snapshot_absence_refutes_commit_at_that_instant(self):
        self.assertEqual(self.appraise(self.observe("absent")), "refuted")

    def test_signed_wrong_content_refutes_exact_commit(self):
        digest = "0" * 64
        self.assertNotEqual(digest, action_sha256(self.action))
        self.assertEqual(self.appraise(self.observe(digest=digest)), "refuted")

    def test_wrong_nonce_is_undetermined(self):
        self.assertEqual(
            self.appraise(self.observe(), nonce=self.nonce + "-wrong"),
            "undetermined",
        )

    def test_tampered_payload_is_undetermined(self):
        receipt = self.observe()
        receipt["payload"]["state"] = "absent"
        receipt["payload"]["action_sha256"] = None
        self.assertEqual(self.appraise(receipt), "undetermined")

    def test_unknown_target_key_is_undetermined(self):
        other = Ed25519PrivateKey.generate().public_key()
        self.assertEqual(self.appraise(self.observe(), public=other), "undetermined")

    def test_malformed_base64_is_undetermined(self):
        receipt = self.observe()
        receipt["signature"] = "not%%%base64"
        self.assertEqual(self.appraise(receipt), "undetermined")

    def test_unexpected_schema_field_is_undetermined(self):
        receipt = self.observe()
        receipt["payload"]["claim"] = "allow"
        self.assertEqual(self.appraise(receipt), "undetermined")

    def test_untrusted_or_missing_evidence_is_undetermined(self):
        self.assertEqual(self.appraise(None), "undetermined")
        self.assertEqual(self.appraise({"payload": {}}), "undetermined")


if __name__ == "__main__":
    unittest.main()
