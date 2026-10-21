"""Reproducible offline appraisal tests using ephemeral target test keys.

All test keys are generated in the fixture; no externally trusted deployment
or independently administered target is claimed by these cases.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from effect_target_protocol import action_sha256, signed_observation
from verify_target_observation import offline_appraise


class OfflineTargetObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.action_file = root / "action.json"
        self.observation_file = root / "observation.json"
        self.key_file = root / "target-public.raw"
        self.signer = Ed25519PrivateKey.generate()
        self.public_bytes = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.key_file.write_bytes(self.public_bytes)
        self.fingerprint = hashlib.sha256(self.public_bytes).hexdigest()
        self.nonce = "verifier-owned-fresh-nonce-123456"
        self.action = {
            "action_id": "action-001", "subject": "test-principal",
            "tenant": "test-tenant", "resource": "/test/report",
            "operation": "write", "value": "test-value",
        }
        self.action_file.write_text(json.dumps(self.action), encoding="utf-8")
        self.issue()

    def issue(self, *, state="committed", digest=None):
        if state == "committed" and digest is None:
            digest = action_sha256(self.action)
        receipt = signed_observation(
            self.signer, action_id=self.action["action_id"], nonce=self.nonce,
            state=state, action_digest=digest, observed_at=1790000000,
        )
        self.observation_file.write_text(
            json.dumps(receipt), encoding="utf-8",
        )
        return receipt

    def check(self, **overrides):
        params = {
            "action_path": self.action_file,
            "receipt_path": self.observation_file,
            "public_key_path": self.key_file,
            "expected_key_sha256": self.fingerprint,
            "nonce": self.nonce,
        }
        params.update(overrides)
        return offline_appraise(**params)

    def cli(self, expected, *, fingerprint=None, nonce=None):
        return subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("verify_target_observation.py")),
                "--action", str(self.action_file),
                "--observation", str(self.observation_file),
                "--target-public-key", str(self.key_file),
                "--expected-key-sha256",
                self.fingerprint if fingerprint is None else fingerprint,
                "--nonce", self.nonce if nonce is None else nonce,
                "--expect", expected,
            ],
            capture_output=True, text=True, check=False, timeout=10,
        )

    def test_exact_committed_snapshot_established(self):
        result = self.check()
        self.assertEqual(result["verdict"], "established")
        self.assertTrue(result["key_pin_matched"])
        self.assertEqual(result["schema"], "effect-target-appraisal/v1")

    def test_target_snapshot_absence_refuted(self):
        self.issue(state="absent")
        self.assertEqual(self.check()["verdict"], "refuted")

    def test_wrong_action_payload_refuted_at_snapshot(self):
        self.issue(digest="0" * 64)
        self.assertNotEqual(action_sha256(self.action), "0" * 64)
        self.assertEqual(self.check()["verdict"], "refuted")

    def test_tampered_observation_undetermined(self):
        receipt = self.issue()
        receipt["payload"]["state"] = "absent"
        receipt["payload"]["action_sha256"] = None
        self.observation_file.write_text(json.dumps(receipt), encoding="utf-8")
        self.assertEqual(self.check()["verdict"], "undetermined")

    def test_wrong_nonce_undetermined(self):
        self.assertEqual(
            self.check(nonce="different-requester-nonce")["verdict"],
            "undetermined",
        )

    def test_wrong_external_key_pin_fails_closed(self):
        result = self.check(expected_key_sha256="0" * 64)
        self.assertEqual(result["verdict"], "undetermined")
        self.assertEqual(result["reason"], "external_key_pin_mismatch")
        self.assertFalse(result["key_pin_matched"])

    def test_other_target_signer_is_not_trusted(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.key_file.write_bytes(other)
        self.assertEqual(self.check()["verdict"], "undetermined")

    def test_missing_key_and_wrong_key_size_undetermined(self):
        self.key_file.unlink()
        self.assertEqual(self.check()["verdict"], "undetermined")
        self.key_file.write_bytes(b"short")
        result = self.check()
        self.assertEqual(result["verdict"], "undetermined")
        self.assertEqual(result["reason"], "invalid_target_public_key")

    def test_malformed_and_oversized_observation_undetermined(self):
        self.observation_file.write_text("{ invalid", encoding="utf-8")
        self.assertEqual(self.check()["verdict"], "undetermined")
        self.observation_file.write_bytes(b" " * (1024 * 1024 + 1))
        self.assertEqual(self.check()["verdict"], "undetermined")

    def test_invalid_pin_format_undetermined(self):
        for pin in ("", "A" * 64, "0" * 63, "x" * 64):
            with self.subTest(pin=pin):
                self.assertEqual(
                    self.check(expected_key_sha256=pin)["reason"],
                    "invalid_external_key_pin",
                )

    def test_cli_correct_expectation_exits_zero_and_outputs_json(self):
        result = self.cli("established")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["verdict"], "established")

    def test_cli_incorrect_expectation_exits_nonzero(self):
        result = self.cli("refuted")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["verdict"], "established")

    def test_cli_requires_independently_supplied_pin(self):
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("verify_target_observation.py")),
                "--action", str(self.action_file),
                "--observation", str(self.observation_file),
                "--target-public-key", str(self.key_file),
                "--nonce", self.nonce, "--expect", "established",
            ],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-key-sha256", result.stderr)


if __name__ == "__main__":
    unittest.main()
