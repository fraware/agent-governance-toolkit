"""Fixed Ed25519 receipt vectors for cross-implementation research conformance.

Fixtures use a publicly reproducible, synthetic test-only key. They are NOT
live deployment credentials, target attestation, or evidence of external effects.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from effect_target_protocol import (
    OBSERVATION_DOMAIN, action_sha256, appraise_observation, canonical,
    valid_action, valid_digest,
)


class FixedTargetSnapshotVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (Path(__file__).resolve().parent / "conformance"
                / "effect-target-v1-vectors.json")
        cls.bundle = json.loads(path.read_text(encoding="utf-8"))
        cls.public_bytes = bytes.fromhex(cls.bundle["public_key_hex"])
        cls.public = Ed25519PublicKey.from_public_bytes(cls.public_bytes)

    def test_fixture_schema_and_signer_fingerprint(self):
        self.assertEqual(self.bundle["schema"], "effect-target-conformance-v1")
        self.assertEqual(len(self.public_bytes), 32)
        self.assertEqual(
            hashlib.sha256(self.public_bytes).hexdigest(),
            self.bundle["public_key_sha256"],
        )
        self.assertEqual(OBSERVATION_DOMAIN.hex(),
                         self.bundle["protocol_domain_hex"])

    def test_canonical_unicode_action_bytes_and_digest(self):
        action = self.bundle["vectors"][0]["action"]
        self.assertIn("\\u00e9", canonical(action).decode("ascii"))
        self.assertEqual(canonical(action).hex(),
                         self.bundle["canonical_action_hex"])
        self.assertEqual(action_sha256(action),
                         self.bundle["canonical_action_sha256"])

    def test_all_fixed_signed_and_adversarial_cases(self):
        vectors = self.bundle["vectors"]
        self.assertEqual(len(vectors), 7)
        self.assertEqual(len({v["id"] for v in vectors}), 7)
        results = set()
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                self.assertTrue(valid_action(vector["action"]))
                result = appraise_observation(
                    vector["receipt"], self.public,
                    action=vector["action"], nonce=vector["nonce"],
                )
                self.assertEqual(result, vector["expected"])
                results.add(result)
        self.assertEqual(results, {"established", "refuted", "undetermined"})

    def test_action_schema_is_exact_and_string_valued(self):
        action = self.bundle["vectors"][0]["action"]
        self.assertTrue(valid_action(action))
        for changed in (
            {key: value for key, value in action.items() if key != "tenant"},
            {**action, "extra": "unexpected"},
            {**action, "value": 1},
            {**action, "action_id": ""},
            {**action, "operation": True},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(valid_action(changed))
                with self.assertRaises(ValueError):
                    action_sha256(changed)
                self.assertEqual(
                    appraise_observation(
                        self.bundle["vectors"][0]["receipt"], self.public,
                        action=changed,
                        nonce=self.bundle["vectors"][0]["nonce"],
                    ), "undetermined",
                )

    def test_digest_encoding_is_strict_lowercase_hex(self):
        for bad in (None, "", "A" * 64, "g" * 64, 0, True, "0" * 63):
            with self.subTest(digest=bad):
                self.assertFalse(valid_digest(bad))
        self.assertTrue(valid_digest("f" * 64))

    def test_malformed_observation_digest_is_undetermined(self):
        case = self.bundle["vectors"][0]
        receipt = json.loads(json.dumps(case["receipt"]))
        receipt["payload"]["action_sha256"] = "Z" * 64
        self.assertEqual(
            appraise_observation(
                receipt, self.public, action=case["action"],
                nonce=case["nonce"],
            ), "undetermined",
        )


if __name__ == "__main__":
    unittest.main()
