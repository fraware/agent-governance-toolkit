"""Local functional and adversarial tests for the target-operator pilot.

All keys, DB state and principals here share the local test administrator.
These tests validate behavior, not the existence of a second operator.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from effect_target_protocol import appraise_observation, canonical
from verify_target_observation import offline_appraise
from operator_pilot.target_observer import (
    PilotInputError, initialize_operator_key, snapshot,
)


class TargetOperatorPilotTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("POSIX file permissions required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.key_dir = root / "target-keys"
        self.db_dir = root / "target-state"
        self.key_dir.mkdir(mode=0o700)
        self.db_dir.mkdir(mode=0o700)
        self.key_dir.chmod(0o700)
        self.db_dir.chmod(0o700)
        self.key_info = initialize_operator_key(self.key_dir)
        self.private = self.key_dir / "observation-private.raw"
        self.pub = self.key_dir / "observation-public.raw"
        self.db_file = self.db_dir / "ledger.sqlite"
        with sqlite3.connect(self.db_file) as db:
            db.execute("CREATE TABLE effects(action_id TEXT PRIMARY KEY, action_bytes BLOB NOT NULL)")
        self.db_file.chmod(0o600)
        self.action = {
            "action_id": "record-001", "subject": "agent-1",
            "tenant": "tenant-a", "resource": "/granted/report",
            "operation": "write", "value": "pilot-content",
        }
        self.challenge = root / "challenge.json"
        self.nonce = "0123456789abcdef0123456789abcdef"
        self.challenge.write_text(json.dumps({
            "schema": "effect-target-challenge/v1",
            "action_id": self.action["action_id"],
            "nonce": self.nonce,
        }), encoding="utf-8")
        self.public_key = Ed25519PublicKey.from_public_bytes(self.pub.read_bytes())

    def commit_fixture(self):
        with sqlite3.connect(self.db_file) as db:
            db.execute(
                "INSERT INTO effects VALUES (?,?)",
                (self.action["action_id"], canonical(self.action)),
            )
        self.db_file.chmod(0o600)

    def observe(self):
        return snapshot(self.db_file, self.challenge, self.private)

    def verdict(self, receipt, action=None, nonce=None):
        return appraise_observation(
            receipt, self.public_key,
            action=self.action if action is None else action,
            nonce=self.nonce if nonce is None else nonce,
        )

    def test_private_key_mode_and_no_overwrite(self):
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.pub.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(self.pub.read_bytes()).hexdigest(),
                         self.key_info["public_key_sha256"])
        old_key = self.private.read_bytes()
        with self.assertRaises(PilotInputError):
            initialize_operator_key(self.key_dir)
        self.assertEqual(self.private.read_bytes(), old_key)

    def test_target_owned_commit_established(self):
        self.commit_fixture()
        receipt = self.observe()
        self.assertEqual(self.verdict(receipt), "established")
        self.assertEqual(receipt["payload"]["state"], "committed")

    def test_target_owned_absence_is_refuted_only_for_snapshot(self):
        receipt = self.observe()
        self.assertEqual(self.verdict(receipt), "refuted")
        self.assertEqual(receipt["payload"]["state"], "absent")

    def test_verifier_uses_out_of_band_pin(self):
        self.commit_fixture()
        receipt_file = self.key_dir.parent / "receipt.json"
        receipt_file.write_text(json.dumps(self.observe()), encoding="utf-8")
        action_file = self.key_dir.parent / "action.json"
        action_file.write_text(json.dumps(self.action), encoding="utf-8")
        good = offline_appraise(
            action_path=action_file, receipt_path=receipt_file,
            public_key_path=self.pub,
            expected_key_sha256=self.key_info["public_key_sha256"],
            nonce=self.nonce,
        )
        self.assertEqual(good["verdict"], "established")
        mismatch = offline_appraise(
            action_path=action_file, receipt_path=receipt_file,
            public_key_path=self.pub,
            expected_key_sha256="0" * 64, nonce=self.nonce,
        )
        self.assertEqual(mismatch["verdict"], "undetermined")

    def test_different_content_refuted(self):
        self.commit_fixture()
        receipt = self.observe()
        wrong = {**self.action, "value": "altered"}
        self.assertEqual(self.verdict(receipt, action=wrong), "refuted")

    def test_wrong_nonce_is_undetermined(self):
        self.commit_fixture()
        self.assertEqual(self.verdict(self.observe(), nonce="f" * 32),
                         "undetermined")

    def test_rejects_database_exposed_by_world_readable_mode(self):
        self.commit_fixture()
        self.db_file.chmod(0o644)
        with self.assertRaises(PilotInputError):
            self.observe()

    def test_restrict_signing_key_permissions(self):
        self.private.chmod(0o644)
        with self.assertRaises(PilotInputError):
            self.observe()

    def test_reject_bad_challenge_and_duplicate_fields(self):
        for value in (
            '{"schema":"effect-target-challenge/v1","action_id":"record-001","nonce":"short"}',
            '{"schema":"effect-target-challenge/v1","action_id":"record-001","nonce":"'
            + self.nonce + '","nonce":"' + self.nonce + '"}',
            '{"schema":"effect-target-challenge/v1","action_id":"record-001"}',
        ):
            with self.subTest(challenge=value):
                self.challenge.write_text(value, encoding="utf-8")
                with self.assertRaises(PilotInputError):
                    self.observe()

    def test_corrupt_or_noncanonical_effect_is_refused(self):
        blob = b'{"action_id":"record-001","unknown":"x"}'
        with sqlite3.connect(self.db_file) as db:
            db.execute("INSERT INTO effects VALUES (?,?)",
                       (self.action["action_id"], blob))
        self.db_file.chmod(0o600)
        with self.assertRaises(PilotInputError):
            self.observe()

    def test_duplicate_rows_in_nonunique_target_table_are_rejected(self):
        # Even if target-schema integrity is compromised, the observation
        # signer refuses to pick an arbitrary duplicate action ID.
        with sqlite3.connect(self.db_file) as db:
            db.execute("DROP TABLE effects")
            db.execute(
                "CREATE TABLE effects(action_id TEXT, action_bytes BLOB NOT NULL)"
            )
            db.executemany(
                "INSERT INTO effects VALUES(?, ?)",
                [
                    (self.action["action_id"], canonical(self.action)),
                    (self.action["action_id"], canonical(self.action)),
                ],
            )
        self.db_file.chmod(0o600)
        with self.assertRaises(PilotInputError):
            self.observe()

    def test_nonexistent_database_never_created(self):
        self.db_file.unlink()
        with self.assertRaises((OSError, PilotInputError)):
            self.observe()
        self.assertFalse(self.db_file.exists())


if __name__ == "__main__":
    unittest.main()
