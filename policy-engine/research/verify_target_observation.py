"""Offline target-snapshot appraisal with an explicitly supplied public-key pin.

Research utility, independent of ACS SDK and its host. The verifier never
discovers keys from the evidence bundle or the target service. The caller is
responsible for authenticating the expected SHA-256 fingerprint through a
separate trusted channel. Merely passing the fingerprint on the same untrusted
channel as the receipt does not provide an independent trust anchor.

A signed absent snapshot refutes only the claim that an exact action is present
in this target's observed state at the snapshot instant. It cannot establish
that an effect never happened or did not happen elsewhere.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from effect_target_protocol import appraise_observation

MAX_INPUT_BYTES = 1024 * 1024
RESULT_SCHEMA = "effect-target-appraisal/v1"


def load_limited_json(path: Path):
    """Read a small JSON artifact; reject oversized/malformed inputs."""
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("JSON artifact exceeds size limit")
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("JSON artifact exceeds size limit")
    return json.loads(
        data.decode("utf-8"),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("non-finite JSON number")
        ),
    )


def offline_appraise(*, action_path: Path, receipt_path: Path,
                    public_key_path: Path, expected_key_sha256: str,
                    nonce: str) -> dict:
    """Appraise against an externally pinned raw Ed25519 public key.

    Malformed evidence, key errors and missing artifacts yield undetermined.
    The expected key hash is a caller trust premise, never learned from receipt.
    """
    result = {
        "schema": RESULT_SCHEMA,
        "verdict": "undetermined",
        "reason": "invalid_or_missing_evidence",
        "scope": "exact_action_in_target_snapshot",
        "key_pin_matched": False,
    }
    if (type(expected_key_sha256) is not str
            or len(expected_key_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_key_sha256)):
        result["reason"] = "invalid_external_key_pin"
        return result
    if type(nonce) is not str or not nonce:
        result["reason"] = "invalid_expected_nonce"
        return result
    try:
        # The key file contains exactly 32 RAW public-key bytes (RFC 8032).
        # It must be distributed and authenticated outside the untrusted
        # receipt channel. No trust is inferred from filesystem co-location.
        key_bytes = public_key_path.read_bytes()
        if len(key_bytes) != 32:
            result["reason"] = "invalid_target_public_key"
            return result
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        if not hmac.compare_digest(fingerprint, expected_key_sha256):
            result["reason"] = "external_key_pin_mismatch"
            return result
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        result["key_pin_matched"] = True
        action = load_limited_json(action_path)
        receipt = load_limited_json(receipt_path)
        verdict = appraise_observation(
            receipt, public_key, action=action, nonce=nonce,
        )
        result["verdict"] = verdict
        result["reason"] = (
            "verified_target_snapshot" if verdict != "undetermined"
            else "invalid_or_missing_evidence"
        )
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        # Do not promote incomplete or improperly interpreted evidence.
        pass
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Appraise a signed target-state snapshot using an external key pin."
    )
    parser.add_argument("--action", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--target-public-key", type=Path, required=True,
                        help="File containing 32 raw Ed25519 public-key bytes")
    parser.add_argument("--expected-key-sha256", required=True,
                        help="64 lowercase hex digits obtained through a trusted channel")
    parser.add_argument("--nonce", required=True,
                        help="Challenge nonce provided by the evidence requester")
    parser.add_argument("--expect", required=True,
                        choices=("established", "refuted", "undetermined"),
                        help="Mandatory expected verdict; mismatches fail the CLI gate")
    args = parser.parse_args(argv)
    result = offline_appraise(
        action_path=args.action,
        receipt_path=args.observation,
        public_key_path=args.target_public_key,
        expected_key_sha256=args.expected_key_sha256,
        nonce=args.nonce,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["verdict"] == args.expect else 1


if __name__ == "__main__":
    sys.exit(main())
