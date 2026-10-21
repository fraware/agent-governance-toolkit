"""Strict native ACS two-signature conformance gate (zero skips)."""
from __future__ import annotations

import importlib.machinery
from pathlib import Path
import sys
import unittest


def main() -> int:
    try:
        from agent_control_specification import _native
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    except (ImportError, OSError) as exc:
        print(f"DUAL_ATTESTATION_NATIVE_UNAVAILABLE: {exc}", file=sys.stderr)
        return 3
    path = getattr(_native, "__file__", "")
    if not isinstance(path, str) or not any(
        path.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        print("DUAL_ATTESTATION_NATIVE_UNAVAILABLE: compiled extension missing", file=sys.stderr)
        return 3
    directory = Path(__file__).resolve().parents[1] / "sdk" / "python" / "tests"
    suite = unittest.defaultTestLoader.discover(
        str(directory), pattern="test_effect_grounded_native_dual_attestation.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 16 or result.skipped or not result.wasSuccessful():
        print(
            f"DUAL_ATTESTATION_NATIVE_FAILED: run={result.testsRun} skipped={len(result.skipped)}",
            file=sys.stderr,
        )
        return 1
    print("DUAL_ATTESTATION_NATIVE_PASSED: 16 tests, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
