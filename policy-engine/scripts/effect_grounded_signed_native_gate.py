"""Mandatory native ACS + signed-target gate; skip or missing native is failure."""
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
        print(f"SIGNED_TARGET_NATIVE_UNAVAILABLE: {exc}", file=sys.stderr)
        return 3
    path = getattr(_native, "__file__", "")
    if not isinstance(path, str) or not any(
        path.endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES
    ):
        print("SIGNED_TARGET_NATIVE_UNAVAILABLE: compiled extension absent", file=sys.stderr)
        return 3

    test_dir = Path(__file__).resolve().parents[1] / "sdk" / "python" / "tests"
    suite = unittest.defaultTestLoader.discover(
        str(test_dir), pattern="test_effect_grounded_native_signed_target.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 18 or result.skipped or not result.wasSuccessful():
        print(
            f"SIGNED_TARGET_NATIVE_FAILED: run={result.testsRun} "
            f"skipped={len(result.skipped)}",
            file=sys.stderr,
        )
        return 1
    print("SIGNED_TARGET_NATIVE_PASSED: 18 tests, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
