"""Strict ACS action-binding conformance gate; native and crypto are mandatory."""
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
        print(f"ACTION_BINDING_NATIVE_UNAVAILABLE: {exc}", file=sys.stderr)
        return 3
    location = getattr(_native, "__file__", "")
    if not isinstance(location, str) or not any(
        location.endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES
    ):
        print("ACTION_BINDING_NATIVE_UNAVAILABLE: compiled runtime absent", file=sys.stderr)
        return 3
    test_dir = Path(__file__).resolve().parents[1] / "sdk" / "python" / "tests"
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(test_dir),
        pattern="test_effect_grounded_native_action_binding.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 12 or result.skipped or not result.wasSuccessful():
        print(
            f"ACTION_BINDING_NATIVE_FAILED: run={result.testsRun} skipped={len(result.skipped)}",
            file=sys.stderr,
        )
        return 1
    print("ACTION_BINDING_NATIVE_PASSED: 12 tests, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
