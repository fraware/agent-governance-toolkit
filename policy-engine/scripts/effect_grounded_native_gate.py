"""Mandatory native ACS conformance gate for the effect-grounding probe.

Unlike the general SDK test suite, this command must fail if the Rust-backed
extension is missing, every test is skipped, or any test fails.
Run from policy-engine/: python scripts/effect_grounded_native_gate.py
"""
from __future__ import annotations

import importlib.machinery
from pathlib import Path
import sys
import unittest


def main() -> int:
    try:
        from agent_control_specification import _native
    except (ImportError, OSError) as exc:
        print(f"NATIVE_ACS_UNAVAILABLE: {exc}", file=sys.stderr)
        return 3
    origin = getattr(_native, "__file__", "")
    if not isinstance(origin, str) or not any(
        origin.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        print("NATIVE_ACS_UNAVAILABLE: compiled extension not established", file=sys.stderr)
        return 3
    test_dir = Path(__file__).resolve().parents[1] / "sdk" / "python" / "tests"
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(test_dir),
        pattern="test_effect_grounded_native_boundary.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 8 or result.skipped or not result.wasSuccessful():
        print(
            f"NATIVE_ACS_CONFORMANCE_FAILED: run={result.testsRun} skipped={len(result.skipped)}",
            file=sys.stderr,
        )
        return 1
    print("NATIVE_ACS_CONFORMANCE_PASSED: 8 tests, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
