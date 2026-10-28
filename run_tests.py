"""
SentinelNIDS Test Suite Runner.
Executes all unit, schema, parser, and normalization tests using standard library unittest.
Exits with code 0 on success, or code 1 on failure.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_all_tests() -> int:
    print("=" * 70)
    print(" Running SentinelNIDS Comprehensive Verification Test Suite")
    print(" (Phase 1: Ingestion & Parsing | Phase 2: ML Pipeline | Phase 3: Backend & Rules)")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(PROJECT_ROOT / "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)

    if result.wasSuccessful():
        print(">>> ALL VERIFICATION TESTS PASSED SUCCESSFULLY! <<<")
        return 0
    else:
        print(">>> SOME TESTS FAILED. PLEASE REVIEW OUTPUT ABOVE. <<<")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)

