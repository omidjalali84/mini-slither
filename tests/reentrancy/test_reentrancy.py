"""
Integration tests for the reentrancy analyzer.

Each test loads a real .sol file from tests/contracts/, parses it with
solc via get_ast(), and runs check_reentrancy() on the result.

Requirements
────────────
- solc must be installed and on PATH.
  Install: https://docs.soliditylang.org/en/latest/installing-solidity.html
  Quick:   pip install solc-select && solc-select install 0.8.0 && solc-select use 0.8.0

Run
───
    # from the project root (mini-slither/)
    python -m pytest tests/test_reentrancy.py -v
    # or
    python -m unittest tests/test_reentrancy -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.reentrancy import check_reentrancy

# Absolute path to tests/contracts/ regardless of where pytest is invoked from
CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    """Parse a contract file and return its AST."""
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestReentrancyIntegration(unittest.TestCase):

    # ── vulnerable.sol ────────────────────────────────────────────────────────

    def test_vulnerable_contract_is_detected(self):
        """vulnerable.sol: call() before state update → must produce a HIGH finding."""
        ast = load("vulnerable.sol")
        results = check_reentrancy(ast)

        self.assertGreater(len(results), 0,
            "Expected at least one finding but got none.")

    def test_vulnerable_finding_severity_is_high(self):
        """Every finding in vulnerable.sol must be severity HIGH."""
        ast = load("vulnerable.sol")
        results = check_reentrancy(ast)

        for finding in results:
            self.assertEqual(finding["severity"], "HIGH",
                f"Expected HIGH severity, got: {finding['severity']}")

    def test_vulnerable_finding_names_withdraw(self):
        """The finding must point at the 'withdraw' function."""
        ast = load("vulnerable.sol")
        results = check_reentrancy(ast)

        found_functions = [r["function"] for r in results]
        self.assertIn("withdraw", found_functions,
            f"Expected 'withdraw' in findings, got: {found_functions}")

    def test_vulnerable_finding_has_all_keys(self):
        """Each finding must contain the required output keys."""
        ast = load("vulnerable.sol")
        results = check_reentrancy(ast)

        required_keys = {"severity", "issue", "function", "details", "recommendation"}
        for finding in results:
            missing = required_keys - finding.keys()
            self.assertFalse(missing, f"Finding is missing keys: {missing}")

    # ── vulnerable2.sol ────────────────────────────────────────────────────────

    def test_vulnerable2_contract_is_detected(self):
        """vulnerable2.sol: call() before local changes → must produce a HIGH finding."""
        ast = load("vulnerable2.sol")
        results = check_reentrancy(ast)

        self.assertGreater(len(results), 0,
            "Expected at least one finding but got none.")

    # ── safe.sol ──────────────────────────────────────────────────────────────

    def test_safe_contract_produces_no_findings(self):
        """safe.sol: state update before call() → must produce zero findings."""
        ast = load("safe.sol")
        results = check_reentrancy(ast)

        self.assertEqual(len(results), 0,
            f"Expected no findings for safe contract, got: {results}")

        
        # ── safe2.sol ──────────────────────────────────────────────────────────────

    def test_safe2_contract_produces_no_findings(self):
        """safe2.sol: state update before local changes → must produce zero findings."""
        ast = load("safe2.sol")
        results = check_reentrancy(ast)

        self.assertEqual(len(results), 0,
            f"Expected no findings for safe contract, got: {results}")



if __name__ == "__main__":
    unittest.main(verbosity=2)