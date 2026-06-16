"""
Tests for the unused state variable analyzer.

Run
───
    python -m pytest tests/unused-state-var/test_unused_state_var.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.unused_state_var import check_unused_state_var

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


# ── helpers for unit AST construction ────────────────────────────────────────

def _make_contract(state_vars: list[dict], func_body_identifiers: list[str]) -> dict:
    """
    Build a minimal SourceUnit AST with given state vars and a single
    function body referencing the given identifier names.
    """
    return {
        "nodeType": "SourceUnit",
        "nodes": [{
            "nodeType": "ContractDefinition",
            "nodes": [
                *[{
                    "nodeType": "StateVariableDeclaration",
                    "variables": [{
                        "nodeType": "VariableDeclaration",
                        "name": v["name"],
                        "visibility": v.get("visibility", "internal"),
                        "src": "0:0:0",
                    }],
                } for v in state_vars],
                {
                    "nodeType": "FunctionDefinition",
                    "name": "doWork",
                    "body": {
                        "nodeType": "Block",
                        "statements": [
                            {
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "Identifier",
                                    "name": ident,
                                },
                            }
                            for ident in func_body_identifiers
                        ],
                    },
                },
            ],
        }],
    }


# ── integration tests ─────────────────────────────────────────────────────────

@unittest.skipUnless(shutil.which("solc"), "solc not on PATH")
class TestUnusedStateVarIntegration(unittest.TestCase):

    def test_unused_vars_detected(self):
        """UnusedVars.sol: unusedLimit and deprecated are never referenced."""
        ast = load("UnusedVars.sol")
        results = check_unused_state_var(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for unused state variables.")

    def test_unused_var_severity_is_info(self):
        ast = load("UnusedVars.sol")
        results = check_unused_state_var(ast)
        for r in results:
            self.assertEqual(r["severity"], "INFO")

    def test_unused_var_names_in_findings(self):
        ast = load("UnusedVars.sol")
        results = check_unused_state_var(ast)
        flagged = {r["variable"] for r in results}
        self.assertIn("unusedLimit", flagged)
        self.assertIn("deprecated", flagged)

    def test_used_var_not_flagged(self):
        """owner is referenced in the modifier body — must NOT be flagged."""
        ast = load("UnusedVars.sol")
        results = check_unused_state_var(ast)
        flagged = {r["variable"] for r in results}
        self.assertNotIn("owner", flagged)

    def test_finding_has_required_keys(self):
        ast = load("UnusedVars.sol")
        results = check_unused_state_var(ast)
        required = {"severity", "issue", "variable", "details", "recommendation"}
        for r in results:
            missing = required - r.keys()
            self.assertFalse(missing, f"Finding missing keys: {missing}")

    def test_all_vars_used_no_findings(self):
        """AllVarsUsed.sol: all internal vars are referenced — no findings."""
        ast = load("AllVarsUsed.sol")
        results = check_unused_state_var(ast)
        self.assertEqual(results, [],
            f"Expected no findings, got: {results}")

    def test_public_vars_not_flagged(self):
        """PublicVarsOnly.sol: public vars have auto-getters — must not be flagged."""
        ast = load("PublicVarsOnly.sol")
        results = check_unused_state_var(ast)
        self.assertEqual(results, [],
            f"Expected no findings for public vars, got: {results}")


# ── unit tests (no solc) ──────────────────────────────────────────────────────

class TestUnusedStateVarUnit(unittest.TestCase):

    def test_unit_single_unused_internal_var(self):
        ast = _make_contract(
            [{"name": "deadVar", "visibility": "internal"}],
            [],  # nothing referenced in function
        )
        results = check_unused_state_var(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["variable"], "deadVar")
        self.assertEqual(results[0]["severity"], "INFO")

    def test_unit_used_var_not_flagged(self):
        ast = _make_contract(
            [{"name": "counter", "visibility": "internal"}],
            ["counter"],  # referenced in function body
        )
        results = check_unused_state_var(ast)
        self.assertEqual(results, [])

    def test_unit_public_var_not_flagged(self):
        ast = _make_contract(
            [{"name": "total", "visibility": "public"}],
            [],  # never referenced, but public = has getter
        )
        results = check_unused_state_var(ast)
        self.assertEqual(results, [])

    def test_unit_mixed_vars(self):
        """Two vars declared; one used, one not."""
        ast = _make_contract(
            [
                {"name": "active", "visibility": "internal"},
                {"name": "unused", "visibility": "internal"},
            ],
            ["active"],
        )
        results = check_unused_state_var(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["variable"], "unused")

    def test_unit_no_state_vars(self):
        ast = _make_contract([], [])
        results = check_unused_state_var(ast)
        self.assertEqual(results, [])

    def test_unit_private_var_unused_flagged(self):
        ast = _make_contract(
            [{"name": "secret", "visibility": "private"}],
            [],
        )
        results = check_unused_state_var(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["variable"], "secret")


if __name__ == "__main__":
    unittest.main(verbosity=2)