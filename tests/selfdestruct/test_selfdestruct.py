"""
Tests for the self-destruct risk analyzer.

Run
───
    python -m pytest tests/selfdestruct/test_selfdestruct.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.self_destruct import check_selfdestruct

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


# ── AST builders ──────────────────────────────────────────────────────────────

def _selfdestruct_call(recipient: str = "owner") -> dict:
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {"nodeType": "Identifier", "name": "selfdestruct"},
            "arguments": [{"nodeType": "Identifier", "name": recipient}],
        },
    }


def _suicide_call(recipient: str = "owner") -> dict:
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {"nodeType": "Identifier", "name": "suicide"},
            "arguments": [{"nodeType": "Identifier", "name": recipient}],
        },
    }


def _make_function(name: str, statements: list, modifiers: list | None = None) -> dict:
    return {
        "nodeType": "FunctionDefinition",
        "name": name,
        "modifiers": modifiers or [],
        "body": {"nodeType": "Block", "statements": statements},
    }


def _make_source(functions: list) -> dict:
    return {
        "nodeType": "SourceUnit",
        "nodes": [{"nodeType": "ContractDefinition", "nodes": functions}],
    }


def _owner_modifier() -> dict:
    return {
        "modifierName": {"name": "onlyOwner"},
    }


# ── integration tests ─────────────────────────────────────────────────────────

@unittest.skipUnless(shutil.which("solc"), "solc not on PATH")
class TestSelfdestructIntegration(unittest.TestCase):

    def test_kill_switch_detected(self):
        """KillSwitch.sol: owner-gated selfdestruct() must be flagged HIGH."""
        ast = load("KillSwitch.sol")
        results = check_selfdestruct(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for selfdestruct.")

    def test_kill_switch_severity_is_high(self):
        ast = load("KillSwitch.sol")
        results = check_selfdestruct(ast)
        self.assertTrue(all(r["severity"] == "HIGH" for r in results))

    def test_kill_switch_names_function(self):
        ast = load("KillSwitch.sol")
        results = check_selfdestruct(ast)
        functions = [r["function"] for r in results]
        self.assertIn("destroy", functions)

    def test_unprotected_kill_detected(self):
        """UnprotectedKill.sol: selfdestruct without auth must also be flagged."""
        ast = load("UnprotectedKill.sol")
        results = check_selfdestruct(ast)
        self.assertGreater(len(results), 0)

    def test_unprotected_kill_notes_no_access_control(self):
        ast = load("UnprotectedKill.sol")
        results = check_selfdestruct(ast)
        self.assertTrue(any("no obvious access control" in r["details"] for r in results))

    def test_no_selfdestruct_no_findings(self):
        """NoKillSwitch.sol: no selfdestruct — must produce zero findings."""
        ast = load("NoKillSwitch.sol")
        results = check_selfdestruct(ast)
        self.assertEqual(results, [],
            f"Expected no findings, got: {results}")

    def test_finding_has_required_keys(self):
        ast = load("KillSwitch.sol")
        results = check_selfdestruct(ast)
        required = {"severity", "issue", "function", "details", "recommendation"}
        for r in results:
            missing = required - r.keys()
            self.assertFalse(missing, f"Finding missing keys: {missing}")


# ── unit tests (no solc) ──────────────────────────────────────────────────────

class TestSelfdestructUnit(unittest.TestCase):

    def test_unit_selfdestruct_flagged(self):
        ast = _make_source([_make_function("destroy", [_selfdestruct_call()])])
        results = check_selfdestruct(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[0]["function"], "destroy")

    def test_unit_suicide_alias_flagged(self):
        """The deprecated suicide() alias must also be detected."""
        ast = _make_source([_make_function("kill", [_suicide_call()])])
        results = check_selfdestruct(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["function"], "kill")

    def test_unit_owner_gated_notes_centralization(self):
        func = _make_function(
            "destroy",
            [_selfdestruct_call()],
            modifiers=[_owner_modifier()],
        )
        ast = _make_source([func])
        results = check_selfdestruct(ast)
        self.assertEqual(len(results), 1)
        self.assertIn("privileged", results[0]["details"])

    def test_unit_no_selfdestruct_no_findings(self):
        regular_call = {
            "nodeType": "ExpressionStatement",
            "expression": {
                "nodeType": "FunctionCall",
                "expression": {"nodeType": "Identifier", "name": "transfer"},
                "arguments": [],
            },
        }
        ast = _make_source([_make_function("safe", [regular_call])])
        results = check_selfdestruct(ast)
        self.assertEqual(results, [])

    def test_unit_multiple_functions_each_flagged(self):
        ast = _make_source([
            _make_function("destroy1", [_selfdestruct_call()]),
            _make_function("destroy2", [_selfdestruct_call()]),
        ])
        results = check_selfdestruct(ast)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)