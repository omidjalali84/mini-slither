"""
Tests for the delegatecall risk analyzer.

Run
───
    python -m pytest tests/delegatecall/test_delegatecall.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.delegatecall import check_delegatecall

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


# ── AST builders ──────────────────────────────────────────────────────────────

def _delegatecall_stmt(target_name: str = "target") -> dict:
    """Produces: (bool ok,) = <target>.delegatecall(data)"""
    return {
        "nodeType": "VariableDeclarationStatement",
        "declarations": [{"nodeType": "VariableDeclaration", "name": "ok"}],
        "initialValue": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "memberName": "delegatecall",
                "expression": {"nodeType": "Identifier", "name": target_name},
            },
            "arguments": [{"nodeType": "Identifier", "name": "data"}],
        },
    }


def _bare_delegatecall_expr_stmt(target_name: str = "target") -> dict:
    """Bare ExpressionStatement: target.delegatecall(data)"""
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "memberName": "delegatecall",
                "expression": {"nodeType": "Identifier", "name": target_name},
            },
            "arguments": [{"nodeType": "Identifier", "name": "data"}],
        },
    }


def _regular_call_stmt(target_name: str = "target") -> dict:
    """(bool ok,) = target.call(data) — NOT delegatecall."""
    return {
        "nodeType": "VariableDeclarationStatement",
        "declarations": [{"nodeType": "VariableDeclaration", "name": "ok"}],
        "initialValue": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "MemberAccess",
                "memberName": "call",
                "expression": {"nodeType": "Identifier", "name": target_name},
            },
            "arguments": [],
        },
    }


def _make_function(name: str, params: list[str], statements: list) -> dict:
    return {
        "nodeType": "FunctionDefinition",
        "name": name,
        "parameters": {
            "parameters": [
                {"nodeType": "VariableDeclaration", "name": p}
                for p in params
            ]
        },
        "modifiers": [],
        "body": {"nodeType": "Block", "statements": statements},
    }


def _make_source(functions: list) -> dict:
    return {
        "nodeType": "SourceUnit",
        "nodes": [{"nodeType": "ContractDefinition", "nodes": functions}],
    }


# ── integration tests ─────────────────────────────────────────────────────────

@unittest.skipUnless(shutil.which("solc"), "solc not on PATH")
class TestDelegatecallIntegration(unittest.TestCase):

    def test_user_controlled_target_detected(self):
        """DelegatecallProxy.sol: target param passed to delegatecall must be flagged."""
        ast = load("DelegatecallProxy.sol")
        results = check_delegatecall(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for delegatecall with user-controlled target.")

    def test_user_controlled_notes_injection(self):
        ast = load("DelegatecallProxy.sol")
        results = check_delegatecall(ast)
        self.assertTrue(
            any("user-controlled" in r["details"] or "parameter" in r["details"]
                for r in results),
            "Expected details to mention user-controlled/parameter target."
        )

    def test_severity_is_high(self):
        ast = load("DelegatecallProxy.sol")
        results = check_delegatecall(ast)
        self.assertTrue(all(r["severity"] == "HIGH" for r in results))

    def test_function_name_in_finding(self):
        ast = load("DelegatecallProxy.sol")
        results = check_delegatecall(ast)
        functions = [r["function"] for r in results]
        self.assertIn("execute", functions)

    def test_upgradeable_proxy_detected(self):
        """UpgradeableProxy.sol: fixed-target delegatecall in fallback must still be flagged."""
        ast = load("UpgradeableProxy.sol")
        results = check_delegatecall(ast)
        self.assertGreater(len(results), 0,
            "Expected finding even for fixed-target delegatecall.")

    def test_regular_call_not_flagged(self):
        """RegularCall.sol: .call() (not .delegatecall()) must produce no findings."""
        ast = load("RegularCall.sol")
        results = check_delegatecall(ast)
        self.assertEqual(results, [],
            f"Expected no findings for regular call, got: {results}")

    def test_finding_has_required_keys(self):
        ast = load("DelegatecallProxy.sol")
        results = check_delegatecall(ast)
        required = {"severity", "issue", "function", "details", "recommendation"}
        for r in results:
            missing = required - r.keys()
            self.assertFalse(missing, f"Finding missing keys: {missing}")


# ── unit tests (no solc) ──────────────────────────────────────────────────────

class TestDelegatecallUnit(unittest.TestCase):

    def test_unit_delegatecall_to_param_flagged_as_user_controlled(self):
        func = _make_function(
            "execute",
            ["target", "data"],
            [_bare_delegatecall_expr_stmt("target")],
        )
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertIn("parameter", results[0]["details"])

    def test_unit_delegatecall_to_state_var_flagged_but_not_user_controlled(self):
        func = _make_function(
            "forward",
            [],  # no params
            [_bare_delegatecall_expr_stmt("implementation")],
        )
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(len(results), 1)
        # Should NOT mention user-controlled
        self.assertNotIn("parameter", results[0]["details"])

    def test_unit_regular_call_not_flagged(self):
        func = _make_function("safe", ["target"], [_regular_call_stmt("target")])
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(results, [])

    def test_unit_multiple_delegatecalls_in_one_function(self):
        func = _make_function(
            "multi",
            ["t1", "t2"],
            [
                _bare_delegatecall_expr_stmt("t1"),
                _bare_delegatecall_expr_stmt("t2"),
            ],
        )
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(len(results), 2)

    def test_unit_no_delegatecall_no_findings(self):
        func = _make_function("empty", [], [])
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(results, [])

    def test_unit_issue_label_correct(self):
        func = _make_function(
            "execute", ["target"], [_bare_delegatecall_expr_stmt("target")]
        )
        ast = _make_source([func])
        results = check_delegatecall(ast)
        self.assertEqual(results[0]["issue"], "Delegatecall risk")


if __name__ == "__main__":
    unittest.main(verbosity=2)