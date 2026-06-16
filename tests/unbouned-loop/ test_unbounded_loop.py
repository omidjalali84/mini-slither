"""
Tests for the unbounded loop analyzer.

Run
───
    python -m pytest tests/unbounded-loop/test_unbounded_loop.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.unbounded_loop import check_unbounded_loop

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


# ── AST builders ──────────────────────────────────────────────────────────────

def _for_loop_with_length(array_name: str, body_stmts: list) -> dict:
    """for (uint i = 0; i < <array_name>.length; i++) { ... }"""
    return {
        "nodeType": "ForStatement",
        "src": "0:0:0",
        "condition": {
            "nodeType": "BinaryOperation",
            "operator": "<",
            "leftExpression": {"nodeType": "Identifier", "name": "i"},
            "rightExpression": {
                "nodeType": "MemberAccess",
                "memberName": "length",
                "expression": {"nodeType": "Identifier", "name": array_name},
            },
        },
        "body": {"nodeType": "Block", "statements": body_stmts},
    }


def _while_loop_with_length(array_name: str, body_stmts: list) -> dict:
    """while (i < <array_name>.length) { ... }"""
    return {
        "nodeType": "WhileStatement",
        "src": "0:0:0",
        "condition": {
            "nodeType": "BinaryOperation",
            "operator": "<",
            "leftExpression": {"nodeType": "Identifier", "name": "i"},
            "rightExpression": {
                "nodeType": "MemberAccess",
                "memberName": "length",
                "expression": {"nodeType": "Identifier", "name": array_name},
            },
        },
        "body": {"nodeType": "Block", "statements": body_stmts},
    }


def _for_loop_constant(limit: int, body_stmts: list) -> dict:
    """for (uint i = 0; i < <constant>; i++) { ... }"""
    return {
        "nodeType": "ForStatement",
        "src": "0:0:0",
        "condition": {
            "nodeType": "BinaryOperation",
            "operator": "<",
            "leftExpression": {"nodeType": "Identifier", "name": "i"},
            "rightExpression": {"nodeType": "Literal", "value": str(limit)},
        },
        "body": {"nodeType": "Block", "statements": body_stmts},
    }


def _make_source(statements: list) -> dict:
    return {
        "nodeType": "SourceUnit",
        "nodes": [{
            "nodeType": "ContractDefinition",
            "nodes": [{
                "nodeType": "FunctionDefinition",
                "name": "test",
                "body": {"nodeType": "Block", "statements": statements},
            }],
        }],
    }


# ── integration tests ─────────────────────────────────────────────────────────

@unittest.skipUnless(shutil.which("solc"), "solc not on PATH")
class TestUnboundedLoopIntegration(unittest.TestCase):

    def test_unbounded_for_loop_detected(self):
        """UnboundedDistribute.sol: loop over recipients.length must be flagged."""
        ast = load("UnboundedDistribute.sol")
        results = check_unbounded_loop(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for unbounded for-loop.")

    def test_unbounded_for_severity_is_medium(self):
        ast = load("UnboundedDistribute.sol")
        results = check_unbounded_loop(ast)
        for r in results:
            self.assertEqual(r["severity"], "MEDIUM")

    def test_unbounded_while_loop_detected(self):
        """UnboundedWhile.sol: while (i < users.length) must be flagged."""
        ast = load("UnboundedWhile.sol")
        results = check_unbounded_loop(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for unbounded while-loop.")

    def test_bounded_loop_not_flagged(self):
        """BoundedLoop.sol: loop over a constant MAX_BATCH must not be flagged."""
        ast = load("BoundedLoop.sol")
        results = check_unbounded_loop(ast)
        self.assertEqual(results, [],
            f"Expected no findings for bounded loop, got: {results}")

    def test_finding_has_required_keys(self):
        ast = load("UnboundedDistribute.sol")
        results = check_unbounded_loop(ast)
        required = {"severity", "issue", "details", "recommendation"}
        for r in results:
            missing = required - r.keys()
            self.assertFalse(missing, f"Finding missing keys: {missing}")


# ── unit tests (no solc) ──────────────────────────────────────────────────────

class TestUnboundedLoopUnit(unittest.TestCase):

    def test_unit_for_loop_with_array_length_flagged(self):
        ast = _make_source([_for_loop_with_length("recipients", [])])
        results = check_unbounded_loop(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "MEDIUM")
        self.assertIn("recipients", results[0]["details"])

    def test_unit_while_loop_with_array_length_flagged(self):
        ast = _make_source([_while_loop_with_length("users", [])])
        results = check_unbounded_loop(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["issue"], "Unbounded loop")

    def test_unit_bounded_for_loop_not_flagged(self):
        ast = _make_source([_for_loop_constant(100, [])])
        results = check_unbounded_loop(ast)
        self.assertEqual(results, [])

    def test_unit_nested_unbounded_loops_both_flagged(self):
        inner = _for_loop_with_length("members", [])
        outer = _for_loop_with_length("groups", [inner])
        ast = _make_source([outer])
        results = check_unbounded_loop(ast)
        self.assertGreaterEqual(len(results), 2,
            "Both outer and inner unbounded loops should be flagged.")

    def test_unit_multiple_functions_each_flagged(self):
        loop1 = _for_loop_with_length("list1", [])
        loop2 = _for_loop_with_length("list2", [])
        ast = {
            "nodeType": "SourceUnit",
            "nodes": [{
                "nodeType": "ContractDefinition",
                "nodes": [
                    {
                        "nodeType": "FunctionDefinition",
                        "name": "fn1",
                        "body": {"nodeType": "Block", "statements": [loop1]},
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "name": "fn2",
                        "body": {"nodeType": "Block", "statements": [loop2]},
                    },
                ],
            }],
        }
        results = check_unbounded_loop(ast)
        self.assertEqual(len(results), 2)

    def test_unit_no_loops_no_findings(self):
        ast = _make_source([])
        results = check_unbounded_loop(ast)
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)