"""
Integration + unit tests for the unchecked external call analyzer.

Each integration test loads a real .sol file from tests/unchecked_call/contracts/,
parses it with solc via get_ast(), and runs check_unchecked_call() on the result.

Requirements
────────────
- solc must be installed and on PATH.

Run
───
    python -m pytest tests/unchecked_call/test_unchecked_call.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.unchecked_call import check_unchecked_call

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


# ── helpers for unit AST construction ────────────────────────────────────────

def _make_function(name: str, statements: list) -> dict:
    return {
        "nodeType": "FunctionDefinition",
        "name": name,
        "body": {"nodeType": "Block", "statements": statements},
    }


def _bare_call(method: str = "call") -> dict:
    """ExpressionStatement wrapping a bare .call{value:x}("") — return value ignored."""
    return {
        "nodeType": "ExpressionStatement",
        "expression": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "FunctionCallOptions",
                "expression": {
                    "nodeType": "MemberAccess",
                    "memberName": method,
                    "expression": {"nodeType": "Identifier", "name": "dest"},
                },
            },
            "arguments": [{"nodeType": "Literal", "value": ""}],
        },
    }


def _tuple_assignment_call(method: str = "call") -> dict:
    """
    (bool ok,) = addr.call{...}("")  — return value IS captured.
    Represented as a VariableDeclarationStatement (not ExpressionStatement).
    """
    return {
        "nodeType": "VariableDeclarationStatement",
        "declarations": [{"nodeType": "VariableDeclaration", "name": "ok"}],
        "initialValue": {
            "nodeType": "FunctionCall",
            "expression": {
                "nodeType": "FunctionCallOptions",
                "expression": {
                    "nodeType": "MemberAccess",
                    "memberName": method,
                    "expression": {"nodeType": "Identifier", "name": "dest"},
                },
            },
        },
    }


def _make_source(functions: list) -> dict:
    return {
        "nodeType": "SourceUnit",
        "nodes": [{
            "nodeType": "ContractDefinition",
            "nodes": functions,
        }],
    }


# ── integration tests ─────────────────────────────────────────────────────────

@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestUncheckedCallVulnerable(unittest.TestCase):

    def test_bare_call_detected(self):
        """UncheckedCall.sol: bare .call() must produce a MEDIUM finding."""
        ast = load("UncheckedCall.sol")
        results = check_unchecked_call(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for bare .call().")

    def test_bare_call_severity_is_medium(self):
        ast = load("UncheckedCall.sol")
        results = check_unchecked_call(ast)
        self.assertTrue(all(r["severity"] == "MEDIUM" for r in results))

    def test_bare_call_names_function(self):
        ast = load("UncheckedCall.sol")
        results = check_unchecked_call(ast)
        functions = [r["function"] for r in results]
        self.assertIn("sendEth", functions)

    def test_finding_has_all_keys(self):
        ast = load("UncheckedCall.sol")
        results = check_unchecked_call(ast)
        required = {"severity", "issue", "function", "details", "recommendation"}
        for r in results:
            self.assertFalse(required - r.keys(), f"Missing keys: {required - r.keys()}")

    def test_bare_send_detected(self):
        """UncheckedSend.sol: bare .send() must produce a MEDIUM finding."""
        ast = load("UncheckedSend.sol")
        results = check_unchecked_call(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding for bare .send().")
        self.assertTrue(any("send" in r["details"] for r in results))


@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestUncheckedCallSafe(unittest.TestCase):

    def test_checked_call_not_flagged(self):
        """CheckedCall.sol: (bool ok,) = call(...) + require(ok) must produce no findings."""
        ast = load("CheckedCall.sol")
        results = check_unchecked_call(ast)
        self.assertEqual(results, [],
            f"Expected no findings for checked .call(), got: {results}")

    def test_transfer_not_flagged(self):
        """TransferSafe.sol: .transfer() auto-reverts — must not be flagged."""
        ast = load("TransferSafe.sol")
        results = check_unchecked_call(ast)
        self.assertEqual(results, [],
            f"Expected no findings for .transfer(), got: {results}")


# ── unit tests (no solc) ──────────────────────────────────────────────────────

class TestUncheckedCallUnit(unittest.TestCase):

    def test_unit_bare_call_flagged(self):
        ast = _make_source([_make_function("doCall", [_bare_call("call")])])
        results = check_unchecked_call(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "MEDIUM")
        self.assertEqual(results[0]["function"], "doCall")

    def test_unit_bare_send_flagged(self):
        ast = _make_source([_make_function("doSend", [_bare_call("send")])])
        results = check_unchecked_call(ast)
        self.assertEqual(len(results), 1)

    def test_unit_bare_delegatecall_flagged(self):
        ast = _make_source([_make_function("doDelegate", [_bare_call("delegatecall")])])
        results = check_unchecked_call(ast)
        self.assertEqual(len(results), 1)

    def test_unit_tuple_assignment_not_flagged(self):
        """(bool ok,) = addr.call(...) — return value is captured."""
        ast = _make_source([_make_function("safe", [_tuple_assignment_call("call")])])
        results = check_unchecked_call(ast)
        self.assertEqual(results, [])

    def test_unit_multiple_bare_calls_in_one_function(self):
        ast = _make_source([_make_function(
            "multiCall",
            [_bare_call("call"), _bare_call("send")],
        )])
        results = check_unchecked_call(ast)
        self.assertEqual(len(results), 2)

    def test_unit_transfer_not_flagged(self):
        """transfer() auto-reverts — must never be flagged."""
        transfer_stmt = {
            "nodeType": "ExpressionStatement",
            "expression": {
                "nodeType": "FunctionCall",
                "expression": {
                    "nodeType": "MemberAccess",
                    "memberName": "transfer",
                    "expression": {"nodeType": "Identifier", "name": "dest"},
                },
                "arguments": [{"nodeType": "Identifier", "name": "amount"}],
            },
        }
        ast = _make_source([_make_function("doTransfer", [transfer_stmt])])
        results = check_unchecked_call(ast)
        self.assertEqual(results, [])

    def test_unit_empty_function_not_flagged(self):
        ast = _make_source([_make_function("empty", [])])
        results = check_unchecked_call(ast)
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
