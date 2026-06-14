"""
Integration tests for the tx.origin analyzer.

Each test loads a real .sol file from tests/tx_origin/contracts/, parses it
with solc via get_ast(), and runs scan_tx_origin() on the result.

Requirements
────────────
- solc must be installed and on PATH.

Run
───
    python -m pytest tests/tx_origin/test_tx_origin.py -v
"""

import unittest
import shutil
from pathlib import Path

from parser.ast_loader import get_ast
from analyzer.tx_origin import scan_tx_origin

CONTRACTS_DIR = Path(__file__).parent / "contracts"


def load(filename: str) -> dict:
    path = CONTRACTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {path}")
    return get_ast(str(path))


@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestTxOriginVulnerable(unittest.TestCase):

    def test_direct_require_tx_origin_detected(self):
        """TxOriginAuth.sol: require(tx.origin == owner) must produce a HIGH finding."""
        ast = load("TxOriginAuth.sol")
        results = scan_tx_origin(ast)
        self.assertGreater(len(results), 0,
            "Expected at least one finding but got none.")

    def test_direct_require_severity_is_high(self):
        ast = load("TxOriginAuth.sol")
        results = scan_tx_origin(ast)
        self.assertTrue(all(r["severity"] == "HIGH" for r in results))

    def test_direct_require_names_function(self):
        ast = load("TxOriginAuth.sol")
        results = scan_tx_origin(ast)
        functions = [r["function"] for r in results]
        self.assertIn("transferFunds", functions)

    def test_finding_has_all_keys(self):
        ast = load("TxOriginAuth.sol")
        results = scan_tx_origin(ast)
        required = {"severity", "issue", "function", "details", "recommendation"}
        for r in results:
            self.assertFalse(required - r.keys(), f"Missing keys: {required - r.keys()}")

    def test_tx_origin_in_modifier_detected(self):
        """TxOriginModifier.sol: tx.origin inside a modifier body must be flagged."""
        ast = load("TxOriginModifier.sol")
        results = scan_tx_origin(ast)
        self.assertGreater(len(results), 0,
            "Expected finding for tx.origin inside modifier.")
        modifier_findings = [r for r in results if "modifier:" in r["function"]]
        self.assertGreater(len(modifier_findings), 0,
            "Expected a finding attributed to a modifier.")


@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestTxOriginSafe(unittest.TestCase):

    def test_msg_sender_auth_not_flagged(self):
        """MsgSenderAuth.sol: msg.sender-based auth must produce zero findings."""
        ast = load("MsgSenderAuth.sol")
        results = scan_tx_origin(ast)
        self.assertEqual(results, [],
            f"Expected no findings, got: {results}")

    def test_tx_origin_non_auth_use_not_flagged(self):
        """NoContractCaller.sol: tx.origin == msg.sender guard must not be flagged."""
        ast = load("NoContractCaller.sol")
        results = scan_tx_origin(ast)
        # The require(tx.origin == msg.sender) pattern is not a privileged-owner
        # bypass — both sides are caller-controlled. Our analyzer checks for
        # comparison against a named state variable (owner/admin); this pattern
        # should produce no findings.
        # NOTE: if your policy is to flag ALL tx.origin comparisons, adjust this
        # assertion to assertEqual(len(results), 1) and update the analyzer.
        self.assertEqual(results, [],
            f"Expected no findings for non-auth tx.origin use, got: {results}")


@unittest.skipUnless(shutil.which("solc"), "solc not on PATH — install it to run integration tests")
class TestTxOriginUnit(unittest.TestCase):
    """Unit tests using hand-crafted AST fragments — no solc required."""

    def _make_require_tx_origin_ast(self):
        """Minimal AST simulating: require(tx.origin == owner)"""
        return {
            "nodeType": "SourceUnit",
            "nodes": [{
                "nodeType": "ContractDefinition",
                "nodes": [{
                    "nodeType": "FunctionDefinition",
                    "name": "privileged",
                    "body": {
                        "nodeType": "Block",
                        "statements": [{
                            "nodeType": "ExpressionStatement",
                            "expression": {
                                "nodeType": "FunctionCall",
                                "expression": {"nodeType": "Identifier", "name": "require"},
                                "arguments": [{
                                    "nodeType": "BinaryOperation",
                                    "operator": "==",
                                    "leftExpression": {
                                        "nodeType": "MemberAccess",
                                        "memberName": "origin",
                                        "expression": {"nodeType": "Identifier", "name": "tx"},
                                    },
                                    "rightExpression": {"nodeType": "Identifier", "name": "owner"},
                                }],
                            },
                        }],
                    },
                }],
            }],
        }

    def test_unit_require_tx_origin(self):
        ast = self._make_require_tx_origin_ast()
        results = scan_tx_origin(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[0]["function"], "privileged")

    def test_unit_no_tx_origin(self):
        ast = {
            "nodeType": "SourceUnit",
            "nodes": [{
                "nodeType": "ContractDefinition",
                "nodes": [{
                    "nodeType": "FunctionDefinition",
                    "name": "safe",
                    "body": {
                        "nodeType": "Block",
                        "statements": [{
                            "nodeType": "ExpressionStatement",
                            "expression": {
                                "nodeType": "FunctionCall",
                                "expression": {"nodeType": "Identifier", "name": "require"},
                                "arguments": [{
                                    "nodeType": "BinaryOperation",
                                    "operator": "==",
                                    "leftExpression": {"nodeType": "Identifier", "name": "msg.sender"},
                                    "rightExpression": {"nodeType": "Identifier", "name": "owner"},
                                }],
                            },
                        }],
                    },
                }],
            }],
        }
        results = scan_tx_origin(ast)
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)