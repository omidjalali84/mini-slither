import sys
import types
import unittest

from analyzer.dos import check_dos


# ---------------------------------------------------------------------------
# AST builders — mirror the structure of the .sol files in contracts/
# ---------------------------------------------------------------------------

def make_contract(function_bodies):
    return {
        "nodeType": "SourceUnit",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "nodes": [
                    {
                        "nodeType": "FunctionDefinition",
                        "body": {"nodeType": "Block", "statements": stmts},
                    }
                    for stmts in function_bodies
                ],
            }
        ],
    }


def for_loop(body_statements):
    return {
        "nodeType": "ForStatement",
        "initializationExpression": {},
        "condition": {},
        "loopExpression": {},
        "body": {"nodeType": "Block", "statements": body_statements},
    }


def external_call(method="call"):
    return {
        "nodeType": "FunctionCall",
        "expression": {"nodeType": "MemberAccess", "memberName": method},
    }


def assignment(var):
    return {
        "nodeType": "Assignment",
        "leftHandSide": {"name": var},
        "rightHandSide": {"nodeType": "Literal", "value": "0"},
    }


def require_call():
    return {
        "nodeType": "FunctionCall",
        "expression": {"nodeType": "Identifier", "name": "require"},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDos(unittest.TestCase):

    def test_distribute_all(self):
        # contracts/DistributeAll.sol — transfer() inside a loop
        ast = make_contract([[for_loop([external_call("transfer")])]])
        results = check_dos(ast)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")

    def test_notify_and_pay(self):
        # contracts/NotifyAndPay.sol — call() + transfer() in one iteration
        ast = make_contract([[for_loop([external_call("call"), external_call("transfer")])]])
        results = check_dos(ast)
        self.assertEqual(results[0]["call_count"], 2)

    def test_airdrop_and_refund(self):
        # contracts/AirdropAndRefund.sol — two functions each with a risky loop
        ast = make_contract([
            [for_loop([external_call("call")])],
            [for_loop([external_call("transfer")])],
        ])
        self.assertEqual(len(check_dos(ast)), 2)

    def test_nested_payout(self):
        # contracts/NestedPayout.sol — transfer() inside an inner loop
        inner = for_loop([external_call("transfer")])
        outer = for_loop([inner])
        ast = make_contract([[outer]])
        self.assertGreaterEqual(len(check_dos(ast)), 1)

    def test_pull_payment(self):
        # contracts/PullPayment.sol — loop with state changes only, no external calls
        ast = make_contract([[for_loop([assignment("balances")])]])
        self.assertEqual(check_dos(ast), [])

    def test_single_withdraw(self):
        # contracts/SingleWithdraw.sol — external call outside any loop
        ast = make_contract([[external_call("transfer"), assignment("balance")]])
        self.assertEqual(check_dos(ast), [])

    def test_validate_all(self):
        # contracts/ValidateAll.sol — loop with require() only
        ast = make_contract([[for_loop([require_call()])]])
        self.assertEqual(check_dos(ast), [])


def import_engine():
    for mod_name, fn_name in [
        ("analyzer.reentrancy", "check_reentrancy"),
        ("analyzer.tx_origin",  "scan_tx_origin"),
    ]:
        if mod_name not in sys.modules:
            mod = types.ModuleType(mod_name)
            setattr(mod, fn_name, lambda *a, **kw: [])
            sys.modules[mod_name] = mod
    sys.modules.pop("core.engine", None)
    from core.engine import AnalyzerEngine
    return AnalyzerEngine


class TestEngineIntegration(unittest.TestCase):

    def test_vulnerable_contract_produces_dos_finding(self):
        AnalyzerEngine = import_engine()
        ast = make_contract([[for_loop([external_call("transfer")])]])
        results = AnalyzerEngine(ast, cfg={}).run()
        self.assertTrue(any("DOS" in r.get("issue", "") for r in results))

    def test_safe_contract_produces_no_dos_finding(self):
        AnalyzerEngine = import_engine()
        ast = make_contract([[for_loop([assignment("balances")])]])
        results = AnalyzerEngine(ast, cfg={}).run()
        self.assertFalse(any("DOS" in r.get("issue", "") for r in results))


if __name__ == "__main__":
    unittest.main()
