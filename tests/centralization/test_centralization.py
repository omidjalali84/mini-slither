import pytest
from parser.ast_loader import get_ast
from analyzer.centralization import check_centralization_withdrawal

CONTRACTS_DIR = "tests/centralization/contracts"


class TestVulnerableContracts:

    def test_drain_with_only_owner_modifier_and_transfer(self):
        ast = get_ast(f"{CONTRACTS_DIR}/CentralizedVault.sol")
        results = check_centralization_withdrawal(ast)
        assert len(results) >= 1
        assert any(r["severity"] == "HIGH" for r in results)
        assert any(r["function"] == "drain" for r in results)

    def test_emergency_withdraw_with_require_admin_and_call(self):
        ast = get_ast(f"{CONTRACTS_DIR}/AdminWithdrawable.sol")
        results = check_centralization_withdrawal(ast)
        assert len(results) >= 1
        assert any(r["severity"] == "HIGH" for r in results)
        assert any(r["function"] == "emergencyWithdraw" for r in results)


class TestSafeContracts:

    def test_user_withdraw_own_balance_not_flagged(self):
        ast = get_ast(f"{CONTRACTS_DIR}/SafeUserWithdraw.sol")
        results = check_centralization_withdrawal(ast)
        assert len(results) == 0

    def test_onlyowner_no_fund_movement_not_flagged(self):
        ast = get_ast(f"{CONTRACTS_DIR}/NoFunds.sol")
        results = check_centralization_withdrawal(ast)
        assert len(results) == 0
