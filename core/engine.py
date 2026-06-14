from analyzer.reentrancy import check_reentrancy
from analyzer.tx_origin import scan_tx_origin
from analyzer.centralization import check_centralization_withdrawal
from analyzer.dos import check_dos
from analyzer.unchecked_call import check_unchecked_call


class AnalyzerEngine:
    def __init__(self, ast, cfg):
        self.ast = ast
        self.cfg = cfg

    def run(self):
        results = []

        results += check_reentrancy(self.ast, self.cfg)
        results += scan_tx_origin(self.ast)
        results += check_centralization_withdrawal(self.ast, self.cfg)
        results += check_dos(self.ast, self.cfg)
        results += check_unchecked_call(self.ast, self.cfg)

        return results
