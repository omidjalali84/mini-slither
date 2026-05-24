from analyzer.reentrancy import check_reentrancy
from analyzer.tx_origin import scan_tx_origin

class AnalyzerEngine:
    def __init__(self, ast, cfg):
        self.ast = ast
        self.cfg = cfg

    def run(self):
        results = []

        results += check_reentrancy(self.ast, self.cfg)
        results += scan_tx_origin(self.ast)

        return results

