from analyzer.reentrancy import check_reentrancy
from analyzer.dos import check_dos

class AnalyzerEngine:
    def __init__(self, ast, cfg):
        self.ast = ast
        self.cfg = cfg

    def run(self):
        results = []

        results += check_reentrancy(self.ast, self.cfg)
        results += check_dos(self.ast, self.cfg)

        return results