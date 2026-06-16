from analyzer.reentrancy        import check_reentrancy
from analyzer.tx_origin         import scan_tx_origin
from analyzer.centralization    import check_centralization_withdrawal
from analyzer.dos               import check_dos
from analyzer.unchecked_call    import check_unchecked_call
from analyzer.delegatecall      import check_delegatecall
from analyzer.self_destruct     import check_selfdestruct
from analyzer.unbounded_loop    import check_unbounded_loop
from analyzer.unused_state_var  import check_unused_state_var
from core.src_mapper            import SrcMapper
from core.detector_docs         import annotate_docs


class AnalyzerEngine:
    def __init__(self, ast, cfg, file_path: str = "", sources: dict | None = None):
        self.ast      = ast
        self.cfg      = cfg
        self._mapper  = SrcMapper(file_path, sources) if file_path else None

    def run(self) -> list[dict]:
        results: list[dict] = []

        results += check_reentrancy(self.ast, self.cfg)
        results += scan_tx_origin(self.ast)
        results += check_centralization_withdrawal(self.ast, self.cfg)
        results += check_dos(self.ast, self.cfg)
        results += check_unchecked_call(self.ast, self.cfg)
        results += check_delegatecall(self.ast, self.cfg)
        results += check_selfdestruct(self.ast, self.cfg)
        results += check_unbounded_loop(self.ast, self.cfg)
        results += check_unused_state_var(self.ast, self.cfg)

        # Enrich every finding with docs link + source location
        for finding in results:
            annotate_docs(finding)
            if self._mapper:
                self._mapper.enrich(finding)

        return results