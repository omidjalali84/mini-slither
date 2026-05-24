
from parser.ast_loader import get_ast
from parser.cfg_loader import get_cfg
from core.engine import AnalyzerEngine
import json

file_path = "tests/vulnerbale_contracts/Contract1.sol"

ast = get_ast(file_path)
cfg = get_cfg(file_path)

engine = AnalyzerEngine(ast, cfg)

results = engine.run()

print(json.dumps(results, indent=2))