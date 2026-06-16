"""
main.py — Mini-Slither entry point.

Usage
─────
    python main.py [path/to/Contract.sol]
"""

from __future__ import annotations

import sys
from pathlib import Path

from parser.ast_loader import get_ast
from parser.cfg_loader import get_cfg
from core.engine       import AnalyzerEngine

FILE_PATH = "tests/vulnerbale_contracts/Contract1.sol"

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

_ANSI = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[94m",
    "INFO":   "\033[96m",
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "GREEN":  "\033[92m",
    "CYAN":   "\033[96m",
}

_USE_COLOUR = sys.stdout.isatty()


def _c(key: str, text: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"{_ANSI.get(key, '')}{text}{_ANSI['RESET']}"


def _severity_badge(sev: str) -> str:
    icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}
    icon = icons.get(sev, "❓")
    return f"{icon}  {_c(sev, _c('BOLD', sev))}"


def _wrap(text: str, width: int = 72, indent: str = "  ") -> str:
    words, lines, buf = text.split(), [], []
    for w in words:
        if sum(len(x) + 1 for x in buf) + len(w) > width:
            lines.append(indent + " ".join(buf))
            buf = [w]
        else:
            buf.append(w)
    if buf:
        lines.append(indent + " ".join(buf))
    return "\n".join(lines)


def _print_finding(idx: int, f: dict) -> None:
    sev     = f.get("severity", "?")
    func    = f.get("function", "")
    var     = f.get("variable", "")
    subject = func or var or "—"

    print(f"\n{'─' * 70}")
    print(f"  [{idx}] {_severity_badge(sev)}  │  {_c('BOLD', f.get('issue', ''))}")
    print(f"{'─' * 70}")

    label = "Variable" if var else "Function"
    if subject != "—":
        print(f"  {label:10}: {subject}")

    # ── location ──────────────────────────────────────────────────────────────
    file_str = f.get("file")
    line     = f.get("line")
    col      = f.get("col")
    vscode   = f.get("vscode_url")
    file_url = f.get("file_url")

    if file_str and line:
        print(f"  {'Location':10}: {_c('DIM', file_str)}:{_c('BOLD', str(line))}:{col}")
    if vscode:
        print(f"  {'VS Code':10}: {_c('GREEN', vscode)}")
    if file_url:
        print(f"  {'File URL':10}: {_c('DIM', file_url)}")

    # ── docs link ─────────────────────────────────────────────────────────────
    docs = f.get("docs_url")
    if docs:
        print(f"  {'Docs':10}: {_c('CYAN', docs)}")

    # ── details / recommendation ──────────────────────────────────────────────
    print()
    if f.get("details"):
        print(_wrap(f["details"]))
    if f.get("recommendation"):
        print()
        print(_wrap("💡 " + f["recommendation"], indent="  "))


def _print_summary(results: list[dict], file_path: str) -> None:
    counts: dict[str, int] = {}
    for r in results:
        sev = r.get("severity", "?")
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n{'═' * 70}")
    print(f"  Mini-Slither  │  {Path(file_path).name}")
    print(f"{'═' * 70}")
    if not results:
        print(f"  {_c('GREEN', '✅  No issues found.')}")
    else:
        parts = "  " + "  ".join(
            f"{_c(sev, sev)}: {cnt}"
            for sev, cnt in sorted(counts.items(),
                                   key=lambda x: _SEVERITY_ORDER.get(x[0], 9))
        )
        print(f"  Found {_c('BOLD', str(len(results)))} issue(s).")
        print(parts)
    print(f"{'═' * 70}")


def main() -> None:
    file_path = sys.argv[1] if len(sys.argv) > 1 else FILE_PATH
    print(f"\n🔍 Analysing  {file_path} …")

    ast = get_ast(file_path)
    cfg = get_cfg(file_path)

    engine  = AnalyzerEngine(ast, cfg, file_path=file_path)
    results = engine.run()

    results.sort(key=lambda r: (
        _SEVERITY_ORDER.get(r.get("severity", "?"), 9),
        r.get("line") or 9999,
    ))

    _print_summary(results, file_path)

    for i, finding in enumerate(results, 1):
        _print_finding(i, finding)

    print()


if __name__ == "__main__":
    main()