"""
main.py — Mini-Slither entry point.

Usage
─────
    python main.py [path/to/Contract.sol]

If no argument is given, falls back to the hardcoded FILE_PATH below.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from parser.ast_loader import get_ast
from parser.cfg_loader import get_cfg
from core.engine       import AnalyzerEngine

# ── config ────────────────────────────────────────────────────────────────────

FILE_PATH = "tests/centralization/contracts/CentralizedVault.sol"

# Severity display order and colours (ANSI)
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

_ANSI = {
    "HIGH":   "\033[91m",   # bright red
    "MEDIUM": "\033[93m",   # bright yellow
    "LOW":    "\033[94m",   # bright blue
    "INFO":   "\033[96m",   # bright cyan
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "GREEN":  "\033[92m",
}

_USE_COLOUR = sys.stdout.isatty()


def _c(key: str, text: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"{_ANSI.get(key, '')}{text}{_ANSI['RESET']}"


# ── reporter ──────────────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}
    icon = icons.get(sev, "❓")
    return f"{icon}  {_c(sev, _c('BOLD', sev))}"


def _print_finding(idx: int, f: dict) -> None:
    sev  = f.get("severity", "?")
    func = f.get("function", "")
    var  = f.get("variable", "")
    subject = func or var or "—"

    print(f"\n{'─' * 70}")
    print(f"  [{idx}] {_severity_badge(sev)}  │  {_c('BOLD', f.get('issue', ''))}")
    print(f"{'─' * 70}")

    if subject != "—":
        label = "Variable" if var else "Function"
        print(f"  {label:10}: {subject}")

    # ── location block ────────────────────────────────────────────────────────
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

    # ── details / recommendation ──────────────────────────────────────────────
    print()
    details = f.get("details", "")
    if details:
        # Word-wrap at 78 chars
        words, line_buf = details.split(), []
        for w in words:
            if sum(len(x) + 1 for x in line_buf) + len(w) > 72:
                print("  " + " ".join(line_buf))
                line_buf = [w]
            else:
                line_buf.append(w)
        if line_buf:
            print("  " + " ".join(line_buf))

    rec = f.get("recommendation", "")
    if rec:
        print()
        print(f"  {_c('DIM', '💡 ' + rec)}")


def _print_summary(results: list[dict], file_path: str) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("severity", "?")] = counts.get(r.get("severity", "?"), 0) + 1

    print(f"\n{'═' * 70}")
    print(f"  Mini-Slither  │  {Path(file_path).name}")
    print(f"{'═' * 70}")
    if not results:
        print(f"  {_c('GREEN', '✅  No issues found.')}")
    else:
        total = len(results)
        parts = "  " + "  ".join(
            f"{_c(sev, sev)}: {cnt}"
            for sev, cnt in sorted(counts.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 9))
        )
        print(f"  Found {_c('BOLD', str(total))} issue(s).")
        print(parts)
    print(f"{'═' * 70}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    file_path = sys.argv[1] if len(sys.argv) > 1 else FILE_PATH

    print(f"\n🔍 Analysing  {file_path} …")

    ast = get_ast(file_path)
    cfg = get_cfg(file_path)

    engine  = AnalyzerEngine(ast, cfg, file_path=file_path)
    results = engine.run()

    # Sort by severity then by line number
    results.sort(key=lambda r: (
        _SEVERITY_ORDER.get(r.get("severity", "?"), 9),
        r.get("line") or 9999,
    ))

    _print_summary(results, file_path)

    for i, finding in enumerate(results, 1):
        _print_finding(i, finding)

    # Also dump raw JSON for piping / CI
    json_path = Path(file_path).stem + "_findings.json"

    # Remove non-serialisable SourceLocation object before dumping
    serialisable = []
    for r in results:
        row = {k: v for k, v in r.items() if k != "location"}
        serialisable.append(row)

    Path(json_path).write_text(json.dumps(serialisable, indent=2))
    print(f"\n📁 JSON report saved → {json_path}\n")


if __name__ == "__main__":
    main()