"""
src_mapper.py — resolve solc "src" fields to human-readable file locations.

solc compact-JSON AST encodes every node's position as:
    "<charOffset>:<length>:<fileIndex>"

e.g.  "42:18:0"  means: starts at byte 42, is 18 bytes long, in file index 0.

This module:
  1. Builds a char-offset → (line, col) lookup table from source files.
  2. Resolves a src string into a SourceLocation(file, line, col, url).
  3. Generates clickable deep-link URLs:
       - VS Code:   vscode://file/<abs_path>:<line>:<col>
       - File URI:  file://<abs_path>#L<line>    (fallback, opens in browser)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional


@dataclass
class SourceLocation:
    file: str           # absolute path to the .sol file
    line: int           # 1-based line number
    col: int            # 1-based column number
    offset: int         # raw char offset
    length: int         # raw length
    vscode_url: str     # vscode://file/...
    file_url: str       # file://... (browser fallback)

    def __str__(self) -> str:
        rel = _rel(self.file)
        return f"{rel}:{self.line}:{self.col}"

    def format_block(self, indent: str = "  ") -> str:
        rel = _rel(self.file)
        lines = [
            f"{indent}📄 File   : {rel}",
            f"{indent}📍 Line   : {self.line}",
            f"{indent}🔢 Column : {self.col}",
            f"{indent}🔗 VS Code: {self.vscode_url}",
            f"{indent}🌐 File   : {self.file_url}",
        ]
        return "\n".join(lines)


def _rel(path: str) -> str:
    """Return path relative to cwd if possible, else absolute."""
    try:
        return str(Path(path).relative_to(Path.cwd()))
    except ValueError:
        return path


# ── offset → (line, col) table ────────────────────────────────────────────────

@lru_cache(maxsize=64)
def _build_offset_table(file_path: str) -> list[int]:
    """
    Return a list where index i holds the char offset of the START of line i+1.
    Built once per file and cached.
    """
    try:
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [0]

    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _offset_to_line_col(file_path: str, offset: int) -> tuple[int, int]:
    """Convert a char offset to (line, col), both 1-based."""
    table = _build_offset_table(file_path)
    # Binary search for the largest line-start ≤ offset
    lo, hi = 0, len(table) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if table[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    line = lo + 1                    # 1-based
    col  = offset - table[lo] + 1   # 1-based
    return line, col


# ── file-index registry ───────────────────────────────────────────────────────

class SrcMapper:
    """
    Resolves solc src strings to SourceLocation objects.

    Usage
    ─────
    mapper = SrcMapper(file_path)          # single-file analysis
    mapper = SrcMapper(file_path, sources) # multi-file (sources = {idx: path})

    loc = mapper.resolve("42:18:0")
    print(loc)                             # tests/contracts/Foo.sol:5:3
    print(loc.format_block())              # full block with URLs
    """

    def __init__(
        self,
        primary_file: str,
        sources: Optional[dict[int, str]] = None,
    ) -> None:
        self.primary_file = os.path.abspath(primary_file)
        # sources maps fileIndex → absolute path
        self._sources: dict[int, str] = {}
        if sources:
            self._sources = {k: os.path.abspath(v) for k, v in sources.items()}
        # index 0 is always the primary file
        self._sources.setdefault(0, self.primary_file)

    def _file_for_index(self, idx: int) -> str:
        return self._sources.get(idx, self.primary_file)

    def resolve(self, src: str) -> Optional[SourceLocation]:
        """
        Parse a solc src string "offset:length:fileIndex" and return a
        SourceLocation.  Returns None if src is missing or malformed.
        """
        if not src or src == "unknown":
            return None
        parts = src.split(":")
        if len(parts) < 2:
            return None
        try:
            offset = int(parts[0])
            length = int(parts[1])
            file_idx = int(parts[2]) if len(parts) >= 3 else 0
        except ValueError:
            return None

        file_path = self._file_for_index(file_idx)
        abs_path  = os.path.abspath(file_path)
        line, col = _offset_to_line_col(abs_path, offset)

        vscode_url = f"vscode://file/{abs_path}:{line}:{col}"
        file_url   = f"file://{abs_path}#L{line}"

        return SourceLocation(
            file=abs_path,
            line=line,
            col=col,
            offset=offset,
            length=length,
            vscode_url=vscode_url,
            file_url=file_url,
        )

    def enrich(self, finding: dict) -> dict:
        """
        Add location fields to a finding dict in-place and return it.

        New keys added:
          "location"   → SourceLocation object (or None)
          "file"       → relative path string   (or None)
          "line"       → int                    (or None)
          "col"        → int                    (or None)
          "vscode_url" → clickable URL string   (or None)
          "file_url"   → file:// URL string     (or None)
        """
        src = finding.get("src", "unknown")
        loc = self.resolve(src)
        finding["location"] = loc
        if loc:
            finding["file"]       = _rel(loc.file)
            finding["line"]       = loc.line
            finding["col"]        = loc.col
            finding["vscode_url"] = loc.vscode_url
            finding["file_url"]   = loc.file_url
        else:
            finding["file"] = finding["col"] = finding["line"] = None
            finding["vscode_url"] = finding["file_url"] = None
        return finding