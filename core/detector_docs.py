"""
core/detector_docs.py — maps each detector's issue label to its README anchor.

The engine calls `annotate_docs(finding)` on every result so the output
always includes a `docs_url` pointing to the relevant README section.

Keeping the mapping here (rather than hardcoded in each analyzer) means
adding a new detector only requires one entry in this file.
"""

from __future__ import annotations

# Base URL for the README — update this to your actual GitHub repo URL.
_README_BASE = "https://github.com/OmidJalali84/Mini-Slither#"

# Maps the "issue" field value (as set by each analyzer) to the README anchor.
# GitHub auto-generates anchors from headings: lowercase, spaces→hyphens,
# punctuation stripped.  Each entry here must match the heading in README.md.
_DOCS_MAP: dict[str, str] = {
    "Reentrancy vulnerability":         "reentrancy",
    "tx.origin authentication":         "txorigin-authentication",
    "Centralized fund withdrawal":       "centralized-fund-withdrawal",
    "DOS: External call inside a for loop": "dos-via-external-call-in-loop",
    "Unchecked external call":          "unchecked-external-call",
    "Delegatecall risk":                "delegatecall-risk",
    "Self-destruct risk":               "self-destruct-risk",
    "Unbounded loop":                   "unbounded-loop",
    "Unused state variable":            "unused-state-variable",
}


def docs_url(issue: str) -> str | None:
    """Return the full README anchor URL for a given issue label, or None."""
    anchor = _DOCS_MAP.get(issue)
    if anchor is None:
        return None
    return _README_BASE + anchor


def annotate_docs(finding: dict) -> dict:
    """Add a 'docs_url' key to a finding dict in-place and return it."""
    finding["docs_url"] = docs_url(finding.get("issue", ""))
    return finding