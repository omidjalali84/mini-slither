"""
Unbounded loop analyzer — detects for/while loops whose iteration count
depends on a storage array or mapping that can grow without an upper bound.

Why it matters
──────────────
If a loop iterates over a dynamically-sized storage array (e.g. `recipients`)
and that array grows unboundedly, the loop will eventually exceed the block
gas limit, making the function permanently un-callable (DOS by gas exhaustion).

Detection strategy
──────────────────
A loop is flagged when its condition (or init/update expression) references
an Identifier whose name ends with common array-length suffixes or whose
name matches a known dynamic-array variable.

Heuristic used
──────────────
We look for ForStatement / WhileStatement nodes where the condition
string contains ".length" — the overwhelmingly common pattern:

    for (uint i = 0; i < recipients.length; i++) { ... }
    while (i < users.length) { ... }

This catches the real-world pattern without requiring type information.
"""

from __future__ import annotations
from typing import Any


def _node_str(node: Any) -> str:
    return str(node) if node else ""


def _condition_is_unbounded(condition: Any) -> tuple[bool, str]:
    """
    Return (True, hint) if the loop condition references a .length access
    on a storage-like variable.
    """
    s = _node_str(condition)
    if "'memberName': 'length'" in s or '"memberName": "length"' in s:
        # Try to extract the variable name from the AST dict
        var_name = _extract_length_base(condition)
        return True, var_name
    return False, ""


def _extract_length_base(node: Any) -> str:
    """Walk the condition AST and find the base of a .length MemberAccess."""
    if isinstance(node, dict):
        if (node.get("nodeType") == "MemberAccess"
                and node.get("memberName") == "length"):
            base = node.get("expression", {})
            if isinstance(base, dict):
                return base.get("name", "<array>")
        for v in node.values():
            result = _extract_length_base(v)
            if result:
                return result
    elif isinstance(node, list):
        for item in node:
            result = _extract_length_base(item)
            if result:
                return result
    return ""


def _find_unbounded_loops(ast_node: Any, findings: list | None = None) -> list[dict]:
    if findings is None:
        findings = []

    if isinstance(ast_node, dict):
        node_type = ast_node.get("nodeType", "")

        if node_type == "ForStatement":
            condition = ast_node.get("condition")
            is_unbounded, var_name = _condition_is_unbounded(condition)
            if is_unbounded:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Unbounded loop",
                    "details": (
                        f"For-loop iterates over '{var_name}.length' which can grow "
                        "without bound. If the array grows large enough, the loop "
                        "will exceed the block gas limit and permanently revert "
                        "(gas-exhaustion DOS)."
                    ),
                    "recommendation": (
                        "Cap the loop with a maximum iteration count, use "
                        "pagination, or switch to a pull-payment / off-chain "
                        "enumeration pattern."
                    ),
                    "src": ast_node.get("src", "unknown"),
                })

        elif node_type == "WhileStatement":
            condition = ast_node.get("condition")
            is_unbounded, var_name = _condition_is_unbounded(condition)
            if is_unbounded:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Unbounded loop",
                    "details": (
                        f"While-loop condition references '{var_name}.length' which "
                        "can grow without bound, risking gas-exhaustion DOS."
                    ),
                    "recommendation": (
                        "Introduce a maximum iteration limit or use a paginated "
                        "approach."
                    ),
                    "src": ast_node.get("src", "unknown"),
                })

        # Keep walking — catch nested loops and multiple functions
        for v in ast_node.values():
            _find_unbounded_loops(v, findings)

    elif isinstance(ast_node, list):
        for item in ast_node:
            _find_unbounded_loops(item, findings)

    return findings


# ── public entry point ────────────────────────────────────────────────────────

def check_unbounded_loop(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Scans all loop statements for conditions that reference a dynamic
    .length accessor, indicating the loop bound is not capped.
    """
    return _find_unbounded_loops(ast)