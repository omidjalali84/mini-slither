"""
Unused state variable analyzer — detects state variables declared at the
contract level that are never read or written in any function body.

Dead storage variables bloat contract bytecode and deployment gas costs,
and often indicate leftover code from refactoring.

Detection strategy
──────────────────
1. Collect all StateVariableDeclaration names from the contract.
2. Walk every FunctionDefinition body for Identifier nodes whose name
   matches a state variable.
3. Any state variable with zero references is flagged as INFO severity.

Excluded:
  - Variables referenced in their own initialValue expression.
  - Public variables (their auto-generated getter counts as usage).
"""

from __future__ import annotations
from typing import Any


# ── state variable collection ─────────────────────────────────────────────────

def _collect_state_vars(ast_node: Any, results: list | None = None) -> list[dict]:
    """Return list of {name, visibility, src} for all StateVariableDeclaration nodes."""
    if results is None:
        results = []
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "StateVariableDeclaration":
            for decl in ast_node.get("variables", []):
                results.append({
                    "name": decl.get("name", ""),
                    "visibility": decl.get("visibility", "internal"),
                    "src": decl.get("src", "unknown"),
                })
        for v in ast_node.values():
            _collect_state_vars(v, results)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _collect_state_vars(item, results)
    return results


# ── reference collection ──────────────────────────────────────────────────────

def _collect_identifiers(ast_node: Any, names_out: set) -> None:
    """Walk AST and collect all Identifier names found in function bodies."""
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "Identifier":
            name = ast_node.get("name")
            if name:
                names_out.add(name)
        for v in ast_node.values():
            _collect_identifiers(v, names_out)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _collect_identifiers(item, names_out)


def _collect_referenced_names(ast_node: Any) -> set[str]:
    """
    Collect every Identifier name that appears inside a FunctionDefinition body
    or a modifier body — i.e. actual usage sites, not declarations.
    """
    referenced: set[str] = set()

    if isinstance(ast_node, dict):
        node_type = ast_node.get("nodeType", "")
        if node_type in ("FunctionDefinition", "ModifierDefinition"):
            body = ast_node.get("body")
            if body:
                _collect_identifiers(body, referenced)
        else:
            for v in ast_node.values():
                referenced |= _collect_referenced_names(v)

    elif isinstance(ast_node, list):
        for item in ast_node:
            referenced |= _collect_referenced_names(item)

    return referenced


# ── public entry point ────────────────────────────────────────────────────────

def check_unused_state_var(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Finds state variables that are declared but never referenced in any
    function or modifier body.
    """
    state_vars = _collect_state_vars(ast)
    referenced = _collect_referenced_names(ast)

    results: list[dict] = []
    for var in state_vars:
        name = var["name"]
        visibility = var["visibility"]

        # Public vars expose an auto-generated getter — skip them.
        if visibility == "public":
            continue

        if name and name not in referenced:
            results.append({
                "severity": "INFO",
                "issue": "Unused state variable",
                "variable": name,
                "details": (
                    f"State variable '{name}' is declared but never referenced "
                    "in any function or modifier. It wastes storage and gas."
                ),
                "recommendation": (
                    f"Remove '{name}' if it is no longer needed, or make it "
                    "public if you intend to expose it via a getter."
                ),
                "src": var["src"],
            })

    return results