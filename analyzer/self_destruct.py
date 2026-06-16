"""
Self-destruct risk analyzer — detects use of selfdestruct() / suicide()
in contract functions, especially when gated by a single privileged address.

Why it matters
──────────────
selfdestruct(recipient) destroys the contract and forwards its entire ETH
balance to recipient. This is:
  - Irreversible: the contract code and storage are wiped permanently.
  - Dangerous if owner-controlled: a compromised or malicious owner can
    destroy the contract, breaking integrations and stealing all funds.
  - A centralization risk: users must trust a single key forever.

Detection strategy
──────────────────
1. Find every FunctionCall where the callee identifier is "selfdestruct"
   or the deprecated alias "suicide".
2. Flag all occurrences as HIGH severity.
3. If the containing function also has an owner-auth check (same heuristic
   as centralization.py), note the added centralization risk in details.
"""

from __future__ import annotations
from typing import Any

_SELFDESTRUCT_NAMES = {"selfdestruct", "suicide"}
_OWNER_KEYWORDS = {"owner", "admin", "operator", "deployer", "governance"}


# ── helpers ───────────────────────────────────────────────────────────────────

def _find_functions(ast_node: Any, results: list | None = None) -> list:
    if results is None:
        results = []
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "FunctionDefinition":
            results.append(ast_node)
        for v in ast_node.values():
            _find_functions(v, results)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _find_functions(item, results)
    return results


def _has_owner_auth(func_node: dict) -> bool:
    """True if the function has a privilege modifier or require(msg.sender == owner)."""
    for modifier in func_node.get("modifiers", []):
        mod_name = modifier.get("modifierName", {}).get("name", "").lower()
        if any(kw in mod_name for kw in _OWNER_KEYWORDS):
            return True
    return _walk_for_auth(func_node.get("body", {}))


def _walk_for_auth(node: Any) -> bool:
    if isinstance(node, dict):
        node_type = node.get("nodeType", "")
        if node_type in ("FunctionCall", "IfStatement"):
            s = str(node)
            if "msg.sender" in s and any(kw in s for kw in _OWNER_KEYWORDS):
                return True
        for v in node.values():
            if _walk_for_auth(v):
                return True
    elif isinstance(node, list):
        for item in node:
            if _walk_for_auth(item):
                return True
    return False


def _find_selfdestruct_calls(body: Any, found: list | None = None) -> list[dict]:
    """Collect all selfdestruct/suicide FunctionCall nodes in a body."""
    if found is None:
        found = []
    if isinstance(body, dict):
        if body.get("nodeType") == "FunctionCall":
            expr = body.get("expression", {})
            if isinstance(expr, dict):
                name = expr.get("name", "")
                if name in _SELFDESTRUCT_NAMES:
                    found.append(body)
        for v in body.values():
            _find_selfdestruct_calls(v, found)
    elif isinstance(body, list):
        for item in body:
            _find_selfdestruct_calls(item, found)
    return found


def _get_function_name(func_node: dict) -> str:
    return func_node.get("name") or "<fallback/receive>"


# ── public entry point ────────────────────────────────────────────────────────

def check_selfdestruct(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Flags every function that contains a selfdestruct() or suicide() call.
    """
    results: list[dict] = []

    for func in _find_functions(ast):
        body = func.get("body")
        if not body:
            continue

        sd_calls = _find_selfdestruct_calls(body)
        if not sd_calls:
            continue

        func_name = _get_function_name(func)
        has_auth = _has_owner_auth(func)

        auth_note = (
            " The function is gated by a privileged address, so a compromised "
            "or malicious owner can trigger destruction at any time."
            if has_auth else
            " The function has no obvious access control — anyone may be able "
            "to trigger self-destruction."
        )

        results.append({
            "severity": "HIGH",
            "issue": "Self-destruct risk",
            "function": func_name,
            "details": (
                f"Function '{func_name}' calls selfdestruct(), permanently "
                f"destroying the contract and forwarding its ETH balance.{auth_note}"
            ),
            "recommendation": (
                "Avoid selfdestruct unless absolutely necessary. If required, "
                "protect it with a time-lock or multi-sig, and clearly document "
                "the risk to users."
            ),
            "src": func.get("src", "unknown"),
        })

    return results