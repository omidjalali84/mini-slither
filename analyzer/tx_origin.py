"""
tx_origin analyzer — detects authentication based on tx.origin instead of msg.sender.

Using tx.origin for auth is dangerous because:
  - tx.origin is always the EOA that initiated the outermost transaction.
  - A malicious contract in the call chain can exploit this: if the victim
    calls the attacker contract, and the attacker contract calls back into
    the victim, tx.origin still equals the victim's address — bypassing
    any tx.origin check.

This analyzer flags:
  1. require(tx.origin == <state_var>) / require(<state_var> == tx.origin)
  2. if (tx.origin == <state_var>) used as an auth guard
  3. Direct modifier bodies containing the above patterns

NOT flagged:
  - require(tx.origin == msg.sender)  — EOA-only guard, different smell,
    not the phishing vulnerability.
"""

from __future__ import annotations
from typing import Any


# ── helpers ───────────────────────────────────────────────────────────────────

def _uses_tx_origin(node: Any) -> bool:
    """
    Return True if the node string representation likely contains a tx.origin
    reference — cheap broad sweep before deeper checks.

    The AST stores tx.origin as two separate fields:
      {"nodeType": "MemberAccess", "memberName": "origin",
       "expression": {"nodeType": "Identifier", "name": "tx"}}
    so str(node) never contains the literal "tx.origin".
    Checking for "'memberName': 'origin'" is a reliable fast filter.
    """
    if not isinstance(node, (dict, list)):
        return False
    s = str(node)
    return "'memberName': 'origin'" in s or '"memberName": "origin"' in s


def _is_tx_origin_member(node: dict) -> bool:
    """True when node is the MemberAccess expression `tx.origin`."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") != "MemberAccess":
        return False
    if node.get("memberName") != "origin":
        return False
    inner = node.get("expression", {})
    return isinstance(inner, dict) and inner.get("name") == "tx"


def _is_msg_sender(node: dict) -> bool:
    """True when node is the MemberAccess expression `msg.sender`."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") != "MemberAccess":
        return False
    if node.get("memberName") != "sender":
        return False
    inner = node.get("expression", {})
    return isinstance(inner, dict) and inner.get("name") == "msg"


def _comparison_uses_tx_origin(node: dict) -> bool:
    """
    Return True when node is a BinaryOperation with operator == or !=
    where one side is tx.origin AND the other side is NOT msg.sender.

    The pattern  tx.origin == msg.sender  is an EOA-only guard (blocks
    smart contract callers) — a debatable design choice but NOT the
    phishing vulnerability where a privileged state variable is compared.
    We intentionally skip it to avoid false positives.
    """
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") != "BinaryOperation":
        return False
    if node.get("operator") not in ("==", "!="):
        return False

    left = node.get("leftExpression", {})
    right = node.get("rightExpression", {})

    if _is_tx_origin_member(left):
        return not _is_msg_sender(right)   # skip tx.origin == msg.sender
    if _is_tx_origin_member(right):
        return not _is_msg_sender(left)    # skip msg.sender == tx.origin

    return False


def _walk_for_tx_origin_auth(node: Any) -> bool:
    """
    Recursively check whether any require() / if-guard in this subtree
    uses tx.origin for comparison against a privileged address.
    """
    if not isinstance(node, dict):
        if isinstance(node, list):
            return any(_walk_for_tx_origin_auth(i) for i in node)
        return False

    node_type = node.get("nodeType", "")

    # require(tx.origin == owner) or require(owner == tx.origin)
    if node_type == "FunctionCall":
        expr = node.get("expression", {})
        if isinstance(expr, dict) and expr.get("name") == "require":
            args = node.get("arguments", [])
            for arg in args:
                if _comparison_uses_tx_origin(arg):
                    return True

    # if (tx.origin == owner) { ... }
    if node_type == "IfStatement":
        condition = node.get("condition", {})
        if _comparison_uses_tx_origin(condition):
            return True

    for v in node.values():
        if _walk_for_tx_origin_auth(v):
            return True

    return False


def _get_function_name(func_node: dict) -> str:
    return func_node.get("name") or "<fallback/receive>"


def _find_all_functions(ast_node: Any, results: list | None = None) -> list:
    if results is None:
        results = []
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "FunctionDefinition":
            results.append(ast_node)
        for v in ast_node.values():
            _find_all_functions(v, results)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _find_all_functions(item, results)
    return results


def _find_all_modifiers(ast_node: Any, results: list | None = None) -> list:
    if results is None:
        results = []
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "ModifierDefinition":
            results.append(ast_node)
        for v in ast_node.values():
            _find_all_modifiers(v, results)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _find_all_modifiers(item, results)
    return results


# ── public entry point ────────────────────────────────────────────────────────

def scan_tx_origin(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Scans all function bodies and modifier definitions for tx.origin-based
    authentication patterns where tx.origin is compared against a privileged
    address (owner, admin, etc.) rather than msg.sender.
    """
    results: list[dict] = []

    # Check function bodies directly
    for func in _find_all_functions(ast):
        body = func.get("body")
        if not body:
            continue
        # Fast pre-check: skip if tx.origin not mentioned at all
        if not _uses_tx_origin(body):
            continue
        if _walk_for_tx_origin_auth(body):
            func_name = _get_function_name(func)
            results.append({
                "severity": "HIGH",
                "issue": "tx.origin authentication",
                "function": func_name,
                "details": (
                    f"Function '{func_name}' uses tx.origin for authentication. "
                    "A malicious intermediary contract can trick the original "
                    "sender into calling it, then forward the call to this "
                    "function — tx.origin still resolves to the victim, "
                    "bypassing the check."
                ),
                "recommendation": (
                    "Replace tx.origin with msg.sender for all authentication "
                    "and authorization checks."
                ),
                "src": func.get("src", "unknown"),
            })

    # Check modifier definitions (e.g. modifier onlyOwner { require(tx.origin...) })
    for modifier in _find_all_modifiers(ast):
        body = modifier.get("body")
        if not body:
            continue
        if not _uses_tx_origin(body):
            continue
        if _walk_for_tx_origin_auth(body):
            mod_name = modifier.get("name", "<unknown modifier>")
            results.append({
                "severity": "HIGH",
                "issue": "tx.origin authentication",
                "function": f"modifier:{mod_name}",
                "details": (
                    f"Modifier '{mod_name}' uses tx.origin for authentication. "
                    "Any function using this modifier inherits the vulnerability."
                ),
                "recommendation": (
                    "Replace tx.origin with msg.sender inside the modifier."
                ),
                "src": modifier.get("src", "unknown"),
            })

    return results