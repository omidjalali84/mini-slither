"""
Reentrancy analyzer — detects state changes that occur AFTER a low-level
ETH-transfer call (.call / .transfer / .send) within the same function.

Root cause of the previous miss
─────────────────────────────────
solc encodes  msg.sender.call{value: x}("")  as:

    FunctionCall
    └─ expression: FunctionCallOptions          ← extra wrapper node
       ├─ expression: MemberAccess memberName="call"
       └─ options: [...]

The previous version only looked one level deep
(FunctionCall → MemberAccess), so it never matched the real AST.
The fix: unwrap FunctionCallOptions before checking memberName.
"""

from __future__ import annotations
from typing import Any

_ETH_TRANSFER_NAMES = {"call", "transfer", "send"}


# ── call detection ────────────────────────────────────────────────────────────

def _resolve_callee(expr: Any) -> dict:
    """
    Walk through optional FunctionCallOptions wrappers and return the
    innermost expression of a FunctionCall.

    FunctionCall
    └─ expression  (may be FunctionCallOptions)
       └─ expression  (the actual MemberAccess)
    """
    if not isinstance(expr, dict):
        return {}
    # Peel off as many FunctionCallOptions layers as exist
    while expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression", {})
    return expr


def _is_eth_transfer_call(node: dict) -> bool:
    """
    True when node is a FunctionCall whose effective callee is a
    MemberAccess with memberName in {call, transfer, send}.

    Handles both plain  addr.transfer(x)
    and option-bearing  addr.call{value: x}("")  (FunctionCallOptions).
    """
    if node.get("nodeType") != "FunctionCall":
        return False
    callee = _resolve_callee(node.get("expression", {}))
    if callee.get("nodeType") != "MemberAccess":
        return False
    return callee.get("memberName") in _ETH_TRANSFER_NAMES


# ── state-change detection ────────────────────────────────────────────────────

def _lhs_is_state_var(lhs: Any) -> bool:
    """
    Return True when the assignment LHS refers to a storage (state) variable.
    Skips local memory/calldata variables and msg/tx/block members.
    """
    if not isinstance(lhs, dict):
        return False
    nt = lhs.get("nodeType")

    if nt == "Identifier":
        # Local vars always carry an explicit storageLocation
        if lhs.get("storageLocation") in ("memory", "calldata"):
            return False
        return True  # conservative: treat as state variable

    if nt == "IndexAccess":
        # balances[msg.sender]  →  recurse into the base (balances)
        return _lhs_is_state_var(lhs.get("baseExpression", {}))

    if nt == "MemberAccess":
        inner = lhs.get("expression", {})
        # msg.x, tx.x, block.x are not state writes
        if isinstance(inner, dict) and inner.get("name") in ("msg", "tx", "block"):
            return False
        return _lhs_is_state_var(inner)

    return False


def _is_state_change(node: dict) -> bool:
    """True when node is an Assignment to a state variable."""
    if node.get("nodeType") != "Assignment":
        return False
    return _lhs_is_state_var(node.get("leftHandSide", {}))


# ── statement flattener ───────────────────────────────────────────────────────

def _collect_statements(body: Any) -> list[dict]:
    """
    Flatten a function body into a source-ordered list of statement dicts.
    Recurses into blocks, if-branches, and loops.
    """
    stmts: list[dict] = []
    if not isinstance(body, dict):
        return stmts

    nt = body.get("nodeType", "")

    if nt == "Block":
        for s in body.get("statements", []):
            stmts += _collect_statements(s)

    elif nt == "IfStatement":
        stmts += _collect_statements(body.get("trueBody", {}))
        stmts += _collect_statements(body.get("falseBody", {}))

    elif nt in ("ForStatement", "WhileStatement", "DoWhileStatement"):
        stmts += _collect_statements(body.get("body", {}))

    elif nt in ("ExpressionStatement", "Return",
                "EmitStatement", "RevertStatement"):
        stmts.append(body)

    else:
        for key in ("body", "statements", "trueBody", "falseBody",
                    "expression", "initialValue"):
            child = body.get(key)
            if child:
                stmts += _collect_statements(child)

    return stmts


def _unwrap(stmt: dict) -> dict:
    """Unwrap ExpressionStatement → inner expression."""
    if stmt.get("nodeType") == "ExpressionStatement":
        return stmt.get("expression", stmt)
    return stmt


# ── per-function analysis ─────────────────────────────────────────────────────

def _check_function(func_node: dict) -> list[dict]:
    """
    Scan one FunctionDefinition for:
        external_call()  ...  state_var = ...    (state change AFTER call)
    """
    findings: list[dict] = []
    body = func_node.get("body")
    if not body:
        return findings  # abstract / interface

    func_name = func_node.get("name", "<unnamed>")
    stmts = _collect_statements(body)

    pending_call: dict | None = None  # tracks the last seen external-call node

    for stmt in stmts:
        expr = _unwrap(stmt)

        if pending_call is None:
            if _is_eth_transfer_call(expr):
                pending_call = expr
        else:
            if _is_state_change(expr):
                # Resolve callee name for the report
                call_name = (
                    _resolve_callee(pending_call.get("expression", {}))
                    .get("memberName", "call")
                )
                findings.append({
                    "severity": "HIGH",
                    "issue": "Reentrancy vulnerability",
                    "function": func_name,
                    "details": (
                        f"State variable written AFTER .{call_name}() in "
                        f"'{func_name}'. An attacker can re-enter before "
                        f"the balance is updated and repeatedly drain funds."
                    ),
                    "recommendation": (
                        "Apply the Checks-Effects-Interactions pattern: "
                        "update all state variables before any external "
                        "call, or protect the function with a "
                        "ReentrancyGuard modifier."
                    ),
                })
                pending_call = None  # reset; keep scanning for more sites

            elif _is_eth_transfer_call(expr):
                # Another external call before any state change — track latest
                pending_call = expr

    return findings


# ── AST walker ────────────────────────────────────────────────────────────────

def _walk_functions(ast_node: Any, out: list[dict]) -> None:
    """Recursively collect every FunctionDefinition node."""
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "FunctionDefinition":
            out.append(ast_node)
        for v in ast_node.values():
            _walk_functions(v, out)
    elif isinstance(ast_node, list):
        for item in ast_node:
            _walk_functions(item, out)


# ── public entry point ────────────────────────────────────────────────────────

def check_reentrancy(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Parameters
    ----------
    ast : compact-JSON AST produced by solc.
    cfg : Slither CFG (reserved for future flow-sensitive passes).
    """
    funcs: list[dict] = []
    _walk_functions(ast, funcs)

    results: list[dict] = []
    for func in funcs:
        results += _check_function(func)

    return results