"""
Unchecked external call analyzer — detects low-level calls whose return
value is never checked.

Solidity's .call(), .send(), and .delegatecall() return a boolean success
flag. If this flag is ignored, a failed call silently continues execution,
potentially leaving the contract in an inconsistent state (e.g. funds
appear sent but weren't, or a delegate call silently failed).

.transfer() is excluded — it reverts automatically on failure.

Detection strategy
──────────────────
A call is "unchecked" when the FunctionCall node for .call / .send /
.delegatecall appears as a bare ExpressionStatement (i.e. its return
value is NOT stored in a variable and NOT used in a require / if / assert).

Patterns flagged:
    addr.call{value: x}("");            // bare statement
    addr.send(amount);                  // bare statement

Patterns NOT flagged:
    (bool ok,) = addr.call{...}("");    // return value captured in tuple
    bool ok = addr.send(amount);        // return value stored
    require(addr.send(amount));         // return value checked inline
    if (!addr.send(amount)) revert();   // return value checked in if
"""

from __future__ import annotations
from typing import Any

_UNCHECKED_CALL_NAMES = {"call", "send", "delegatecall"}


# ── call detection ────────────────────────────────────────────────────────────

def _resolve_callee(expr: Any) -> dict:
    """Unwrap FunctionCallOptions layers and return the innermost expression."""
    if not isinstance(expr, dict):
        return {}
    while expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression", {})
    return expr


def _is_low_level_call(node: dict) -> bool:
    """
    True when node is a FunctionCall to .call / .send / .delegatecall
    (after unwrapping FunctionCallOptions).
    """
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") != "FunctionCall":
        return False
    callee = _resolve_callee(node.get("expression", {}))
    if callee.get("nodeType") != "MemberAccess":
        return False
    return callee.get("memberName") in _UNCHECKED_CALL_NAMES


def _get_call_name(node: dict) -> str:
    callee = _resolve_callee(node.get("expression", {}))
    return callee.get("memberName", "call")


# ── "is the return value used?" check ────────────────────────────────────────

def _is_bare_expression_statement(stmt: dict) -> bool:
    """
    True when stmt is an ExpressionStatement whose expression is directly
    a low-level call — meaning the boolean return value is discarded.

    Counter-examples (NOT bare):
      - Tuple assignment:   (bool ok,) = addr.call(...)
        → nodeType == VariableDeclarationStatement  or  Assignment
      - require(addr.send(...))
        → ExpressionStatement whose expression is a FunctionCall to require,
          not directly to .send
    """
    if stmt.get("nodeType") != "ExpressionStatement":
        return False
    expr = stmt.get("expression", {})
    return _is_low_level_call(expr)


# ── statement-level walker ────────────────────────────────────────────────────

def _collect_bare_calls_in_body(body: Any, findings_out: list, func_name: str) -> None:
    """
    Walk a function body and record every bare (unchecked) low-level call.
    """
    if not isinstance(body, dict):
        return

    nt = body.get("nodeType", "")

    if nt == "Block":
        for stmt in body.get("statements", []):
            _collect_bare_calls_in_body(stmt, findings_out, func_name)

    elif nt == "ExpressionStatement":
        if _is_bare_expression_statement(body):
            call_node = body.get("expression", {})
            call_name = _get_call_name(call_node)
            findings_out.append({
                "severity": "MEDIUM",
                "issue": "Unchecked external call",
                "function": func_name,
                "details": (
                    f"Return value of '.{call_name}()' in '{func_name}' is not "
                    "checked. If the call fails, execution continues silently, "
                    "potentially leaving the contract in an inconsistent state."
                ),
                "recommendation": (
                    f"Capture and verify the return value: "
                    f"`(bool ok, ) = addr.{call_name}(...);"
                    f" require(ok, \"call failed\");`"
                ),
                "src": body.get("src", "unknown"),
            })

    elif nt == "IfStatement":
        _collect_bare_calls_in_body(body.get("trueBody", {}), findings_out, func_name)
        _collect_bare_calls_in_body(body.get("falseBody", {}), findings_out, func_name)

    elif nt in ("ForStatement", "WhileStatement", "DoWhileStatement"):
        _collect_bare_calls_in_body(body.get("body", {}), findings_out, func_name)

    # Catch any other container nodes generically
    else:
        for key in ("body", "statements", "trueBody", "falseBody"):
            child = body.get(key)
            if child:
                _collect_bare_calls_in_body(child, findings_out, func_name)


# ── AST walker ────────────────────────────────────────────────────────────────

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


# ── public entry point ────────────────────────────────────────────────────────

def check_unchecked_call(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Scans all function bodies for low-level external calls (.call, .send,
    .delegatecall) whose boolean return value is never captured or checked.
    """
    results: list[dict] = []

    for func in _find_functions(ast):
        body = func.get("body")
        if not body:
            continue
        func_name = func.get("name") or "<fallback/receive>"
        _collect_bare_calls_in_body(body, results, func_name)

    return results
