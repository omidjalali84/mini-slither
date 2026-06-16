"""
Delegatecall risk analyzer — detects use of .delegatecall() in contract
functions, especially when the call target is user-controlled.

Why it matters
──────────────
delegatecall executes the callee's code in the CALLER's storage context.
This means:
  - A malicious or compromised implementation contract can overwrite any
    storage slot in the calling contract, including the owner variable.
  - If the target address is passed as a parameter (user-controlled), an
    attacker can point delegatecall at a malicious contract.
  - Even with a fixed target, upgradeability patterns that rely on
    delegatecall require careful proxy storage layout discipline.

Detection strategy
──────────────────
1. Find all FunctionCall nodes where the callee is a MemberAccess with
   memberName == "delegatecall" (after unwrapping FunctionCallOptions).
2. Check whether the call target (base of the MemberAccess) is a function
   parameter or a local variable — indicating user-controlled input.
3. Flag all occurrences as HIGH; note "user-controlled target" when detected.
"""

from __future__ import annotations
from typing import Any


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


def _resolve_callee(expr: Any) -> dict:
    """Unwrap FunctionCallOptions to find the innermost expression."""
    if not isinstance(expr, dict):
        return {}
    while expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression", {})
    return expr


def _is_delegatecall(node: dict) -> bool:
    """True when node is a FunctionCall to .delegatecall()."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") != "FunctionCall":
        return False
    callee = _resolve_callee(node.get("expression", {}))
    return (
        callee.get("nodeType") == "MemberAccess"
        and callee.get("memberName") == "delegatecall"
    )


def _get_call_target_name(node: dict) -> str:
    """Extract the name of the address being delegatecalled."""
    callee = _resolve_callee(node.get("expression", {}))
    base = callee.get("expression", {})
    if isinstance(base, dict):
        return base.get("name", "<unknown>")
    return "<unknown>"


def _collect_param_names(func_node: dict) -> set[str]:
    """Return the set of parameter names for a function."""
    params: set[str] = set()
    param_list = func_node.get("parameters", {}).get("parameters", [])
    for p in param_list:
        name = p.get("name")
        if name:
            params.add(name)
    return params


def _find_delegatecalls(body: Any, found: list | None = None) -> list[dict]:
    """Recursively collect all delegatecall FunctionCall nodes."""
    if found is None:
        found = []
    if isinstance(body, dict):
        if _is_delegatecall(body):
            found.append(body)
        for v in body.values():
            _find_delegatecalls(v, found)
    elif isinstance(body, list):
        for item in body:
            _find_delegatecalls(item, found)
    return found


def _get_function_name(func_node: dict) -> str:
    return func_node.get("name") or "<fallback/receive>"


# ── public entry point ────────────────────────────────────────────────────────

def check_delegatecall(ast: Any, cfg=None) -> list[dict]:
    """
    Called by core/engine.py.

    Flags every function that uses .delegatecall(), with extra detail when
    the target address appears to come from a function parameter.
    """
    results: list[dict] = []

    for func in _find_functions(ast):
        body = func.get("body")
        if not body:
            continue

        dc_calls = _find_delegatecalls(body)
        if not dc_calls:
            continue

        func_name = _get_function_name(func)
        param_names = _collect_param_names(func)

        for call in dc_calls:
            target = _get_call_target_name(call)
            user_controlled = target in param_names

            if user_controlled:
                extra = (
                    f" The target address '{target}' is a function parameter — "
                    "an attacker can pass a malicious contract address and "
                    "overwrite arbitrary storage slots in this contract."
                )
            else:
                extra = (
                    f" The target is '{target}'. Even with a fixed target, ensure "
                    "storage layout compatibility between this contract and the "
                    "implementation to prevent slot collisions."
                )

            results.append({
                "severity": "HIGH",
                "issue": "Delegatecall risk",
                "function": func_name,
                "details": (
                    f"Function '{func_name}' uses .delegatecall(), executing "
                    f"external code in this contract's storage context.{extra}"
                ),
                "recommendation": (
                    "Avoid delegatecall to user-supplied addresses. If used in "
                    "a proxy pattern, validate the implementation address via "
                    "an admin-controlled registry and audit storage layout "
                    "compatibility carefully."
                ),
                "src": func.get("src", "unknown"),
            })

    return results