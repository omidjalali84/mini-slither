TRANSFER_KEYWORDS = {"transfer", "send", "call", "safeTransfer", "transferFrom"}
OWNER_KEYWORDS = {"owner", "admin", "operator", "deployer", "governance"}


def _find_functions(ast_node, results=None):
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


def _has_owner_auth_check(func_node):
    """
    Returns True if the function has a require/if that compares
    msg.sender to a privileged address, or uses a privileged modifier.
    """
    # 1. Check modifiers applied to the function (e.g. onlyOwner)
    for modifier in func_node.get("modifiers", []):
        mod_name = modifier.get("modifierName", {}).get("name", "").lower()
        if any(kw in mod_name for kw in OWNER_KEYWORDS):
            return True

    # 2. Walk the function body for require/if checks
    return _walk_for_auth(func_node.get("body", {}))


def _walk_for_auth(node):
    if isinstance(node, dict):
        node_type = node.get("nodeType", "")

        # require(msg.sender == owner) or require(msg.sender == admin)
        if node_type in ("FunctionCall", "IfStatement"):
            node_str = str(node)
            if "msg.sender" in node_str:
                if any(kw in node_str for kw in OWNER_KEYWORDS):
                    return True

        for v in node.values():
            if _walk_for_auth(v):
                return True

    elif isinstance(node, list):
        for item in node:
            if _walk_for_auth(item):
                return True

    return False


def _has_fund_movement(func_node):
    """
    Returns (True, keyword) if the function body contains a fund transfer call.
    """
    return _walk_for_transfer(func_node.get("body", {}))


def _walk_for_transfer(node):
    if isinstance(node, dict):
        node_type = node.get("nodeType", "")

        if node_type == "FunctionCall":
            node_str = str(node)
            for kw in TRANSFER_KEYWORDS:
                if kw in node_str:
                    # Exclude the case where it's a user pulling their own balance:
                    # transfer(msg.sender, amount) is fine if there's no owner gate —
                    # but here we already know there IS an owner gate, so flag it.
                    return True, kw

        for v in node.values():
            result = _walk_for_transfer(v)
            if result[0]:
                return result

    elif isinstance(node, list):
        for item in node:
            result = _walk_for_transfer(item)
            if result[0]:
                return result

    return False, None


def _get_function_name(func_node):
    return func_node.get("name") or "<fallback/receive>"


def check_centralization_withdrawal(ast, cfg=None):
    """
    Detects fund withdrawal centralization:
    A function that is gated by a single-address auth check AND
    contains a fund movement operation.
    """
    results = []

    functions = _find_functions(ast)

    for func in functions:
        has_auth = _has_owner_auth_check(func)
        has_transfer, transfer_kw = _has_fund_movement(func)

        if has_auth and has_transfer:
            func_name = _get_function_name(func)
            results.append({
                "severity": "HIGH",
                "issue": "Centralized fund withdrawal",
                "details": (
                    f"Function '{func_name}' is restricted to a single privileged address "
                    f"and moves funds via '{transfer_kw}'. "
                    "A compromised or malicious owner can drain the contract."
                ),
                "function": func_name,
                "src": func.get("src", "unknown"),
            })

    return results
