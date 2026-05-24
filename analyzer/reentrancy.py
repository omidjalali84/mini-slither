
def find_external_calls(ast_node):
    calls = []

    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "FunctionCall":
            expression = str(ast_node)

            if "call" in expression or "transfer" in expression:
                calls.append(ast_node)

        for k in ast_node:
            calls += find_external_calls(ast_node[k])

    elif isinstance(ast_node, list):
        for item in ast_node:
            calls += find_external_calls(item)

    return calls


def find_state_changes(ast_node):
    changes = []

    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "Assignment":
            changes.append(ast_node)

        for k in ast_node:
            changes += find_state_changes(ast_node[k])

    elif isinstance(ast_node, list):
        for item in ast_node:
            changes += find_state_changes(item)

    return changes


def check_reentrancy(ast, cfg=None):
    results = []

    external_calls = find_external_calls(ast)
    state_changes = find_state_changes(ast)

    if external_calls and state_changes:
        # ساده‌ترین heuristic:
        results.append({
            "severity": "HIGH",
            "issue": "Possible reentrancy vulnerability",
            "details": "External call + state change detected"
        })

    return results