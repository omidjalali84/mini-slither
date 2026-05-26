def find_external_calls_in_node(ast_node):
    """Find external calls directly within a given AST node (non-recursive into loops)."""
    calls = []

    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "FunctionCall":
            expression = str(ast_node)
            if "call" in expression or "transfer" in expression or "send" in expression:
                calls.append(ast_node)

        for k, v in ast_node.items():
            # Don't recurse into nested for loops here — handled at top level
            if k != "body":
                calls += find_external_calls_in_node(v)

    elif isinstance(ast_node, list):
        for item in ast_node:
            calls += find_external_calls_in_node(item)

    return calls


def find_for_loops_with_external_calls(ast_node, findings=None):
    """
    Recursively walk the AST and find ForStatement nodes that contain
    external calls anywhere in their body.
    """
    if findings is None:
        findings = []

    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "ForStatement":
            body = ast_node.get("body", {})
            external_calls = find_external_calls_in_node(body)

            if external_calls:
                findings.append({
                    "severity": "HIGH",
                    "issue": "DOS: External call inside a for loop",
                    "details": (
                        f"Found {len(external_calls)} external call(s) inside a for loop. "
                        "If any callee reverts or consumes unbounded gas, the entire loop "
                        "will revert, potentially blocking contract execution (DOS)."
                    ),
                    "call_count": len(external_calls),
                })

        # Continue walking the full tree to catch nested loops / multiple functions
        for v in ast_node.values():
            find_for_loops_with_external_calls(v, findings)

    elif isinstance(ast_node, list):
        for item in ast_node:
            find_for_loops_with_external_calls(item, findings)

    return findings


def check_dos(ast, cfg=None):
    return find_for_loops_with_external_calls(ast)