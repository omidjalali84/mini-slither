def scan_tx_origin(ast_node):
    findings = []

    if isinstance(ast_node, dict):
        if "tx.origin" in str(ast_node):
            findings.append({
                "severity": "MEDIUM",
                "issue": "tx.origin usage detected"
            })

        for k in ast_node:
            findings += scan_tx_origin(ast_node[k])

    elif isinstance(ast_node, list):
        for item in ast_node:
            findings += scan_tx_origin(item)

    return findings