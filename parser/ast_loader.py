"""
ast_loader.py — parse a Solidity file into a compact-JSON AST dict.

solc --ast-compact-json output format
──────────────────────────────────────
The command prints a plain-text header before the JSON blob:

    ======= path/to/file.sol =======
    JSON AST:

    { ...json... }

The original loader used output.find("{") which works but is fragile.
This version finds the first LINE that starts with "{" so it is robust
against any header content that might itself contain curly braces.
"""

import json
import subprocess


def get_ast(file_path: str) -> dict:
    """
    Run  solc --ast-compact-json <file_path>  and return the parsed
    SourceUnit dict.

    Raises
    ------
    RuntimeError   if solc exits with a non-zero code.
    ValueError     if no JSON object can be found in the output.
    """
    cmd = ["solc", "--ast-compact-json", file_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"solc failed for {file_path}:\n{result.stderr.strip()}"
        )

    # Find the first line that begins with "{" — that is the JSON blob.
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            return json.loads(stripped)

    raise ValueError(
        f"Could not find JSON in solc output for {file_path}.\n"
        f"Raw output:\n{result.stdout[:500]}"
    )