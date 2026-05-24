import json
import subprocess

def get_ast(file_path):
    cmd = ["solc", "--ast-compact-json", file_path]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception(result.stderr)

    # solc خروجی چند بخش دارد، ما JSON را جدا می‌کنیم
    output = result.stdout

    # ساده‌سازی: پیدا کردن JSON
    start = output.find("{")
    ast_json = output[start:]

    return json.loads(ast_json)