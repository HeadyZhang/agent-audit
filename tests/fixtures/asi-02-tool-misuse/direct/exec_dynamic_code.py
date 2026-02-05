"""
Vuln: exec() on dynamic code.
Expected: AGENT-034.
Ref: KNOWN-002 (CVE-2023-36258).
"""


def run_python_code(code: str, context: dict) -> dict:
    """Execute Python code in a given context"""
    local_vars = {}
    exec(code, {"__builtins__": {}}, local_vars)  # LINE 8 — AGENT-034
    return local_vars


class PythonREPLTool:
    def execute(self, code_input: str):
        return run_python_code(code_input, {})
