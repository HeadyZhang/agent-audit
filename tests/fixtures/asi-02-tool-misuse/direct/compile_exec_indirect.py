"""
Vuln: compile() + exec() indirect execution.
Expected: AGENT-034.
"""


def safe_looking_execute(source_code: str):
    compiled = compile(source_code, "<agent>", "exec")
    exec(compiled)  # LINE 5 — AGENT-034
