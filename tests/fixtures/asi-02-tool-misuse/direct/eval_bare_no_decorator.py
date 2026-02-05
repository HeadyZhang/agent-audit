"""
Vuln: bare eval() without @tool context.
Expected: AGENT-034 (Gap-1).
Ref: KNOWN-001 (CVE-2023-29374).
"""
import json


def calculate(expression: str) -> float:
    """Simple calculator that evaluates expressions"""
    result = eval(expression)  # LINE 11 — AGENT-034
    return float(result)


def process_request(request_data: str):
    data = json.loads(request_data)
    return calculate(data["expression"])
