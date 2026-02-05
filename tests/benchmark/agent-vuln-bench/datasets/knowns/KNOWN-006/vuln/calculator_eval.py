"""
CVE-2023-46229: eval() in calculator tool.
Set A | ASI-02 | CWE-95
"""
import json


class CalculatorTool:
    """A tool that evaluates mathematical expressions"""
    name = "calculator"
    description = "Evaluate mathematical expressions"

    def run(self, expression: str) -> str:
        try:
            result = eval(expression)  # LINE 13 — VULN: RCE via eval
            return str(result)
        except Exception as e:
            return f"Error: {e}"


def handle_agent_action(action_json: str):
    action = json.loads(action_json)
    if action["tool"] == "calculator":
        tool = CalculatorTool()
        return tool.run(action["input"])
