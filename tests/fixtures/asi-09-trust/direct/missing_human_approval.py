"""
ASI-09: Missing human approval for sensitive actions.
Rule: AGENT-037
Expected: TRUE POSITIVE at line 18
"""
from langchain_core.tools import tool


@tool
def execute_financial_transaction(amount: float, recipient: str) -> str:
    """Execute financial transaction without approval."""
    # VULNERABILITY: No human-in-the-loop for sensitive action
    # Direct execution without confirmation
    return f"Transferred {amount} to {recipient}"
