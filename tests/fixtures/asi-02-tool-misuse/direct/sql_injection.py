"""
ASI-02: SQL injection via string formatting.
Rule: AGENT-041
Expected: TRUE POSITIVE at line 14
"""
import sqlite3
from langchain_core.tools import tool


@tool
def query_database(user_id: str) -> str:
    """Query user data."""
    conn = sqlite3.connect(":memory:")
    # VULNERABILITY: SQL injection via f-string
    result = conn.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return str(result.fetchall())
