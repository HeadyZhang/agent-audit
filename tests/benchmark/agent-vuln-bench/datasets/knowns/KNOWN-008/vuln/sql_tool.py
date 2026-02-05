"""
MCP-style tool: SQL execution without input validation.
Set B | ASI-02
"""


def run_sql(query: str) -> list:
    """Execute SQL from user input (no parameterization)."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # LINE 11 — SQL injection
    return cursor.fetchall()
