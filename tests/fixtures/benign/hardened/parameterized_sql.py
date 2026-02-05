"""
BENIGN: Parameterized SQL query.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import sqlite3
from langchain_core.tools import tool


@tool
def safe_query(user_id: str) -> str:
    """Query with parameterized statement."""
    conn = sqlite3.connect(":memory:")
    # SAFE: Parameterized query prevents SQL injection
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(result.fetchall())
