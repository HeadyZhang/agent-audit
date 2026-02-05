"""Fixed: parameterized queries."""

import sqlite3


def run_sql(query: str, params: tuple = ()) -> list:
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query, params)  # parameterized
    return cursor.fetchall()
