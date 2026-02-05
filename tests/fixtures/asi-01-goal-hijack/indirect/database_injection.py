"""
ASI-01: Indirect prompt injection via database content.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 18
"""


def query_and_process(db_connection, record_id: int):
    """Query database and use content in prompt."""
    cursor = db_connection.cursor()
    cursor.execute("SELECT content FROM records WHERE id = ?", (record_id,))
    row = cursor.fetchone()

    if row:
        # VULNERABILITY: Database content used in prompt without validation
        prompt = f"Summarize this record: {row[0]}"
        return prompt
    return None
