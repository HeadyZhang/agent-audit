"""
ASI-07: WebSocket without TLS vulnerability.
Rule: AGENT-020
Expected: TRUE POSITIVE at line 14
owasp_id: ASI-07
"""
import websocket


def connect_to_agent(host: str, port: int):
    """Connect to agent via unencrypted WebSocket."""
    # VULNERABILITY: Unencrypted inter-agent channel
    ws = websocket.create_connection(f"ws://{host}:{port}/agent")
    return ws
