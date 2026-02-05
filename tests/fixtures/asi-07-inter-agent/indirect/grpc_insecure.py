"""
ASI-07: Insecure gRPC channel vulnerability.
Rule: AGENT-020
Expected: TRUE POSITIVE at line 13
owasp_id: ASI-07
"""
import grpc


def connect_to_agent_service(host: str):
    """Connect to agent service via insecure gRPC."""
    # VULNERABILITY: Unencrypted inter-agent gRPC channel
    channel = grpc.insecure_channel(f"{host}:50051")
    return channel
