"""
Intentionally Vulnerable Tool Functions - For Testing agent-audit
==================================================================
DO NOT USE IN PRODUCTION. This file contains deliberate security flaws.
"""

import os
import pickle
from langchain.tools import tool


# =============================================================================
# AGENT-035: Unrestricted Code Execution
# =============================================================================
@tool
def execute_python(code: str) -> str:
    """Execute arbitrary Python code."""
    # DANGEROUS: exec() with user input, no sandboxing
    local_vars = {}
    exec(code, {}, local_vars)  # AGENT-035: Unrestricted code execution
    return str(local_vars)


# =============================================================================
# AGENT-034: File Operations Without Path Validation
# =============================================================================
@tool
def read_file(filepath: str) -> str:
    """Read contents of a file."""
    # DANGEROUS: No path validation - allows reading any file
    # e.g., filepath = "/etc/passwd" or "../../secrets.txt"
    with open(filepath, 'r') as f:  # AGENT-034: Path traversal risk
        return f.read()


@tool
def write_file(filepath: str, content: str) -> str:
    """Write content to a file."""
    # DANGEROUS: No path validation - allows writing anywhere
    with open(filepath, 'w') as f:  # AGENT-034: Arbitrary file write
        f.write(content)
    return f"Written to {filepath}"


@tool
def delete_file(filepath: str) -> str:
    """Delete a file."""
    # DANGEROUS: No path validation, no confirmation
    os.remove(filepath)  # AGENT-034 + AGENT-037: Missing human approval
    return f"Deleted {filepath}"


# =============================================================================
# AGENT-036: Trusting Tool Output Without Sanitization
# =============================================================================
@tool
def fetch_and_execute(url: str) -> str:
    """Fetch code from URL and execute it."""
    import requests
    response = requests.get(url)
    code = response.text
    # DANGEROUS: Executing code from untrusted source
    exec(code)  # AGENT-036: Trusting external output
    return "Executed remote code"


# =============================================================================
# Supply Chain: Insecure Deserialization
# =============================================================================
@tool
def load_model(filepath: str) -> str:
    """Load a pickled model from file."""
    # DANGEROUS: pickle.load can execute arbitrary code
    with open(filepath, 'rb') as f:
        model = pickle.load(f)  # Insecure deserialization
    return f"Loaded model: {type(model)}"
