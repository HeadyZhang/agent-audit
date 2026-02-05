"""
BENIGN: Safe file read with path validation.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import os
from langchain_core.tools import tool


@tool
def safe_read_file(filepath: str) -> str:
    """Read file from allowed directory."""
    try:
        # SAFE: Path validation
        allowed_dir = "/app/data"
        abs_path = os.path.abspath(filepath)

        if not abs_path.startswith(allowed_dir):
            return "Error: Access denied - Path outside allowed directory"

        # SAFE: Only after path validation
        with open(abs_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"
