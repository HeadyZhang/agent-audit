"""
ASI-04: Unverified package import.
Rule: AGENT-015
Expected: TRUE POSITIVE at line 13
"""


def load_untrusted_plugin(plugin_name: str):
    """Load plugin dynamically without verification."""
    # VULNERABILITY: Dynamic import of unverified package
    module = __import__(plugin_name)
    return module
