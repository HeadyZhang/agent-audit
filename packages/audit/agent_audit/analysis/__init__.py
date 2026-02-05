"""Analysis module for agent-audit confidence scoring."""

from agent_audit.analysis.entropy import shannon_entropy, normalized_entropy
from agent_audit.analysis.placeholder_detector import (
    is_placeholder,
    PlaceholderResult,
    PLACEHOLDER_PATTERNS,
)
from agent_audit.analysis.value_analyzer import (
    analyze_credential_value,
    CredentialAnalysis,
    KNOWN_CREDENTIAL_FORMATS,
)

__all__ = [
    "shannon_entropy",
    "normalized_entropy",
    "is_placeholder",
    "PlaceholderResult",
    "PLACEHOLDER_PATTERNS",
    "analyze_credential_value",
    "CredentialAnalysis",
    "KNOWN_CREDENTIAL_FORMATS",
]
