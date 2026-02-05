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
    detect_uuid_format,
    UUIDAnalysis,
)
from agent_audit.analysis.identifier_analyzer import (
    analyze_identifier,
    identifier_suggests_credential,
    identifier_suggests_data_id,
    IdentifierAnalysis,
    IdentifierCategory,
)
from agent_audit.analysis.confidence_matrix import (
    ConfidenceAdjustment,
    AdjustmentDirection,
    CONFIDENCE_ADJUSTMENTS,
    calculate_final_confidence,
    should_suppress,
    get_tier_from_confidence,
    get_adjustment,
    get_uuid_adjustment,
    get_data_identifier_adjustment,
    get_placeholder_adjustment,
    get_known_format_adjustment,
    get_test_file_adjustment,
)

__all__ = [
    # Entropy
    "shannon_entropy",
    "normalized_entropy",
    # Placeholder detection
    "is_placeholder",
    "PlaceholderResult",
    "PLACEHOLDER_PATTERNS",
    # Value analysis
    "analyze_credential_value",
    "CredentialAnalysis",
    "KNOWN_CREDENTIAL_FORMATS",
    "detect_uuid_format",
    "UUIDAnalysis",
    # Identifier analysis
    "analyze_identifier",
    "identifier_suggests_credential",
    "identifier_suggests_data_id",
    "IdentifierAnalysis",
    "IdentifierCategory",
    # Confidence matrix (v0.6.0)
    "ConfidenceAdjustment",
    "AdjustmentDirection",
    "CONFIDENCE_ADJUSTMENTS",
    "calculate_final_confidence",
    "should_suppress",
    "get_tier_from_confidence",
    "get_adjustment",
    "get_uuid_adjustment",
    "get_data_identifier_adjustment",
    "get_placeholder_adjustment",
    "get_known_format_adjustment",
    "get_test_file_adjustment",
]
