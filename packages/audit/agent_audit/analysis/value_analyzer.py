"""
Credential value analysis for confidence-based detection.

Combines entropy analysis, placeholder detection, and format matching
to provide high-confidence credential detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from agent_audit.analysis.entropy import shannon_entropy, entropy_confidence
from agent_audit.analysis.placeholder_detector import is_placeholder


@dataclass
class CredentialFormat:
    """Known credential format specification."""
    name: str
    pattern: str
    prefix: Optional[str] = None
    min_length: int = 10
    max_length: int = 500
    expected_entropy: float = 3.5
    confidence_boost: float = 0.3  # Added to base confidence when matched


# Known credential formats with high-confidence patterns
KNOWN_CREDENTIAL_FORMATS: List[CredentialFormat] = [
    # OpenAI
    CredentialFormat(
        name="OpenAI API Key",
        pattern=r'^sk-proj-[a-zA-Z0-9]{20,}$',
        prefix='sk-proj-',
        min_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="OpenAI Legacy Key",
        pattern=r'^sk-[a-zA-Z0-9]{32,}$',
        prefix='sk-',
        min_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # Anthropic
    CredentialFormat(
        name="Anthropic API Key",
        pattern=r'^sk-ant-api\d{2}-[a-zA-Z0-9_-]{80,}$',
        prefix='sk-ant-api',
        min_length=90,
        expected_entropy=4.5,
        confidence_boost=0.4,
    ),

    # Cohere
    CredentialFormat(
        name="Cohere API Key",
        pattern=r'^co-[a-zA-Z0-9]{32,}$',
        prefix='co-',
        min_length=35,
        expected_entropy=4.0,
        confidence_boost=0.3,
    ),

    # AWS
    CredentialFormat(
        name="AWS Access Key",
        pattern=r'^AKIA[0-9A-Z]{16}$',
        prefix='AKIA',
        min_length=20,
        max_length=20,
        expected_entropy=3.5,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="AWS Secret Key",
        pattern=r'^[a-zA-Z0-9/+]{40}$',
        min_length=40,
        max_length=40,
        expected_entropy=4.5,
        confidence_boost=0.3,
    ),

    # Google Cloud
    CredentialFormat(
        name="Google API Key",
        pattern=r'^AIza[0-9A-Za-z_-]{35}$',
        prefix='AIza',
        min_length=39,
        max_length=39,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # GitHub
    CredentialFormat(
        name="GitHub Personal Access Token",
        pattern=r'^ghp_[a-zA-Z0-9]{36}$',
        prefix='ghp_',
        min_length=40,
        max_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="GitHub OAuth Token",
        pattern=r'^gho_[a-zA-Z0-9]{36}$',
        prefix='gho_',
        min_length=40,
        max_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="GitHub App Token",
        pattern=r'^ghs_[a-zA-Z0-9]{36}$',
        prefix='ghs_',
        min_length=40,
        max_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # Stripe
    CredentialFormat(
        name="Stripe Secret Key",
        pattern=r'^sk_live_[a-zA-Z0-9]{24,}$',
        prefix='sk_live_',
        min_length=32,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="Stripe Test Key",
        pattern=r'^sk_test_[a-zA-Z0-9]{24,}$',
        prefix='sk_test_',
        min_length=32,
        expected_entropy=4.0,
        confidence_boost=0.3,  # Lower for test keys
    ),

    # Slack
    CredentialFormat(
        name="Slack Bot Token",
        pattern=r'^xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}$',
        prefix='xoxb-',
        min_length=50,
        expected_entropy=3.5,
        confidence_boost=0.4,
    ),
    CredentialFormat(
        name="Slack User Token",
        pattern=r'^xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}$',
        prefix='xoxp-',
        min_length=50,
        expected_entropy=3.5,
        confidence_boost=0.4,
    ),

    # SendGrid
    CredentialFormat(
        name="SendGrid API Key",
        pattern=r'^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$',
        prefix='SG.',
        min_length=65,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # Twilio
    CredentialFormat(
        name="Twilio API Key",
        pattern=r'^SK[a-f0-9]{32}$',
        prefix='SK',
        min_length=34,
        max_length=34,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # NPM
    CredentialFormat(
        name="NPM Token",
        pattern=r'^npm_[a-zA-Z0-9]{36}$',
        prefix='npm_',
        min_length=40,
        max_length=40,
        expected_entropy=4.0,
        confidence_boost=0.4,
    ),

    # PyPI
    CredentialFormat(
        name="PyPI API Token",
        pattern=r'^pypi-[A-Za-z0-9_-]{150,}$',
        prefix='pypi-',
        min_length=155,
        expected_entropy=4.5,
        confidence_boost=0.4,
    ),

    # Generic patterns
    CredentialFormat(
        name="Generic Bearer Token",
        pattern=r'^Bearer\s+[a-zA-Z0-9._-]{20,}$',
        prefix='Bearer ',
        min_length=27,
        expected_entropy=3.5,
        confidence_boost=0.2,
    ),
    CredentialFormat(
        name="Generic JWT",
        pattern=r'^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$',
        prefix='eyJ',
        min_length=50,
        expected_entropy=4.0,
        confidence_boost=0.3,
    ),
]


@dataclass
class CredentialAnalysis:
    """Result of credential value analysis."""
    is_credential: bool
    confidence: float  # 0.0-1.0
    format_name: Optional[str] = None  # Name of matched format, if any
    is_placeholder: bool = False
    entropy: float = 0.0
    reasons: Optional[List[str]] = None


def analyze_credential_value(value: str) -> CredentialAnalysis:
    """
    Analyze a value to determine if it's a real credential.

    Combines multiple signals:
    1. Known format matching
    2. Entropy analysis
    3. Placeholder detection
    4. Length and character analysis

    Args:
        value: String value to analyze

    Returns:
        CredentialAnalysis with detection result and confidence
    """
    reasons: List[str] = []

    if not value:
        return CredentialAnalysis(
            is_credential=False,
            confidence=0.0,
            is_placeholder=True,
            reasons=["Empty value"]
        )

    # Strip whitespace
    value = value.strip()

    # Calculate base entropy
    entropy = shannon_entropy(value)
    base_confidence = entropy_confidence(value)
    reasons.append(f"Entropy: {entropy:.2f}")

    # Check for placeholder
    placeholder_result = is_placeholder(value)
    if placeholder_result.is_placeholder:
        # Reduce confidence significantly for placeholders
        adjusted_confidence = base_confidence * (1.0 - placeholder_result.confidence)
        reasons.append(f"Placeholder detected: {placeholder_result.reason}")
        return CredentialAnalysis(
            is_credential=False,
            confidence=adjusted_confidence,
            is_placeholder=True,
            entropy=entropy,
            reasons=reasons
        )

    # Check against known formats
    matched_format: Optional[CredentialFormat] = None
    for fmt in KNOWN_CREDENTIAL_FORMATS:
        if re.match(fmt.pattern, value):
            matched_format = fmt
            base_confidence = min(1.0, base_confidence + fmt.confidence_boost)
            reasons.append(f"Matched format: {fmt.name}")
            break

    # Length checks
    value_len = len(value)
    if matched_format:
        if value_len < matched_format.min_length:
            base_confidence *= 0.5
            reasons.append(f"Shorter than expected for {matched_format.name}")
        elif value_len > matched_format.max_length:
            base_confidence *= 0.8
            reasons.append(f"Longer than expected for {matched_format.name}")
    else:
        # No format match - apply generic heuristics
        if value_len < 10:
            base_confidence *= 0.3
            reasons.append("Very short for a credential")
        elif value_len > 500:
            base_confidence *= 0.7
            reasons.append("Unusually long")

    # Character variety check
    unique_chars = len(set(value))
    char_variety = unique_chars / len(value) if value else 0

    if char_variety < 0.3:
        base_confidence *= 0.5
        reasons.append("Low character variety")

    # Final determination
    is_credential = base_confidence >= 0.5

    return CredentialAnalysis(
        is_credential=is_credential,
        confidence=min(1.0, base_confidence),
        format_name=matched_format.name if matched_format else None,
        is_placeholder=False,
        entropy=entropy,
        reasons=reasons
    )


def match_credential_format(value: str) -> Optional[Tuple[str, float]]:
    """
    Check if value matches a known credential format.

    Args:
        value: String to check

    Returns:
        Tuple of (format_name, confidence_boost) if matched, None otherwise
    """
    for fmt in KNOWN_CREDENTIAL_FORMATS:
        if re.match(fmt.pattern, value):
            return (fmt.name, fmt.confidence_boost)
    return None


def get_credential_prefix(value: str) -> Optional[str]:
    """
    Extract the credential prefix if present.

    Args:
        value: String to check

    Returns:
        Prefix string if detected, None otherwise
    """
    for fmt in KNOWN_CREDENTIAL_FORMATS:
        if fmt.prefix and value.startswith(fmt.prefix):
            return fmt.prefix
    return None
