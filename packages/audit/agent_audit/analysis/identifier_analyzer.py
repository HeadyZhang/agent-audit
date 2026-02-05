"""
Identifier name analysis for credential detection context.

Analyzes variable/key names to determine if they suggest credential usage
or data identifier usage, significantly reducing false positives for
UUID-format strings used as sample tokens, scene IDs, etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class IdentifierCategory(Enum):
    """Category of identifier based on naming patterns."""
    CREDENTIAL = "credential"      # Likely holds a secret
    DATA_IDENTIFIER = "data_id"    # Likely holds a data ID/UUID
    AMBIGUOUS = "ambiguous"        # Could be either
    UNKNOWN = "unknown"            # No pattern match


@dataclass
class IdentifierAnalysis:
    """Result of identifier name analysis."""
    category: IdentifierCategory
    confidence: float  # 0.0-1.0
    matched_pattern: Optional[str] = None
    reason: str = ""
    confidence_multiplier: float = 1.0  # Multiplier to apply to base confidence


# Credential-suggesting patterns (increase confidence)
CREDENTIAL_PATTERNS: List[Tuple[re.Pattern, str, float, float]] = [
    # (pattern, description, category_confidence, confidence_multiplier)
    (re.compile(r'(?i)^(api[_-]?key|apikey)$'), "API key variable", 0.95, 1.2),
    (re.compile(r'(?i)^(secret[_-]?key|secretkey)$'), "Secret key variable", 0.95, 1.25),
    (re.compile(r'(?i)^(auth[_-]?token|authtoken)$'), "Auth token variable", 0.90, 1.15),
    (re.compile(r'(?i)^(api[_-]?token|apitoken)$'), "API token variable", 0.90, 1.15),
    (re.compile(r'(?i)^(access[_-]?token|accesstoken)$'), "Access token variable", 0.90, 1.15),
    (re.compile(r'(?i)^(password|passwd|pwd)$'), "Password variable", 0.95, 1.3),
    (re.compile(r'(?i)^(private[_-]?key|privatekey)$'), "Private key variable", 0.95, 1.25),
    (re.compile(r'(?i)^(client[_-]?secret|clientsecret)$'), "Client secret variable", 0.95, 1.2),
    (re.compile(r'(?i)^(bearer[_-]?token)$'), "Bearer token variable", 0.90, 1.15),
    (re.compile(r'(?i)(key|secret|password|credential|auth)'), "Contains credential keyword", 0.70, 1.1),
]

# Data identifier patterns (decrease confidence)
DATA_IDENTIFIER_PATTERNS: List[Tuple[re.Pattern, str, float, float]] = [
    # (pattern, description, category_confidence, confidence_multiplier)
    # Sample/data identifiers
    (re.compile(r'(?i)^(sample[_-]?(token|id|uuid|hash))$'), "Sample identifier", 0.95, 0.15),
    (re.compile(r'(?i)^(data[_-]?(token|id|uuid|hash))$'), "Data identifier", 0.95, 0.15),
    (re.compile(r'(?i)^(scene[_-]?(token|id|uuid))$'), "Scene identifier", 0.95, 0.15),
    (re.compile(r'(?i)^(frame[_-]?(token|id|uuid))$'), "Frame identifier", 0.95, 0.15),
    (re.compile(r'(?i)^(instance[_-]?(token|id|uuid))$'), "Instance identifier", 0.95, 0.15),
    (re.compile(r'(?i)^(annotation[_-]?(token|id))$'), "Annotation identifier", 0.90, 0.2),

    # Generic ID patterns
    (re.compile(r'(?i)^(\w+[_-]?uuid)$'), "UUID variable", 0.90, 0.2),
    (re.compile(r'(?i)^(\w+[_-]?hash)$'), "Hash variable", 0.85, 0.25),
    (re.compile(r'(?i)^(record[_-]?id|recordid)$'), "Record ID", 0.85, 0.25),
    (re.compile(r'(?i)^(item[_-]?id|itemid)$'), "Item ID", 0.85, 0.25),
    (re.compile(r'(?i)^(entity[_-]?id|entityid)$'), "Entity ID", 0.85, 0.25),
    (re.compile(r'(?i)^(session[_-]?id|sessionid)$'), "Session ID (not token)", 0.80, 0.3),
    (re.compile(r'(?i)^(transaction[_-]?id)$'), "Transaction ID", 0.85, 0.25),
    (re.compile(r'(?i)^(correlation[_-]?id)$'), "Correlation ID", 0.85, 0.25),
    (re.compile(r'(?i)^(trace[_-]?id)$'), "Trace ID", 0.85, 0.25),
    (re.compile(r'(?i)^(request[_-]?id)$'), "Request ID", 0.85, 0.25),

    # Bare 'token' without credential context (ambiguous but often data)
    (re.compile(r'^token$'), "Bare 'token' variable", 0.60, 0.4),
]

# Patterns that are explicitly NOT credentials
NON_CREDENTIAL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)^(num[_-]?tokens?|token[_-]?count|token[_-]?length)$'), "Token count variable"),
    (re.compile(r'(?i)^(max[_-]?tokens?|min[_-]?tokens?)$'), "Token limit variable"),
    (re.compile(r'(?i)^(input[_-]?tokens?|output[_-]?tokens?)$'), "Token metric variable"),
    (re.compile(r'(?i)^(token[_-]?limit|token[_-]?budget)$'), "Token budget variable"),
    (re.compile(r'(?i)^(tokenizer|tokenize|tokenization)'), "Tokenization related"),
]


def analyze_identifier(identifier: str) -> IdentifierAnalysis:
    """
    Analyze an identifier name to determine if it suggests credential or data usage.

    Args:
        identifier: Variable or key name to analyze

    Returns:
        IdentifierAnalysis with category, confidence, and multiplier
    """
    if not identifier:
        return IdentifierAnalysis(
            category=IdentifierCategory.UNKNOWN,
            confidence=0.0,
            reason="Empty identifier"
        )

    # Normalize identifier
    identifier = identifier.strip()

    # Check non-credential patterns first (these should never affect confidence)
    for pattern, description in NON_CREDENTIAL_PATTERNS:
        if pattern.search(identifier):
            return IdentifierAnalysis(
                category=IdentifierCategory.DATA_IDENTIFIER,
                confidence=0.99,
                matched_pattern=pattern.pattern,
                reason=description,
                confidence_multiplier=0.05  # Dramatically reduce confidence
            )

    # Check data identifier patterns (higher specificity)
    for pattern, description, cat_conf, conf_mult in DATA_IDENTIFIER_PATTERNS:
        if pattern.search(identifier):
            return IdentifierAnalysis(
                category=IdentifierCategory.DATA_IDENTIFIER,
                confidence=cat_conf,
                matched_pattern=pattern.pattern,
                reason=description,
                confidence_multiplier=conf_mult
            )

    # Check credential patterns
    for pattern, description, cat_conf, conf_mult in CREDENTIAL_PATTERNS:
        if pattern.search(identifier):
            return IdentifierAnalysis(
                category=IdentifierCategory.CREDENTIAL,
                confidence=cat_conf,
                matched_pattern=pattern.pattern,
                reason=description,
                confidence_multiplier=conf_mult
            )

    # No pattern matched - ambiguous
    return IdentifierAnalysis(
        category=IdentifierCategory.AMBIGUOUS,
        confidence=0.5,
        reason="No specific pattern matched",
        confidence_multiplier=1.0  # No adjustment
    )


def identifier_suggests_credential(identifier: str) -> bool:
    """
    Quick check if identifier name suggests it holds a credential.

    Args:
        identifier: Variable/key name

    Returns:
        True if identifier suggests credential usage
    """
    analysis = analyze_identifier(identifier)
    return analysis.category == IdentifierCategory.CREDENTIAL


def identifier_suggests_data_id(identifier: str) -> bool:
    """
    Quick check if identifier name suggests it holds a data identifier.

    Args:
        identifier: Variable/key name

    Returns:
        True if identifier suggests data identifier usage
    """
    analysis = analyze_identifier(identifier)
    return analysis.category == IdentifierCategory.DATA_IDENTIFIER
