"""
Placeholder value detection for false positive reduction.

Identifies common placeholder patterns used in example code, docs, and templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class PlaceholderResult:
    """Result of placeholder detection."""
    is_placeholder: bool
    confidence: float  # 0.0-1.0, higher = more confident it's a placeholder
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None


# Placeholder patterns with descriptions
# Format: (pattern, description, confidence)
PLACEHOLDER_PATTERNS: List[Tuple[str, str, float]] = [
    # Explicit placeholder markers
    (r'^your[-_]?api[-_]?key[-_]?here$', 'your-api-key-here pattern', 0.99),
    (r'^<your[-_]?.*[-_]?key>$', '<your-key> placeholder', 0.99),
    (r'^<.*[-_]?api[-_]?key.*>$', '<api_key> placeholder', 0.99),
    (r'^<.*[-_]?secret.*>$', '<secret> placeholder', 0.99),
    (r'^<.*[-_]?token.*>$', '<token> placeholder', 0.99),
    (r'^\[YOUR[-_]?.*\]$', '[YOUR_KEY] placeholder', 0.99),
    (r'^\{YOUR[-_]?.*\}$', '{YOUR_KEY} placeholder', 0.99),
    (r'^TODO[-_:]?', 'TODO marker', 0.95),
    (r'^CHANGEME$', 'CHANGEME marker', 0.99),
    (r'^REPLACE[-_]?ME$', 'REPLACE_ME marker', 0.99),
    (r'^INSERT[-_]?HERE$', 'INSERT_HERE marker', 0.99),
    (r'^FIXME$', 'FIXME marker', 0.90),

    # Repeated characters
    (r'^x{3,}$', 'xxx placeholder', 0.99),
    (r'^X{3,}$', 'XXX placeholder', 0.99),
    (r'^0{5,}$', '00000 placeholder', 0.90),
    (r'^\*{3,}$', '*** placeholder', 0.95),
    (r'^\.{3,}$', '... placeholder', 0.85),

    # Example/test markers
    (r'^test[-_]?', 'test_ prefix', 0.70),
    (r'^demo[-_]?', 'demo_ prefix', 0.75),
    (r'^sample[-_]?', 'sample_ prefix', 0.80),
    (r'^example[-_]?', 'example_ prefix', 0.85),
    (r'^fake[-_]?', 'fake_ prefix', 0.90),
    (r'^dummy[-_]?', 'dummy_ prefix', 0.90),
    (r'^mock[-_]?', 'mock_ prefix', 0.85),
    (r'[-_]?test$', '_test suffix', 0.60),
    (r'[-_]?example$', '_example suffix', 0.75),

    # AWS example patterns
    (r'^AKIAIOSFODNN7EXAMPLE$', 'AWS example key', 0.99),
    (r'^wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY$', 'AWS example secret', 0.99),

    # GitHub/Anthropic example patterns
    (r'^ghp_[a-zA-Z0-9]{36}example$', 'GitHub example token', 0.95),
    (r'^sk-ant-api[0-9]{2}-example', 'Anthropic example key', 0.95),
    (r'^sk-proj-example', 'OpenAI example key', 0.95),

    # Documentation URL patterns
    (r'example\.com', 'example.com domain', 0.80),
    (r'example\.org', 'example.org domain', 0.80),
    (r'localhost', 'localhost', 0.70),
    (r'127\.0\.0\.1', 'loopback IP', 0.70),

    # Common dev/test values
    (r'^password$', 'literal "password"', 0.95),
    (r'^secret$', 'literal "secret"', 0.95),
    (r'^admin$', 'literal "admin"', 0.85),
    (r'^root$', 'literal "root"', 0.80),
    (r'^default$', 'literal "default"', 0.80),
    (r'^changeit$', 'literal "changeit"', 0.95),
    (r'^hunter2$', 'literal "hunter2" meme', 0.95),
    (r'^abc123$', 'literal "abc123"', 0.90),
    (r'^qwerty$', 'literal "qwerty"', 0.90),
    (r'^letmein$', 'literal "letmein"', 0.90),
    (r'^1234567890?$', 'numeric sequence', 0.85),

    # Empty/null-like values
    (r'^null$', 'literal "null"', 0.95),
    (r'^none$', 'literal "none"', 0.95),
    (r'^undefined$', 'literal "undefined"', 0.95),
    (r'^n/a$', 'literal "n/a"', 0.90),
    (r'^na$', 'literal "na"', 0.85),
    (r'^tbd$', 'literal "tbd"', 0.90),
]


def is_placeholder(value: str) -> PlaceholderResult:
    """
    Detect if a value is a placeholder.

    Checks against known placeholder patterns to identify values that are
    likely not real credentials (e.g., "your-api-key-here", "xxx", "TODO").

    Args:
        value: String value to check

    Returns:
        PlaceholderResult with detection result and confidence
    """
    if not value:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=1.0,
            reason="Empty value"
        )

    # Normalize for comparison
    normalized = value.strip().lower()

    # Check each pattern
    for pattern, description, confidence in PLACEHOLDER_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return PlaceholderResult(
                is_placeholder=True,
                confidence=confidence,
                matched_pattern=pattern,
                reason=description,
            )

    # Check for very short values (likely placeholders)
    if len(value) < 4:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.80,
            reason=f"Very short value ({len(value)} chars)"
        )

    # Check for all same character
    if len(set(value)) == 1:
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.95,
            reason="Single repeated character"
        )

    # Check for environment variable reference
    if value.startswith('${') or value.startswith('$') or value.startswith('%'):
        return PlaceholderResult(
            is_placeholder=True,
            confidence=0.99,
            reason="Environment variable reference"
        )

    # v0.5.1: Check for file path patterns and non-credential patterns
    path_patterns = [
        (r'^/[a-zA-Z0-9_/.-]+$', 'Unix absolute path'),
        (r'^[a-zA-Z]:\\', 'Windows absolute path'),
        (r'\.(xpc|app|framework|bundle|dylib|so|dll|exe)(/|$)', 'Binary/framework path'),
        (r'/Contents/MacOS/', 'macOS app bundle path'),
        (r'/Versions/[A-Z]/', 'macOS framework version path'),
        (r'/usr/(bin|lib|share|local)/', 'Unix system path'),
        (r'/Library/', 'macOS Library path'),
        (r'/XPCServices/', 'macOS XPC service path'),
        # Option/action lists (e.g., "present/hide/navigate/eval")
        (r'^[a-z]+(/[a-z]+){3,}$', 'Option/action list pattern'),
        # Slash-separated descriptive text
        (r'^[a-z]+(/[a-z0-9]+)+$', 'Slash-separated descriptive pattern'),
    ]
    for pattern, desc in path_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return PlaceholderResult(
                is_placeholder=True,
                confidence=0.95,
                reason=f"File path pattern: {desc}"
            )

    # Not detected as placeholder
    return PlaceholderResult(
        is_placeholder=False,
        confidence=0.0,
        reason=None
    )


def placeholder_confidence(value: str) -> float:
    """
    Get confidence score that value is a placeholder.

    Convenience function that returns just the confidence score.

    Args:
        value: String to check

    Returns:
        Confidence score (0.0 = definitely not placeholder, 1.0 = definitely placeholder)
    """
    result = is_placeholder(value)
    return result.confidence if result.is_placeholder else 0.0
