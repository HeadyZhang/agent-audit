"""
Shannon entropy calculation for credential confidence scoring.

High entropy strings are more likely to be real secrets vs. placeholders.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Shannon entropy measures the information content/randomness of a string.
    Higher entropy = more random = more likely to be a real secret.

    Formula: H = -sum(p(x) * log2(p(x))) for each character x

    Reference values:
    - "aaaa": ~0.0 (no randomness)
    - "abcd": ~2.0 (low randomness)
    - "sk-proj-abc123xyz": ~3.5 (moderate randomness)
    - Random 32-char hex: ~4.0 (high randomness)
    - Random base64: ~4.5-5.5 (very high randomness)

    Args:
        s: Input string to analyze

    Returns:
        Shannon entropy value (0.0 to ~6.0 for typical strings)
    """
    if not s:
        return 0.0

    # Count character frequencies
    counter = Counter(s)
    length = len(s)

    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def normalized_entropy(s: str) -> float:
    """
    Calculate normalized Shannon entropy (0.0 to 1.0 scale).

    Normalizes by dividing by log2(len(s)), giving a value between 0 and 1
    that represents how close to maximum randomness the string is.

    Args:
        s: Input string to analyze

    Returns:
        Normalized entropy (0.0 = no randomness, 1.0 = maximum randomness)
    """
    if not s or len(s) < 2:
        return 0.0

    raw_entropy = shannon_entropy(s)
    max_entropy = math.log2(len(s))

    if max_entropy == 0:
        return 0.0

    return min(1.0, raw_entropy / max_entropy)


def entropy_suggests_secret(s: str, threshold: float = 3.5) -> bool:
    """
    Check if string entropy suggests it could be a real secret.

    Args:
        s: String to check
        threshold: Entropy threshold (default 3.5)

    Returns:
        True if entropy is above threshold (likely real secret)
    """
    return shannon_entropy(s) >= threshold


def entropy_confidence(s: str) -> float:
    """
    Convert entropy to a confidence score for credential detection.

    Maps entropy ranges to confidence scores:
    - entropy < 2.0: 0.2 (likely not a real secret)
    - entropy 2.0-3.0: 0.4 (possibly a secret)
    - entropy 3.0-4.0: 0.7 (probably a secret)
    - entropy > 4.0: 0.9 (highly likely a secret)

    Args:
        s: String to analyze

    Returns:
        Confidence score between 0.0 and 1.0
    """
    entropy = shannon_entropy(s)

    if entropy < 2.0:
        return 0.2
    elif entropy < 3.0:
        return 0.4
    elif entropy < 4.0:
        return 0.7
    else:
        return 0.9
