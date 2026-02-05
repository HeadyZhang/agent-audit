"""
Confidence adjustment matrix for credential detection.

Provides fine-grained confidence adjustment rules based on multiple
contextual signals, enabling precise control over false positive rates
while maintaining high recall for real credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class AdjustmentDirection(Enum):
    """Direction of confidence adjustment."""
    INCREASE = "increase"  # Increase confidence (more likely credential)
    DECREASE = "decrease"  # Decrease confidence (less likely credential)


@dataclass
class ConfidenceAdjustment:
    """
    A confidence adjustment rule.
    
    Attributes:
        condition: Identifier for the condition (e.g., 'uuid_format')
        multiplier: Factor to multiply base confidence by
        description: Human-readable description
        priority: Application priority (lower = applied first)
        direction: Whether this increases or decreases confidence
    """
    condition: str
    multiplier: float
    description: str
    priority: int
    direction: AdjustmentDirection = AdjustmentDirection.DECREASE
    
    def __post_init__(self):
        """Validate multiplier value."""
        if self.multiplier < 0:
            raise ValueError(f"Multiplier must be non-negative, got {self.multiplier}")


# Confidence adjustment rules ordered by priority
CONFIDENCE_ADJUSTMENTS: List[ConfidenceAdjustment] = [
    # === Positive Adjustments (Increase Confidence) ===
    ConfidenceAdjustment(
        condition="known_format_prefix",
        multiplier=1.3,
        description="Matches known credential prefix (sk-, ghp_, AKIA)",
        priority=1,
        direction=AdjustmentDirection.INCREASE,
    ),
    ConfidenceAdjustment(
        condition="credential_variable_name",
        multiplier=1.2,
        description="Variable name contains api_key, secret, password",
        priority=2,
        direction=AdjustmentDirection.INCREASE,
    ),
    ConfidenceAdjustment(
        condition="env_file_context",
        multiplier=1.2,
        description="Found in .env file",
        priority=3,
        direction=AdjustmentDirection.INCREASE,
    ),
    ConfidenceAdjustment(
        condition="high_entropy_value",
        multiplier=1.15,
        description="Value has high entropy (>4.0)",
        priority=4,
        direction=AdjustmentDirection.INCREASE,
    ),
    ConfidenceAdjustment(
        condition="production_context",
        multiplier=1.1,
        description="Found in production config file",
        priority=5,
        direction=AdjustmentDirection.INCREASE,
    ),
    
    # === Negative Adjustments (Decrease Confidence) ===
    ConfidenceAdjustment(
        condition="uuid_format",
        multiplier=0.2,
        description="Pure UUID format without credential context",
        priority=1,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="data_identifier_name",
        multiplier=0.15,
        description="Variable name suggests data identifier (sample_, data_, _id)",
        priority=2,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="test_file_generic_pattern",
        multiplier=0.4,
        description="Generic pattern in test file",
        priority=3,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="short_random_string",
        multiplier=0.5,
        description="Short random string (<20 chars) with low entropy",
        priority=4,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="placeholder_detected",
        multiplier=0.1,
        description="Value matches placeholder pattern",
        priority=5,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="documentation_context",
        multiplier=0.3,
        description="Found in documentation or comment",
        priority=6,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="example_file_path",
        multiplier=0.35,
        description="File path contains example/sample/demo",
        priority=7,
        direction=AdjustmentDirection.DECREASE,
    ),
    ConfidenceAdjustment(
        condition="non_credential_token_name",
        multiplier=0.05,
        description="Variable name like num_tokens, token_count (not credential)",
        priority=8,
        direction=AdjustmentDirection.DECREASE,
    ),
]

# Pre-build lookup dictionary for quick condition access
_ADJUSTMENT_BY_CONDITION = {adj.condition: adj for adj in CONFIDENCE_ADJUSTMENTS}


def get_adjustment(condition: str) -> Optional[ConfidenceAdjustment]:
    """
    Get the adjustment rule for a specific condition.
    
    Args:
        condition: The condition identifier
        
    Returns:
        ConfidenceAdjustment if found, None otherwise
    """
    return _ADJUSTMENT_BY_CONDITION.get(condition)


def calculate_final_confidence(
    base_confidence: float,
    adjustments: List[Tuple[str, float]],
    is_known_format: bool = False,
    min_confidence: float = 0.0,
    max_confidence: float = 1.0,
) -> Tuple[float, List[str]]:
    """
    Calculate final confidence score with adjustment rules applied.
    
    Rules:
    1. Known format credentials have minimum confidence of 0.75
    2. Generic format detections have maximum confidence of 0.70
    3. Multiple adjustment factors are multiplied together
    4. Final result is clamped to [min_confidence, max_confidence]
    
    Args:
        base_confidence: Starting confidence score (0.0-1.0)
        adjustments: List of (condition, multiplier) tuples to apply
        is_known_format: Whether the value matches a known credential format
        min_confidence: Minimum allowed confidence (default 0.0)
        max_confidence: Maximum allowed confidence (default 1.0)
        
    Returns:
        Tuple of (final_confidence, list_of_applied_adjustments)
    """
    result = base_confidence
    applied: List[str] = []
    
    # Sort adjustments by priority (from lookup table)
    sorted_adjustments = sorted(
        adjustments,
        key=lambda x: _ADJUSTMENT_BY_CONDITION.get(x[0], ConfidenceAdjustment(
            condition=x[0], multiplier=1.0, description="", priority=999,
        )).priority
    )
    
    # Apply each adjustment
    for condition, multiplier in sorted_adjustments:
        if multiplier != 1.0:  # Skip no-op adjustments
            result *= multiplier
            adj = _ADJUSTMENT_BY_CONDITION.get(condition)
            if adj:
                applied.append(f"{adj.description} (×{multiplier:.2f})")
            else:
                applied.append(f"{condition} (×{multiplier:.2f})")
    
    # Apply format-based constraints
    if is_known_format:
        # Known formats have a confidence floor
        result = max(result, 0.75)
        if result == 0.75 and base_confidence < 0.75:
            applied.append("Known format minimum applied (0.75)")
    else:
        # Generic detections have a confidence ceiling
        if result > 0.70:
            result = 0.70
            applied.append("Generic format maximum applied (0.70)")
    
    # Clamp to valid range
    result = max(min_confidence, min(max_confidence, result))
    
    return (result, applied)


def should_suppress(
    confidence: float,
    is_known_format: bool,
    threshold: float = 0.50,
) -> bool:
    """
    Determine if a finding should be suppressed based on confidence.
    
    Args:
        confidence: The calculated confidence score
        is_known_format: Whether the value matches a known credential format
        threshold: Confidence threshold below which to suppress (default 0.50)
        
    Returns:
        True if the finding should be suppressed
    """
    # Never suppress known format matches above a lower threshold
    if is_known_format:
        return confidence < 0.30
    
    return confidence < threshold


def get_tier_from_confidence(
    confidence: float,
    is_known_format: bool = False,
) -> str:
    """
    Map confidence score to reporting tier.
    
    Tiers:
    - BLOCK: High confidence (≥0.85) - definitely a credential
    - WARN: Medium confidence (0.50-0.85) - likely a credential, needs review
    - INFO: Low confidence (0.30-0.50) - possible credential, low priority
    - SUPPRESSED: Very low confidence (<0.30) - probably not a credential
    
    Args:
        confidence: The calculated confidence score
        is_known_format: Whether the value matches a known credential format
        
    Returns:
        Tier string: 'BLOCK', 'WARN', 'INFO', or 'SUPPRESSED'
    """
    # Known formats get boosted tier assignment
    if is_known_format:
        if confidence >= 0.75:
            return "BLOCK"
        if confidence >= 0.40:
            return "WARN"
        if confidence >= 0.20:
            return "INFO"
        return "SUPPRESSED"
    
    # Generic detections use stricter thresholds
    if confidence >= 0.85:
        return "BLOCK"
    if confidence >= 0.50:
        return "WARN"
    if confidence >= 0.30:
        return "INFO"
    return "SUPPRESSED"


# Utility functions for common adjustment scenarios

def get_uuid_adjustment() -> Tuple[str, float]:
    """Get the standard UUID format adjustment."""
    return ("uuid_format", 0.2)


def get_data_identifier_adjustment() -> Tuple[str, float]:
    """Get the standard data identifier adjustment."""
    return ("data_identifier_name", 0.15)


def get_placeholder_adjustment() -> Tuple[str, float]:
    """Get the standard placeholder adjustment."""
    return ("placeholder_detected", 0.1)


def get_known_format_adjustment() -> Tuple[str, float]:
    """Get the standard known format boost."""
    return ("known_format_prefix", 1.3)


def get_test_file_adjustment() -> Tuple[str, float]:
    """Get the standard test file adjustment."""
    return ("test_file_generic_pattern", 0.4)
