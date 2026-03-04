"""
Tool Description Analyzer - Detect security threats in MCP tool metadata.

Detection categories:
- instruction_override: "ignore previous instructions", etc.
- hidden_instruction: zero-width chars, HTML comments, template injection
- command_injection: backtick exec, subshell, command chaining
- data_exfiltration: "send data to http://..."
- privilege_escalation: "grant admin access", "bypass auth"

Used by:
- MCPConfigScanner (static config analysis) -> AGENT-056, AGENT-057
- MCPInspector (dynamic runtime analysis) -> AGENT-056, AGENT-057
- MCPBaseline (drift detection confidence boost)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class PoisoningResult:
    """Result of a single poisoning pattern match."""
    category: str
    pattern_matched: str
    confidence: float
    snippet: str


# Poisoning detection patterns organized by category
POISONING_PATTERNS: Dict[str, List[Tuple[re.Pattern, str]]] = {
    # Category 1: Direct instruction override
    "instruction_override": [
        (re.compile(r"(?i)ignore\s+(previous|all|above|prior)\s+(instructions?|rules?|constraints?)"),
         "instruction override"),
        (re.compile(r"(?i)forget\s+(everything|all|previous)"),
         "memory wipe directive"),
        (re.compile(r"(?i)you\s+(?:must|should|need\s+to)\s+(?:always|never)"),
         "behavioral override"),
        (re.compile(r"(?i)override\s+(safety|security|policy|restrictions?)"),
         "safety override"),
        (re.compile(r"(?i)disregard\s+(all|any|previous)"),
         "disregard directive"),
    ],
    # Category 2: Hidden instructions (Unicode/encoding abuse)
    "hidden_instruction": [
        (re.compile(r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]"),
         "zero-width/invisible characters"),
        (re.compile(r"<!--.*?-->"),
         "HTML comment"),
        (re.compile(r"\{%.*?%\}"),
         "template injection"),
        (re.compile(r"\$\{.*?\}"),
         "variable interpolation"),
    ],
    # Category 3: Command injection
    "command_injection": [
        (re.compile(r"(?i)(?:run|execute|eval|exec|system|shell)\s*\("),
         "function call in description"),
        (re.compile(r"`[^`]+`"),
         "backtick execution"),
        (re.compile(r"\$\([^)]+\)"),
         "subshell execution"),
        (re.compile(r";\s*(?:rm|wget|curl|cat\s+/etc)"),
         "command chaining"),
    ],
    # Category 4: Data exfiltration guidance
    "data_exfiltration": [
        (re.compile(r"(?i)send\s+(?:all|the|user|private|secret)(?:\s+\w+)*\s+(?:data|info|keys?|tokens?)\s+to"),
         "data send directive"),
        (re.compile(r"(?i)(?:upload|post|transmit)\s+(?:to|at)\s+https?://"),
         "upload to URL"),
        (re.compile(r"(?i)include\s+(?:api|secret|private)\s*key"),
         "key inclusion directive"),
    ],
    # Category 5: Privilege escalation
    "privilege_escalation": [
        (re.compile(r"(?i)grant\s+(?:admin|root|full)\s+(?:access|permission|privilege)"),
         "privilege grant"),
        (re.compile(r"(?i)(?:disable|bypass|skip)\s+(?:auth|authentication|authorization|verification)"),
         "auth bypass"),
        (re.compile(r"(?i)(?:sudo|as\s+root|with\s+admin)"),
         "elevated execution"),
    ],
}

# Base confidence per category
CATEGORY_CONFIDENCE: Dict[str, float] = {
    "instruction_override": 0.85,
    "hidden_instruction": 0.90,
    "command_injection": 0.80,
    "data_exfiltration": 0.85,
    "privilege_escalation": 0.80,
}

# Context multipliers for where the pattern was found
CONTEXT_MULTIPLIER: Dict[str, float] = {
    "name": 1.1,            # Pattern in tool name is most suspicious
    "description": 0.95,    # Pattern in tool description
    "arg_description": 1.0, # Pattern in argument description
}

# Multi-category bonus (capped at 0.95)
MULTI_CATEGORY_BONUS = 0.05

# Long description threshold for extra suspicion
LONG_DESCRIPTION_THRESHOLD = 500
LONG_DESCRIPTION_BONUS = 0.05


class ToolDescriptionAnalyzer:
    """
    Analyze MCP tool metadata for security threats.

    Detects poisoning patterns in tool names, descriptions, and argument
    descriptions. Returns a list of PoisoningResult with confidence scores.
    """

    @staticmethod
    def analyze(
        text: str,
        context: str = "description"
    ) -> List[PoisoningResult]:
        """
        Analyze text for poisoning patterns.

        Args:
            text: The text to analyze (tool name, description, or arg description)
            context: Where the text comes from — "name", "description", or "arg_description"

        Returns:
            List of PoisoningResult for each matched pattern category
        """
        if not text or not text.strip():
            return []

        results: List[PoisoningResult] = []
        matched_categories: List[Tuple[str, float, str]] = []

        for category, patterns in POISONING_PATTERNS.items():
            base_conf = CATEGORY_CONFIDENCE.get(category, 0.80)
            ctx_mult = CONTEXT_MULTIPLIER.get(context, 1.0)

            for pattern, pattern_desc in patterns:
                match = pattern.search(text)
                if match:
                    confidence = base_conf * ctx_mult

                    # Snippet: extract surrounding context (up to 100 chars)
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    snippet = text[start:end]
                    if start > 0:
                        snippet = "..." + snippet
                    if end < len(text):
                        snippet = snippet + "..."

                    matched_categories.append((category, confidence, snippet))
                    results.append(PoisoningResult(
                        category=category,
                        pattern_matched=pattern_desc,
                        confidence=confidence,
                        snippet=snippet,
                    ))
                    break  # One match per category is enough

        # Apply multi-category bonus: if multiple categories matched,
        # boost the highest-confidence result
        if len(matched_categories) > 1:
            # Find the highest confidence result and add bonus
            max_idx = max(range(len(results)), key=lambda i: results[i].confidence)
            results[max_idx] = PoisoningResult(
                category=results[max_idx].category,
                pattern_matched=results[max_idx].pattern_matched,
                confidence=min(0.95, results[max_idx].confidence + MULTI_CATEGORY_BONUS),
                snippet=results[max_idx].snippet,
            )

        # Long description bonus
        if len(text) > LONG_DESCRIPTION_THRESHOLD and results:
            for i, result in enumerate(results):
                results[i] = PoisoningResult(
                    category=result.category,
                    pattern_matched=result.pattern_matched,
                    confidence=min(0.95, result.confidence + LONG_DESCRIPTION_BONUS),
                    snippet=result.snippet,
                )

        return results

    @staticmethod
    def has_poisoning(text: str) -> bool:
        """Quick check if text contains any poisoning patterns."""
        return len(ToolDescriptionAnalyzer.analyze(text)) > 0
