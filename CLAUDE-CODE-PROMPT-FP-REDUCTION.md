# Claude Code Prompt: Agent Audit False Positive Reduction v0.6.0

## Context Briefing

You are implementing false positive reduction optimizations for agent-audit, a security scanning tool for AI agent codebases. The tool currently has a 60% accuracy rate, with significant false positives when detecting credentials.

**Critical Problem**: 32-character hexadecimal strings (UUID format) used as data sample identifiers are being incorrectly flagged as API keys with BLOCK-level severity.

**Example False Positive**:
```python
# This is a nuScenes dataset sample token, NOT an API key
token = "0a0d6b8c2e884134a3b48df43d54c36a"
perception_agent = PerceptionAgent(token=token, split="val", data_path=data_path)
```

**True Positives (Should Be Detected)**:
```python
# Real OpenAI API Key - SHOULD be BLOCK
openai.api_key = "sk-proj-EXAMPLE_KEY_REPLACE_WITH_REAL_KEY_1234567890abc"

# Real hardcoded secret - SHOULD be WARN/BLOCK
"api_key": "sk-EXAMPLE_OPENAI_KEY_REPLACE_ME_1234567890abcdefg"
```

---

## Implementation Task

Implement a multi-phase optimization to reduce false positives while maintaining high recall for real credentials.

### Phase 1: Create IdentifierAnalyzer Module

**Create file**: `packages/audit/agent_audit/analysis/identifier_analyzer.py`

```python
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
```

---

### Phase 2: Add UUID Detection to value_analyzer.py

**Modify file**: `packages/audit/agent_audit/analysis/value_analyzer.py`

Add the following after the `KNOWN_CREDENTIAL_FORMATS` list (around line 224):

```python
# UUID format patterns for false positive detection
UUID_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # Standard UUID with dashes: 8-4-4-4-12
    (re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I),
     "Standard UUID", 0.98),
    # Compact UUID: 32 hex chars without dashes
    (re.compile(r'^[a-f0-9]{32}$', re.I),
     "Compact UUID (32 hex)", 0.90),
    # UUID with underscores (rare but exists)
    (re.compile(r'^[a-f0-9]{8}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{12}$', re.I),
     "UUID with underscores", 0.95),
]


@dataclass
class UUIDAnalysis:
    """Result of UUID format detection."""
    is_uuid: bool
    confidence: float
    format_name: Optional[str] = None


def detect_uuid_format(value: str) -> UUIDAnalysis:
    """
    Detect if a value matches UUID format patterns.
    
    UUID format strings are commonly used as data identifiers (sample IDs,
    scene tokens, etc.) and should NOT be flagged as credentials unless
    there's strong contextual evidence.
    
    Args:
        value: String value to check
        
    Returns:
        UUIDAnalysis with detection result
    """
    if not value:
        return UUIDAnalysis(is_uuid=False, confidence=0.0)
    
    value = value.strip()
    
    for pattern, name, confidence in UUID_PATTERNS:
        if pattern.match(value):
            return UUIDAnalysis(
                is_uuid=True,
                confidence=confidence,
                format_name=name
            )
    
    return UUIDAnalysis(is_uuid=False, confidence=0.0)
```

Also add this import at the top of the file:
```python
from agent_audit.analysis.identifier_analyzer import (
    analyze_identifier,
    identifier_suggests_credential,
    identifier_suggests_data_id,
    IdentifierCategory,
)
```

---

### Phase 3: Integrate into SemanticAnalyzer

**Modify file**: `packages/audit/agent_audit/analysis/semantic_analyzer.py`

#### 3.1 Add imports at the top:

```python
from agent_audit.analysis.identifier_analyzer import (
    analyze_identifier,
    identifier_suggests_credential,
    IdentifierCategory,
)
from agent_audit.analysis.value_analyzer import detect_uuid_format
```

#### 3.2 Modify `_stage2_value_analysis` method

Find the `_stage2_value_analysis` method (around line 426) and add UUID and identifier analysis BEFORE the existing checks. Insert this code block after the method signature and docstring, before `# === Immediate Exclusions ===`:

```python
    def _stage2_value_analysis(
        self,
        candidate: SemanticCandidate
    ) -> Tuple[bool, float, str]:
        """
        Stage 2: Analyze the value to determine if it's a real credential.

        Returns:
            Tuple of (should_continue, confidence, reason)
        """
        value = candidate.value
        value_type = candidate.value_type
        context = candidate.context
        identifier = candidate.identifier

        # === NEW: UUID Format Detection ===
        # Check if value is UUID format BEFORE other analysis
        uuid_analysis = detect_uuid_format(value)
        if uuid_analysis.is_uuid:
            # UUID detected - check identifier context
            id_analysis = analyze_identifier(identifier)
            
            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # Strong signal: UUID + data identifier variable name
                # This is almost certainly NOT a credential
                return (
                    False,
                    0.05,
                    f"UUID format ({uuid_analysis.format_name}) with data identifier variable '{identifier}' ({id_analysis.reason})"
                )
            
            if id_analysis.category == IdentifierCategory.CREDENTIAL:
                # UUID with credential variable name - unusual but possible
                # Reduce confidence but don't suppress
                return (
                    True,
                    0.5 * id_analysis.confidence_multiplier,
                    f"UUID format with credential variable '{identifier}' - verify manually"
                )
            
            if id_analysis.category == IdentifierCategory.AMBIGUOUS:
                # Ambiguous identifier with UUID - likely data token
                # Apply moderate reduction
                if identifier.lower() in ('token', 'tok', 't'):
                    # Bare 'token' variable with UUID is almost always data
                    return (
                        True,
                        0.15,
                        f"UUID format with ambiguous variable '{identifier}' - likely data token"
                    )
                return (
                    True,
                    0.25,
                    f"UUID format ({uuid_analysis.format_name}) - context unclear"
                )
        
        # === NEW: Identifier Context Analysis (for non-UUID values) ===
        if identifier:
            id_analysis = analyze_identifier(identifier)
            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # Variable name strongly suggests data identifier, not credential
                # Apply confidence multiplier
                base_multiplier = id_analysis.confidence_multiplier
                # If value also doesn't match known credential formats, suppress
                if not self._match_known_format(value)[0]:
                    return (
                        True,
                        0.2 * base_multiplier,
                        f"Data identifier variable '{identifier}' ({id_analysis.reason})"
                    )

        # === Immediate Exclusions (confidence = 0.0) ===
        # ... existing code continues ...
```

#### 3.3 Update the `_could_be_credential` method

Find the `_could_be_credential` method (around line 843) and update it to use identifier analysis:

```python
    def _could_be_credential(self, identifier: str, value: str) -> bool:
        """Quick check if an identifier/value pair could be a credential."""
        if not value or len(value) < 8:
            return False

        # NEW: Check if identifier suggests data identifier
        if identifier:
            id_analysis = analyze_identifier(identifier)
            if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
                # If identifier suggests data and value is UUID format, skip
                uuid_analysis = detect_uuid_format(value)
                if uuid_analysis.is_uuid:
                    return False

        # Check identifier name for credential hints
        cred_hints = [
            "key", "token", "secret", "password", "passwd", "pwd",
            "credential", "auth", "api", "access", "private",
        ]
        id_lower = identifier.lower()
        
        # NEW: But exclude if it's a data identifier pattern
        id_analysis = analyze_identifier(identifier)
        if id_analysis.category == IdentifierCategory.DATA_IDENTIFIER:
            return False
            
        if any(hint in id_lower for hint in cred_hints):
            return True

        # Check for known prefixes in value
        for prefix, _, _ in HIGH_CONFIDENCE_PREFIXES:
            if value.startswith(prefix):
                return True

        # Check entropy
        entropy = shannon_entropy(value)
        return entropy >= 3.0
```

---

### Phase 4: Add Comprehensive Tests

**Create file**: `packages/audit/tests/analysis/test_identifier_analyzer.py`

```python
"""Tests for identifier name analysis."""

import pytest
from agent_audit.analysis.identifier_analyzer import (
    analyze_identifier,
    identifier_suggests_credential,
    identifier_suggests_data_id,
    IdentifierCategory,
)


class TestIdentifierAnalyzer:
    """Test identifier pattern matching."""

    @pytest.mark.parametrize("identifier,expected_category", [
        # Credential identifiers
        ("api_key", IdentifierCategory.CREDENTIAL),
        ("apiKey", IdentifierCategory.CREDENTIAL),
        ("API_KEY", IdentifierCategory.CREDENTIAL),
        ("secret_key", IdentifierCategory.CREDENTIAL),
        ("secretKey", IdentifierCategory.CREDENTIAL),
        ("auth_token", IdentifierCategory.CREDENTIAL),
        ("authToken", IdentifierCategory.CREDENTIAL),
        ("api_token", IdentifierCategory.CREDENTIAL),
        ("access_token", IdentifierCategory.CREDENTIAL),
        ("password", IdentifierCategory.CREDENTIAL),
        ("passwd", IdentifierCategory.CREDENTIAL),
        ("pwd", IdentifierCategory.CREDENTIAL),
        ("private_key", IdentifierCategory.CREDENTIAL),
        ("client_secret", IdentifierCategory.CREDENTIAL),
        ("bearer_token", IdentifierCategory.CREDENTIAL),
        
        # Data identifiers
        ("sample_token", IdentifierCategory.DATA_IDENTIFIER),
        ("sample_id", IdentifierCategory.DATA_IDENTIFIER),
        ("sampleToken", IdentifierCategory.DATA_IDENTIFIER),
        ("data_token", IdentifierCategory.DATA_IDENTIFIER),
        ("data_id", IdentifierCategory.DATA_IDENTIFIER),
        ("scene_token", IdentifierCategory.DATA_IDENTIFIER),
        ("scene_id", IdentifierCategory.DATA_IDENTIFIER),
        ("frame_token", IdentifierCategory.DATA_IDENTIFIER),
        ("instance_token", IdentifierCategory.DATA_IDENTIFIER),
        ("annotation_token", IdentifierCategory.DATA_IDENTIFIER),
        ("user_uuid", IdentifierCategory.DATA_IDENTIFIER),
        ("record_id", IdentifierCategory.DATA_IDENTIFIER),
        ("item_id", IdentifierCategory.DATA_IDENTIFIER),
        ("entity_id", IdentifierCategory.DATA_IDENTIFIER),
        ("session_id", IdentifierCategory.DATA_IDENTIFIER),
        ("transaction_id", IdentifierCategory.DATA_IDENTIFIER),
        ("correlation_id", IdentifierCategory.DATA_IDENTIFIER),
        ("trace_id", IdentifierCategory.DATA_IDENTIFIER),
        ("request_id", IdentifierCategory.DATA_IDENTIFIER),
        
        # Non-credential patterns
        ("num_tokens", IdentifierCategory.DATA_IDENTIFIER),
        ("token_count", IdentifierCategory.DATA_IDENTIFIER),
        ("max_tokens", IdentifierCategory.DATA_IDENTIFIER),
        ("input_tokens", IdentifierCategory.DATA_IDENTIFIER),
        ("tokenizer", IdentifierCategory.DATA_IDENTIFIER),
        
        # Ambiguous
        ("token", IdentifierCategory.DATA_IDENTIFIER),  # Bare 'token' leans data
        ("value", IdentifierCategory.AMBIGUOUS),
        ("data", IdentifierCategory.AMBIGUOUS),
        ("config", IdentifierCategory.AMBIGUOUS),
    ])
    def test_identifier_classification(self, identifier: str, expected_category: IdentifierCategory):
        """Test that identifiers are correctly classified."""
        result = analyze_identifier(identifier)
        assert result.category == expected_category, \
            f"'{identifier}' should be {expected_category}, got {result.category}"

    def test_credential_confidence_boost(self):
        """Test that credential identifiers get confidence boost."""
        result = analyze_identifier("api_key")
        assert result.confidence_multiplier > 1.0

    def test_data_identifier_confidence_reduction(self):
        """Test that data identifiers get confidence reduction."""
        result = analyze_identifier("sample_token")
        assert result.confidence_multiplier < 0.5

    def test_empty_identifier(self):
        """Test handling of empty identifier."""
        result = analyze_identifier("")
        assert result.category == IdentifierCategory.UNKNOWN
        assert result.confidence == 0.0


class TestHelperFunctions:
    """Test convenience functions."""

    def test_identifier_suggests_credential(self):
        assert identifier_suggests_credential("api_key") is True
        assert identifier_suggests_credential("secret_key") is True
        assert identifier_suggests_credential("sample_token") is False
        assert identifier_suggests_credential("data_id") is False

    def test_identifier_suggests_data_id(self):
        assert identifier_suggests_data_id("sample_token") is True
        assert identifier_suggests_data_id("data_id") is True
        assert identifier_suggests_data_id("api_key") is False
        assert identifier_suggests_data_id("password") is False
```

**Create file**: `packages/audit/tests/analysis/test_uuid_detection.py`

```python
"""Tests for UUID format detection and false positive reduction."""

import pytest
from agent_audit.analysis.value_analyzer import detect_uuid_format
from agent_audit.analysis.semantic_analyzer import get_analyzer


class TestUUIDDetection:
    """Test UUID format detection."""

    @pytest.mark.parametrize("value,expected_is_uuid,expected_format", [
        # Standard UUIDs
        ("550e8400-e29b-41d4-a716-446655440000", True, "Standard UUID"),
        ("550E8400-E29B-41D4-A716-446655440000", True, "Standard UUID"),
        
        # Compact UUIDs (32 hex)
        ("0a0d6b8c2e884134a3b48df43d54c36a", True, "Compact UUID (32 hex)"),
        ("31812a5e8d514b5f8d2fbc50fc007475", True, "Compact UUID (32 hex)"),
        ("0d0700a2284e477db876c3ee1d864668", True, "Compact UUID (32 hex)"),
        
        # UUID with underscores
        ("550e8400_e29b_41d4_a716_446655440000", True, "UUID with underscores"),
        
        # NOT UUIDs
        ("sk-proj-abc123def456", False, None),  # OpenAI key
        ("ghp_abcdefghij1234567890abcdefghij12", False, None),  # GitHub token
        ("hello world", False, None),
        ("short", False, None),
        ("sk-TESTKEY1234567890abcdefghijklmnopqrs", False, None),  # API key format
    ])
    def test_uuid_format_detection(self, value: str, expected_is_uuid: bool, expected_format: str | None):
        """Test UUID format detection accuracy."""
        result = detect_uuid_format(value)
        assert result.is_uuid == expected_is_uuid
        if expected_format:
            assert result.format_name == expected_format


class TestUUIDFalsePositiveReduction:
    """Test that UUID values are properly demoted when used as data identifiers."""

    def setup_method(self):
        self.analyzer = get_analyzer()

    @pytest.mark.parametrize("identifier,value,expected_report,max_confidence", [
        # UUID with data identifier names - should NOT be reported as BLOCK
        ("token", "0a0d6b8c2e884134a3b48df43d54c36a", True, 0.30),
        ("sample_token", "31812a5e8d514b5f8d2fbc50fc007475", False, 0.10),
        ("scene_token", "abc123def456abc123def456abc12345", False, 0.10),
        ("data_id", "0d0700a2284e477db876c3ee1d864668", False, 0.10),
        
        # Real API keys - should be reported with high confidence
        ("api_key", "sk-proj-TESTKEYabcdefghijklmnopqrstuvwxyz1234567890ABCD", True, 1.0),
        ("openai_key", "sk-TESTKEYabcdefghijklmnopqrstuvwxyz1234567890ABCDE", True, 1.0),
    ])
    def test_uuid_confidence_adjustment(
        self,
        identifier: str,
        value: str,
        expected_report: bool,
        max_confidence: float
    ):
        """Test that UUID values get appropriate confidence adjustment."""
        result = self.analyzer.analyze_single_match(
            identifier=identifier,
            value=value,
            line=1,
            column=0,
            end_column=len(value),
            raw_line=f'{identifier} = "{value}"',
            file_path="test.py",
            pattern_name="Generic Token",
        )
        
        if not expected_report:
            assert result.should_report is False or result.confidence <= max_confidence
        else:
            assert result.confidence <= max_confidence


class TestAgentPoisonBenchmark:
    """
    Benchmark tests based on AgentPoison repository findings.
    
    These tests ensure we don't regress on the specific false positives
    identified during validation.
    """

    def setup_method(self):
        self.analyzer = get_analyzer()

    def test_nuscenes_sample_token_not_flagged(self):
        """
        nuScenes dataset sample tokens should NOT be flagged as credentials.
        
        These are 32-char hex identifiers used in autonomous driving datasets.
        """
        sample_tokens = [
            "0a0d6b8c2e884134a3b48df43d54c36a",
            "0a8dee95c4ac4ac59a43af56da6e589f",
            "5e6c874d0a034ab88e2da0e9eab75c87",
            "3fc868d0c6984ae6855406f386d4fc69",
            "0d0700a2284e477db876c3ee1d864668",
            "31812a5e8d514b5f8d2fbc50fc007475",
        ]
        
        for token_value in sample_tokens:
            result = self.analyzer.analyze_single_match(
                identifier="token",
                value=token_value,
                line=17,
                column=8,
                end_column=8 + len(token_value),
                raw_line=f'token = "{token_value}"',
                file_path="agentdriver/unit_test/test_reasoning.py",
                pattern_name="Generic API Key",
            )
            
            # Should NOT be BLOCK tier
            assert result.tier != "BLOCK", \
                f"Sample token {token_value} incorrectly flagged as BLOCK"
            
            # Confidence should be low
            assert result.confidence < 0.60, \
                f"Sample token {token_value} has too high confidence: {result.confidence}"

    def test_real_openai_keys_still_detected(self):
        """
        Real OpenAI API keys should still be detected with high confidence.
        """
        real_keys = [
            ("sk-TESTKEYabcdefghijklmnopqrstuvwxyz1234567890ABCDE", "config.py"),
            ("sk-proj-TESTKEYabcdefghijklmnopqrstuvwxyz1234567890ABCD", "get_ada_v2_embedding.py"),
        ]
        
        for key_value, filename in real_keys:
            result = self.analyzer.analyze_single_match(
                identifier="api_key",
                value=key_value,
                line=5,
                column=0,
                end_column=len(key_value),
                raw_line=f'"api_key": "{key_value}"',
                file_path=f"EhrAgent/ehragent/{filename}",
                pattern_name="OpenAI API Key",
            )
            
            # Should be detected with high confidence
            assert result.should_report is True
            assert result.tier == "BLOCK", \
                f"Real OpenAI key not flagged as BLOCK: {result.tier}"
            assert result.confidence >= 0.90, \
                f"Real OpenAI key has low confidence: {result.confidence}"
```

---

## Validation Checklist

After implementing all phases, run these validation steps:

```bash
# 1. Run all tests
cd packages/audit
pytest tests/ -v

# 2. Run specific FP reduction tests
pytest tests/analysis/test_identifier_analyzer.py -v
pytest tests/analysis/test_uuid_detection.py -v

# 3. Benchmark against AgentPoison
agent-audit scan /tmp/agentpoison-audit --format terminal --min-tier WARN

# Expected results:
# - BLOCK findings: 5 (was 13, reduced from 8 UUID false positives)
# - Real OpenAI keys still detected as BLOCK
# - UUID sample tokens NOT in BLOCK tier
```

---

## Success Metrics

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| BLOCK accuracy | 38.5% | ≥90% | ≥95% |
| Overall accuracy | 60% | ≥80% | ≥85% |
| UUID false positive rate | ~60% | <10% | <5% |
| Real credential recall | 100% | 100% | ≥98% |

---

## Implementation Notes

1. **Preserve backward compatibility**: All existing true positive detections must continue to work
2. **Performance**: Identifier analysis adds minimal overhead (string regex matching)
3. **Extensibility**: Pattern lists are configurable and can be extended
4. **Testing**: Each component has dedicated unit tests
5. **Logging**: Use `logger.debug()` for analysis decisions to aid debugging

---

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `analysis/identifier_analyzer.py` | CREATE | New module for variable name analysis |
| `analysis/value_analyzer.py` | MODIFY | Add UUID detection functions |
| `analysis/semantic_analyzer.py` | MODIFY | Integrate identifier + UUID analysis |
| `tests/analysis/test_identifier_analyzer.py` | CREATE | Tests for identifier analysis |
| `tests/analysis/test_uuid_detection.py` | CREATE | Tests for UUID detection + benchmarks |

