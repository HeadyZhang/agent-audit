"""Tests for UUID format detection and false positive reduction."""

from typing import Optional

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
        ("sk-FAKE0TEST1KEY2abcd3efgh4ijkl5mnop6qrs", False, None),  # Test API key pattern
    ])
    def test_uuid_format_detection(
        self, value: str, expected_is_uuid: bool, expected_format: Optional[str]
    ):
        """Test UUID format detection accuracy."""
        result = detect_uuid_format(value)
        assert result.is_uuid == expected_is_uuid
        if expected_format:
            assert result.format_name == expected_format


class TestUUIDFalsePositiveReduction:
    """Test that UUID values are properly demoted when used as data identifiers."""

    def setup_method(self):
        self.analyzer = get_analyzer()

    @pytest.mark.parametrize("identifier,value,should_be_block,max_confidence", [
        # UUID with data identifier names - should NOT be reported as BLOCK
        ("token", "0a0d6b8c2e884134a3b48df43d54c36a", False, 0.30),
        ("sample_token", "31812a5e8d514b5f8d2fbc50fc007475", False, 0.10),
        ("scene_token", "abc123def456abc123def456abc12345", False, 0.10),
        ("data_id", "0d0700a2284e477db876c3ee1d864668", False, 0.10),

        # Test API keys - should be reported with high confidence
        ("api_key", "sk-proj-TESTKEY123456789abcdefghijklmnopqrstuvwxyz0123456789", True, 1.0),
        ("openai_key", "sk-FAKEKEY9876543210zyxwvutsrqponmlkjihgfedcba01234567", True, 1.0),
    ])
    def test_uuid_confidence_adjustment(
        self,
        identifier: str,
        value: str,
        should_be_block: bool,
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

        if not should_be_block:
            assert result.tier != "BLOCK", \
                f"UUID {value} with identifier '{identifier}' should NOT be BLOCK tier"
            assert result.confidence <= max_confidence, \
                f"Confidence {result.confidence} exceeds max {max_confidence}"
        else:
            assert result.tier == "BLOCK", \
                f"Real credential should be BLOCK tier, got {result.tier}"


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

    def test_openai_key_patterns_still_detected(self):
        """
        OpenAI API key patterns should still be detected with high confidence.
        Uses test keys that match the format but are obviously fake.
        """
        test_keys = [
            ("sk-FAKEKEY9876543210zyxwvutsrqponmlkjihgfedcba01234567", "config.py"),
            ("sk-proj-TESTKEY123456789abcdefghijklmnopqrstuvwxyz0123456789", "get_ada_v2_embedding.py"),
        ]

        for key_value, filename in test_keys:
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
                f"OpenAI key pattern not flagged as BLOCK: {result.tier}"
            assert result.confidence >= 0.90, \
                f"OpenAI key pattern has low confidence: {result.confidence}"

    def test_data_token_identifiers_reduce_confidence(self):
        """
        Variables named sample_token, scene_token, etc. should have reduced confidence.
        """
        data_token_identifiers = [
            "sample_token",
            "scene_token",
            "frame_token",
            "data_token",
            "instance_token",
            "annotation_token",
        ]

        uuid_value = "abc123def456abc123def456abc12345"

        for identifier in data_token_identifiers:
            result = self.analyzer.analyze_single_match(
                identifier=identifier,
                value=uuid_value,
                line=10,
                column=0,
                end_column=len(uuid_value),
                raw_line=f'{identifier} = "{uuid_value}"',
                file_path="test_file.py",
                pattern_name="Generic API Key",
            )

            # Should NOT be BLOCK tier
            assert result.tier != "BLOCK", \
                f"Data token identifier '{identifier}' should not trigger BLOCK"

            # Confidence should be very low
            assert result.confidence < 0.15, \
                f"Data token '{identifier}' confidence too high: {result.confidence}"

    def test_standard_uuid_format_not_flagged(self):
        """
        Standard UUID format (8-4-4-4-12) should not be flagged as credential.
        """
        standard_uuid = "550e8400-e29b-41d4-a716-446655440000"

        result = self.analyzer.analyze_single_match(
            identifier="entity_id",
            value=standard_uuid,
            line=1,
            column=0,
            end_column=len(standard_uuid),
            raw_line=f'entity_id = "{standard_uuid}"',
            file_path="models.py",
            pattern_name="Generic Token",
        )

        # Should NOT be BLOCK
        assert result.tier != "BLOCK"
        assert result.confidence < 0.30
