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
