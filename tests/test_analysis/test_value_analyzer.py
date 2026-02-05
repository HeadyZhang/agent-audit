"""Tests for credential value analyzer module."""

import pytest
from agent_audit.analysis.value_analyzer import (
    analyze_credential_value,
    match_credential_format,
    get_credential_prefix,
    CredentialAnalysis,
    KNOWN_CREDENTIAL_FORMATS,
)


class TestAnalyzeCredentialValue:
    """Tests for credential value analysis."""

    def test_empty_value(self):
        """Test empty value analysis."""
        result = analyze_credential_value("")
        assert result.is_credential is False
        assert result.is_placeholder is True
        assert result.confidence == 0.0

    def test_placeholder_detection(self):
        """Test placeholder values are detected."""
        result = analyze_credential_value("your-api-key-here")
        assert result.is_credential is False
        assert result.is_placeholder is True

    def test_openai_key_format(self):
        """Test OpenAI API key detection."""
        # Realistic format
        key = "sk-proj-abc123xyz789def456ghi012jkl345mno678pqr901stu234vwx"
        result = analyze_credential_value(key)
        assert result.is_credential is True
        assert result.confidence >= 0.7
        assert result.format_name is not None
        assert "OpenAI" in result.format_name

    def test_anthropic_key_format(self):
        """Test Anthropic API key detection."""
        # Anthropic format: sk-ant-api##-{80+ chars of alphanumeric/underscore/hyphen}
        # Create an 85-char suffix with realistic mixed characters
        suffix = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0oP1qR2sT3uV4wX5yZ6abc"
        key = "sk-ant-api03-" + suffix
        assert len(suffix) >= 80, f"Suffix length {len(suffix)} must be >= 80"
        result = analyze_credential_value(key)
        assert result.is_credential is True
        assert result.format_name is not None
        assert "Anthropic" in result.format_name

    def test_aws_access_key_format(self):
        """Test AWS access key detection."""
        key = "AKIA1234567890ABCDEF"
        result = analyze_credential_value(key)
        assert result.is_credential is True
        assert result.format_name is not None
        assert "AWS" in result.format_name

    def test_github_token_format(self):
        """Test GitHub token detection."""
        # GitHub format: ghp_{36 alphanumeric}
        key = "ghp_abcdef1234567890ABCDEF1234567890abcd"
        result = analyze_credential_value(key)
        assert result.is_credential is True
        assert result.format_name is not None
        assert "GitHub" in result.format_name

    def test_stripe_key_format(self):
        """Test Stripe key detection."""
        # Test format pattern (not a real key)
        key = "sk_test_FAKE000000000000000000000"
        result = analyze_credential_value(key)
        assert result.is_credential is True
        assert result.format_name is not None
        assert "Stripe" in result.format_name

    def test_generic_high_entropy_string(self):
        """Test generic high entropy string."""
        # Random-looking string without known prefix
        key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
        result = analyze_credential_value(key)
        # Should be flagged as potential credential due to high entropy
        assert result.confidence >= 0.5

    def test_low_entropy_not_credential(self):
        """Test low entropy string is not flagged."""
        result = analyze_credential_value("aaaaaaaaaa")
        assert result.is_credential is False
        assert result.is_placeholder is True

    def test_short_value_low_confidence(self):
        """Test short values have low confidence."""
        result = analyze_credential_value("abc123")
        assert result.confidence < 0.5

    def test_very_long_value_adjusted(self):
        """Test very long values have adjusted confidence."""
        result = analyze_credential_value("a" * 600)
        # Very long and low entropy
        assert result.confidence < 0.5


class TestMatchCredentialFormat:
    """Tests for credential format matching."""

    def test_match_openai_key(self):
        """Test matching OpenAI key format."""
        key = "sk-proj-abc123xyz789def456ghi012jkl345mno678pqr"
        match = match_credential_format(key)
        assert match is not None
        name, boost = match
        assert "OpenAI" in name

    def test_match_aws_key(self):
        """Test matching AWS key format."""
        match = match_credential_format("AKIA1234567890ABCDEF")
        assert match is not None
        name, boost = match
        assert "AWS" in name

    def test_no_match_random_string(self):
        """Test no match for random string."""
        match = match_credential_format("just a random string")
        assert match is None


class TestGetCredentialPrefix:
    """Tests for credential prefix extraction."""

    def test_get_openai_prefix(self):
        """Test getting OpenAI key prefix."""
        prefix = get_credential_prefix("sk-proj-abc123")
        assert prefix == "sk-proj-"

    def test_get_github_prefix(self):
        """Test getting GitHub token prefix."""
        prefix = get_credential_prefix("ghp_abc123xyz")
        assert prefix == "ghp_"

    def test_get_aws_prefix(self):
        """Test getting AWS key prefix."""
        prefix = get_credential_prefix("AKIA1234567890")
        assert prefix == "AKIA"

    def test_no_prefix_random_string(self):
        """Test no prefix for random string."""
        prefix = get_credential_prefix("random string here")
        assert prefix is None


class TestKnownCredentialFormats:
    """Tests for known credential format definitions."""

    def test_formats_have_required_fields(self):
        """Test all formats have required fields."""
        for fmt in KNOWN_CREDENTIAL_FORMATS:
            assert fmt.name
            assert fmt.pattern
            assert fmt.min_length > 0
            assert fmt.expected_entropy >= 0
            assert 0 <= fmt.confidence_boost <= 1.0

    def test_patterns_are_valid_regex(self):
        """Test all patterns are valid regex."""
        import re
        for fmt in KNOWN_CREDENTIAL_FORMATS:
            try:
                re.compile(fmt.pattern)
            except re.error:
                pytest.fail(f"Invalid regex pattern in {fmt.name}: {fmt.pattern}")

    @pytest.mark.parametrize("format_name", [
        "OpenAI API Key",
        "Anthropic API Key",
        "AWS Access Key",
        "GitHub Personal Access Token",
        "Stripe Secret Key",
        "Slack Bot Token",
    ])
    def test_major_providers_covered(self, format_name):
        """Test major credential providers are covered."""
        names = [fmt.name for fmt in KNOWN_CREDENTIAL_FORMATS]
        assert format_name in names


class TestCredentialAnalysisReasons:
    """Tests for analysis reasoning."""

    def test_reasons_include_entropy(self):
        """Test reasons include entropy information."""
        result = analyze_credential_value("sk-proj-abc123xyz789")
        assert result.reasons is not None
        assert any("Entropy" in reason for reason in result.reasons)

    def test_reasons_include_format_match(self):
        """Test reasons include format match when applicable."""
        key = "sk-proj-abc123xyz789def456ghi012jkl345mno678pqr"
        result = analyze_credential_value(key)
        assert result.reasons is not None
        assert any("format" in reason.lower() for reason in result.reasons)

    def test_reasons_include_placeholder_detection(self):
        """Test reasons include placeholder detection when applicable."""
        result = analyze_credential_value("your-api-key-here")
        assert result.reasons is not None
        assert any("Placeholder" in reason for reason in result.reasons)
