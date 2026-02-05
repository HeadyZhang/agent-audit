"""Tests for placeholder detection module."""

import pytest
from agent_audit.analysis.placeholder_detector import (
    is_placeholder,
    placeholder_confidence,
    PlaceholderResult,
)


class TestIsPlaceholder:
    """Tests for placeholder detection."""

    def test_empty_string_is_placeholder(self):
        """Test empty string is detected as placeholder."""
        result = is_placeholder("")
        assert result.is_placeholder is True
        assert result.confidence == 1.0

    def test_your_api_key_here(self):
        """Test 'your-api-key-here' pattern."""
        result = is_placeholder("your-api-key-here")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_your_key_in_brackets(self):
        """Test '<your-key>' pattern."""
        result = is_placeholder("<your-api-key>")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_square_bracket_placeholder(self):
        """Test '[YOUR_KEY]' pattern."""
        result = is_placeholder("[YOUR_API_KEY]")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_todo_marker(self):
        """Test 'TODO' marker."""
        result = is_placeholder("TODO: replace with real key")
        assert result.is_placeholder is True
        assert result.confidence >= 0.90

    def test_changeme_marker(self):
        """Test 'CHANGEME' marker."""
        result = is_placeholder("CHANGEME")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_xxx_placeholder(self):
        """Test 'xxx' repeated chars."""
        result = is_placeholder("xxxx")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_test_prefix(self):
        """Test 'test_' prefix."""
        result = is_placeholder("test_api_key")
        assert result.is_placeholder is True
        assert result.confidence >= 0.60

    def test_example_prefix(self):
        """Test 'example_' prefix."""
        result = is_placeholder("example_secret")
        assert result.is_placeholder is True
        assert result.confidence >= 0.80

    def test_aws_example_key(self):
        """Test AWS example access key."""
        result = is_placeholder("AKIAIOSFODNN7EXAMPLE")
        assert result.is_placeholder is True
        # This matches the _example suffix pattern which has lower confidence
        assert result.confidence >= 0.70

    def test_aws_example_secret(self):
        """Test AWS example secret key."""
        result = is_placeholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

    def test_example_com_domain(self):
        """Test example.com domain."""
        result = is_placeholder("https://example.com/api")
        assert result.is_placeholder is True
        assert result.confidence >= 0.70

    def test_localhost(self):
        """Test localhost."""
        result = is_placeholder("http://localhost:8080")
        assert result.is_placeholder is True
        assert result.confidence >= 0.60

    def test_literal_password(self):
        """Test literal 'password'."""
        result = is_placeholder("password")
        assert result.is_placeholder is True
        assert result.confidence >= 0.90

    def test_common_weak_passwords(self):
        """Test common weak password patterns."""
        weak_passwords = ["admin", "qwerty", "letmein", "abc123", "hunter2"]
        for pwd in weak_passwords:
            result = is_placeholder(pwd)
            assert result.is_placeholder is True
            assert result.confidence >= 0.80

    def test_env_var_reference(self):
        """Test environment variable reference."""
        result = is_placeholder("${API_KEY}")
        assert result.is_placeholder is True
        assert result.confidence >= 0.95

        result2 = is_placeholder("$API_KEY")
        assert result2.is_placeholder is True

    def test_very_short_values(self):
        """Test very short values are placeholders."""
        result = is_placeholder("ab")
        assert result.is_placeholder is True
        assert result.confidence >= 0.70

    def test_single_repeated_char(self):
        """Test single repeated character."""
        result = is_placeholder("aaaaaaa")
        assert result.is_placeholder is True
        assert result.confidence >= 0.90

    def test_real_api_key_not_placeholder(self):
        """Test realistic API key is not detected as placeholder."""
        # This looks like a real key (high entropy, proper format)
        result = is_placeholder("sk-proj-abc123xyz789def456ghi012jkl")
        assert result.is_placeholder is False

    def test_real_github_token_not_placeholder(self):
        """Test realistic GitHub token is not placeholder."""
        result = is_placeholder("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        assert result.is_placeholder is False


class TestPlaceholderConfidence:
    """Tests for placeholder confidence scoring."""

    def test_high_confidence_placeholder(self):
        """Test high confidence placeholders."""
        assert placeholder_confidence("your-api-key-here") >= 0.95
        assert placeholder_confidence("CHANGEME") >= 0.95
        assert placeholder_confidence("xxxx") >= 0.95

    def test_medium_confidence_placeholder(self):
        """Test medium confidence placeholders."""
        assert 0.5 <= placeholder_confidence("test_key") < 0.95

    def test_not_placeholder(self):
        """Test non-placeholders have zero confidence."""
        conf = placeholder_confidence("sk-proj-a1b2c3d4e5f6g7h8i9j0")
        assert conf == 0.0


class TestPlaceholderPatterns:
    """Tests for specific placeholder patterns."""

    @pytest.mark.parametrize("value,should_detect", [
        # Should detect
        ("your-api-key-here", True),
        ("your_api_key_here", True),
        ("<your-key>", True),
        ("<api_key>", True),
        ("[YOUR_KEY]", True),
        ("{YOUR_SECRET}", True),
        ("TODO", True),
        ("TODO:fix", True),
        ("CHANGEME", True),
        ("REPLACE_ME", True),
        ("INSERT_HERE", True),
        ("xxx", True),
        ("XXXX", True),
        ("00000", True),
        ("***", True),
        ("test_key", True),
        ("demo_secret", True),
        ("sample_token", True),
        ("example_api", True),
        ("fake_credential", True),
        ("dummy_key", True),
        ("mock_secret", True),
        ("password", True),
        ("secret", True),
        ("changeit", True),
        ("null", True),
        ("undefined", True),
        ("n/a", True),
        ("tbd", True),
        # Should NOT detect
        ("sk-proj-abc123xyz789def456", False),
        ("ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", False),
        ("AKIA1234567890ABCDEF", False),
    ])
    def test_placeholder_patterns(self, value, should_detect):
        """Test various placeholder patterns."""
        result = is_placeholder(value)
        assert result.is_placeholder == should_detect, f"Failed for value: {value}"
