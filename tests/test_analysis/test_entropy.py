"""Tests for entropy calculation module."""

import pytest
from agent_audit.analysis.entropy import (
    shannon_entropy,
    normalized_entropy,
    entropy_suggests_secret,
    entropy_confidence,
)


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_string(self):
        """Test entropy of empty string is 0."""
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        """Test entropy of single character string."""
        assert shannon_entropy("a") == 0.0

    def test_repeated_chars(self):
        """Test entropy of repeated characters is 0."""
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("xxxxx") == 0.0

    def test_two_different_chars(self):
        """Test entropy of alternating two chars."""
        # "ab" has 2 symbols, each with probability 0.5
        # entropy = -2 * (0.5 * log2(0.5)) = 1.0
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_four_different_chars(self):
        """Test entropy of four different chars."""
        # "abcd" has 4 symbols, each with probability 0.25
        # entropy = -4 * (0.25 * log2(0.25)) = 2.0
        assert abs(shannon_entropy("abcd") - 2.0) < 0.01

    def test_real_credential_has_high_entropy(self):
        """Test that realistic credentials have high entropy."""
        # OpenAI-like key
        key = "sk-proj-abc123xyz789def456"
        entropy = shannon_entropy(key)
        assert entropy >= 3.0

    def test_placeholder_has_low_entropy(self):
        """Test that placeholders have low entropy."""
        placeholder = "your-api-key-here"
        entropy = shannon_entropy(placeholder)
        # Not as low as repeated chars, but lower than random
        assert entropy < 4.0

    def test_random_hex_has_high_entropy(self):
        """Test that random hex strings have high entropy."""
        hex_string = "a1b2c3d4e5f6789012345678"
        entropy = shannon_entropy(hex_string)
        assert entropy >= 3.5


class TestNormalizedEntropy:
    """Tests for normalized entropy calculation."""

    def test_empty_string(self):
        """Test normalized entropy of empty string."""
        assert normalized_entropy("") == 0.0

    def test_single_char(self):
        """Test normalized entropy of single char."""
        assert normalized_entropy("a") == 0.0

    def test_range_is_zero_to_one(self):
        """Test that normalized entropy is between 0 and 1."""
        test_strings = [
            "aaaa",
            "abcd",
            "sk-proj-abc123xyz",
            "this is a test string with various characters!",
        ]
        for s in test_strings:
            norm = normalized_entropy(s)
            assert 0.0 <= norm <= 1.0

    def test_max_entropy_string(self):
        """Test string approaching maximum entropy."""
        # Each character unique gives high normalized entropy
        unique = "abcdefghijklmnop"
        norm = normalized_entropy(unique)
        assert norm > 0.8


class TestEntropySuggestsSecret:
    """Tests for secret suggestion based on entropy."""

    def test_high_entropy_suggests_secret(self):
        """Test high entropy strings suggest secrets."""
        assert entropy_suggests_secret("sk-proj-a1b2c3d4e5f6789abcdef") is True

    def test_low_entropy_does_not_suggest_secret(self):
        """Test low entropy strings don't suggest secrets."""
        assert entropy_suggests_secret("aaaa") is False
        assert entropy_suggests_secret("xxxx") is False

    def test_custom_threshold(self):
        """Test custom threshold works."""
        medium = "test1234"
        # With low threshold, it might be a secret
        # With high threshold, it won't be
        assert entropy_suggests_secret(medium, threshold=2.0) is True
        assert entropy_suggests_secret(medium, threshold=5.0) is False


class TestEntropyConfidence:
    """Tests for entropy-based confidence scoring."""

    def test_low_entropy_gives_low_confidence(self):
        """Test low entropy gives low confidence."""
        conf = entropy_confidence("aaa")
        assert conf <= 0.3

    def test_high_entropy_gives_high_confidence(self):
        """Test high entropy gives high confidence."""
        conf = entropy_confidence("a1b2c3d4e5f6g7h8i9j0k1l2m3n4")
        assert conf >= 0.7

    def test_confidence_range(self):
        """Test confidence is always in valid range."""
        test_strings = [
            "",
            "a",
            "aaaa",
            "test",
            "sk-proj-abc123",
            "a" * 100,
        ]
        for s in test_strings:
            conf = entropy_confidence(s)
            assert 0.0 <= conf <= 1.0
