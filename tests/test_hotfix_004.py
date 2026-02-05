"""
Tests for AGENT-004 TypeScript false positive hotfix.

Verifies that TypeScript-specific patterns are correctly identified as non-credentials:
- Interface property declarations (webhookSecret?: string)
- Property access expressions (state.password)
- Zod schema definitions (z.string().optional())
- Variable references in object literals

Also verifies that Generic patterns don't reach BLOCK tier without known format match.
"""

import pytest
from pathlib import Path

from agent_audit.analysis.semantic_analyzer import (
    SemanticAnalyzer,
    analyze_credential_candidate,
    GENERIC_PATTERN_NAMES,
)
from agent_audit.parsers.treesitter_parser import ValueType


@pytest.fixture
def analyzer():
    """Create a semantic analyzer instance."""
    return SemanticAnalyzer()


# ============================================================================
# TypeScript False Positive Tests
# ============================================================================

class TestTypeScriptFalsePositives:
    """Tests for TypeScript patterns that should NOT be flagged as credentials."""

    def test_ts_interface_property_string(self, analyzer):
        """TypeScript interface property 'webhookSecret?: string' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="webhookSecret",
            value="string",
            line=5,
            column=2,
            end_column=24,
            raw_line="  webhookSecret?: string;",
            file_path="/app/types.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude TS interface property, got: {result.reason}"

    def test_ts_interface_property_optional(self, analyzer):
        """TypeScript interface property 'password?: string' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="password",
            value="string",
            line=10,
            column=2,
            end_column=18,
            raw_line="  password?: string;",
            file_path="/app/models.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude TS interface property, got: {result.reason}"

    def test_ts_state_password_property_access(self, analyzer):
        """'password: state.password' should not be flagged (property access)."""
        result = analyze_credential_candidate(
            identifier="password",
            value="state.password",
            line=15,
            column=4,
            end_column=26,
            raw_line="    password: state.password,",
            file_path="/app/form.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude property access, got: {result.reason}"

    def test_ts_form_data_property_access(self, analyzer):
        """'apiKey: formData.apiKey' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="apiKey",
            value="formData.apiKey",
            line=20,
            column=4,
            end_column=25,
            raw_line="    apiKey: formData.apiKey,",
            file_path="/app/submit.ts",
            pattern_name="Generic API Key",
        )
        assert not result.should_report, f"Should exclude property access, got: {result.reason}"

    def test_ts_zod_schema_string(self, analyzer):
        """'password: z.string().optional()' should not be flagged (Zod schema)."""
        result = analyze_credential_candidate(
            identifier="password",
            value="z.string().optional()",
            line=8,
            column=4,
            end_column=30,
            raw_line="  password: z.string().optional(),",
            file_path="/app/schema.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude Zod schema, got: {result.reason}"

    def test_ts_zod_schema_min(self, analyzer):
        """'apiKey: z.string().min(10)' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="apiKey",
            value="z.string().min(10)",
            line=12,
            column=4,
            end_column=28,
            raw_line="  apiKey: z.string().min(10),",
            file_path="/app/validation.ts",
            pattern_name="Generic API Key",
        )
        assert not result.should_report, f"Should exclude Zod schema, got: {result.reason}"

    def test_ts_type_alias(self, analyzer):
        """'type ApiKey = string' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="ApiKey",
            value="string",
            line=1,
            column=5,
            end_column=21,
            raw_line="type ApiKey = string;",
            file_path="/app/types.ts",
            pattern_name="Generic API Key",
        )
        assert not result.should_report, f"Should exclude type alias, got: {result.reason}"

    def test_ts_function_param_type(self, analyzer):
        """'(password: string)' function parameter should not be flagged."""
        result = analyze_credential_candidate(
            identifier="password",
            value="string",
            line=5,
            column=15,
            end_column=30,
            raw_line="function hash(password: string): string {",
            file_path="/app/utils.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude function param type, got: {result.reason}"

    def test_ts_object_spread_variable_ref(self, analyzer):
        """Object property from variable '{ password }' should not be flagged."""
        result = analyze_credential_candidate(
            identifier="password",
            value="password",
            line=10,
            column=2,
            end_column=10,
            raw_line="  { password, username }",
            file_path="/app/auth.ts",
            pattern_name="Generic Secret/Password",
        )
        assert not result.should_report, f"Should exclude shorthand property, got: {result.reason}"


# ============================================================================
# Generic Pattern Confidence Cap Tests
# ============================================================================

class TestGenericPatternConfidenceCap:
    """Tests that Generic patterns don't reach BLOCK tier without known format."""

    def test_generic_secret_not_block_without_known_format(self, analyzer):
        """Generic Secret without known format should NOT be BLOCK tier."""
        # High entropy string that's NOT a known format
        value = "x7Kp2mQwL9vNcR5hT3jU8sYbD6fG4aE1"
        result = analyze_credential_candidate(
            identifier="SECRET_KEY",
            value=value,
            line=5,
            column=14,
            end_column=46,
            raw_line=f'SECRET_KEY = "{value}"',
            file_path="/app/config.py",
            pattern_name="Generic Secret/Password",
        )
        # Should report but NOT as BLOCK
        assert result.should_report, "High entropy secret should be reported"
        assert result.tier != "BLOCK", f"Generic pattern should not be BLOCK, got tier={result.tier}"
        assert result.confidence <= 0.70, f"Generic pattern confidence should be <= 0.70, got {result.confidence}"

    def test_generic_api_key_not_block(self, analyzer):
        """Generic API Key without known format should NOT be BLOCK tier."""
        value = "abcdef1234567890abcdef1234567890"
        result = analyze_credential_candidate(
            identifier="api_key",
            value=value,
            line=3,
            column=11,
            end_column=43,
            raw_line=f'api_key = "{value}"',
            file_path="/app/settings.py",
            pattern_name="Generic API Key",
        )
        assert result.tier != "BLOCK", f"Generic API Key should not be BLOCK, got tier={result.tier}"
        assert result.confidence <= 0.70

    def test_known_format_still_block(self, analyzer):
        """Known format (sk-proj-) should still be BLOCK tier."""
        # OpenAI key with known prefix
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="OPENAI_KEY",
            value=openai_key,
            line=1,
            column=14,
            end_column=70,
            raw_line=f'OPENAI_KEY = "{openai_key}"',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        assert result.should_report
        assert result.tier == "BLOCK", f"Known format should be BLOCK, got tier={result.tier}"
        assert result.confidence >= 0.90


# ============================================================================
# Markdown File Tests
# ============================================================================

class TestMarkdownFileConfidence:
    """Tests that markdown files have appropriately reduced confidence."""

    def test_markdown_generic_secret_not_block(self, analyzer):
        """Generic Secret in .md file should have low confidence."""
        value = "SuperSecretPassword123!"
        result = analyze_credential_candidate(
            identifier="password",
            value=value,
            line=50,
            column=0,
            end_column=len(value),
            raw_line=f'password = "{value}"',
            file_path="/app/docs/setup.md",
            pattern_name="Generic Secret/Password",
        )
        # In markdown, generic patterns should be significantly reduced
        assert result.confidence < 0.50, f"Markdown generic should have low confidence, got {result.confidence}"
        assert result.tier != "BLOCK"

    def test_markdown_known_format_reduced(self, analyzer):
        """Known format in .md file should have reduced but reasonable confidence."""
        openai_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234"
        result = analyze_credential_candidate(
            identifier="",
            value=openai_key,
            line=25,
            column=0,
            end_column=56,
            raw_line=openai_key,
            file_path="/app/docs/config.md",
            pattern_name="OpenAI Project API Key",
        )
        # Known format still gets reported but with markdown multiplier
        assert result.should_report
        # Confidence reduced by 0.40 multiplier
        assert result.confidence < 0.95


# ============================================================================
# True Positive Preservation Tests
# ============================================================================

class TestTruePositivePreservation:
    """Tests that real credentials are still detected properly."""

    def test_hardcoded_api_key_detected(self, analyzer):
        """Hardcoded API key in assignment should still be detected."""
        api_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz12345678901234"
        result = analyze_credential_candidate(
            identifier="API_KEY",
            value=api_key,
            line=5,
            column=11,
            end_column=67,
            raw_line=f'API_KEY = "{api_key}"',
            file_path="/app/config.py",
            pattern_name="OpenAI Project API Key",
        )
        assert result.should_report
        assert result.confidence >= 0.90
        assert result.format_matched is not None

    def test_github_token_detected(self, analyzer):
        """GitHub PAT should still be detected as BLOCK."""
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = analyze_credential_candidate(
            identifier="GITHUB_TOKEN",
            value=token,
            line=10,
            column=16,
            end_column=56,
            raw_line=f'GITHUB_TOKEN = "{token}"',
            file_path="/app/ci.py",
            pattern_name="GitHub Personal Access Token",
        )
        assert result.should_report
        assert result.tier == "BLOCK"
        assert result.format_matched is not None
        assert "GitHub" in result.format_matched

    def test_database_connection_string_detected(self, analyzer):
        """Database connection string with credentials should be detected."""
        conn = "postgresql://admin:RealPassword123@db.example.com/mydb"
        result = analyze_credential_candidate(
            identifier="DATABASE_URL",
            value=conn,
            line=3,
            column=15,
            end_column=70,
            raw_line=f'DATABASE_URL = "{conn}"',
            file_path="/app/production.py",
            pattern_name="Database Connection String with Credentials",
        )
        assert result.should_report
        assert result.confidence >= 0.5


# ============================================================================
# Integration with SecretScanner
# ============================================================================

class TestSecretScannerIntegration:
    """Integration tests with the full SecretScanner."""

    def test_ts_file_property_access_not_flagged(self, tmp_path):
        """TypeScript file with property access should not flag false positives."""
        from agent_audit.scanners.secret_scanner import SecretScanner

        ts_file = tmp_path / "form.ts"
        ts_file.write_text('''
// Form state with password field
const formData = {
    password: state.password,
    username: state.username,
    apiKey: formState.apiKey,
};

// Interface definition
interface Config {
    webhookSecret?: string;
    apiToken?: string;
}

// Zod schema
const schema = z.object({
    password: z.string().min(8),
    secret: z.string().optional(),
});
''')

        scanner = SecretScanner()
        results = scanner.scan(ts_file)

        # Should have no secrets (all are FPs)
        total_secrets = sum(len(r.secrets) for r in results)
        assert total_secrets == 0, f"Expected 0 secrets but found {total_secrets}"

    def test_ts_file_real_secret_still_detected(self, tmp_path):
        """TypeScript file with real hardcoded secret should be detected."""
        from agent_audit.scanners.secret_scanner import SecretScanner

        ts_file = tmp_path / "config.ts"
        ts_file.write_text('''
// Real hardcoded secret (should be detected)
const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678901234";

// False positive (property access, should NOT be detected)
const data = { password: form.password };
''')

        scanner = SecretScanner()
        results = scanner.scan(ts_file)

        # Should detect exactly 1 secret (the OpenAI key)
        total_secrets = sum(len(r.secrets) for r in results)
        assert total_secrets == 1, f"Expected 1 secret but found {total_secrets}"

        secret = results[0].secrets[0]
        assert "OpenAI" in secret.pattern_name
        assert secret.tier == "BLOCK"

    def test_md_file_generic_not_block(self, tmp_path):
        """Markdown file with generic patterns should not be BLOCK tier."""
        from agent_audit.scanners.secret_scanner import SecretScanner

        md_file = tmp_path / "setup.md"
        md_file.write_text('''
# Setup Guide

Configure your password in the settings:

```
password = "your-password-here"
```

For production, use environment variables.
''')

        scanner = SecretScanner()
        results = scanner.scan(md_file)

        # Any findings should not be BLOCK tier
        for result in results:
            for secret in result.secrets:
                assert secret.tier != "BLOCK", f"Markdown generic should not be BLOCK: {secret.pattern_name}"


# ============================================================================
# Placeholder Pattern Tests
# ============================================================================

class TestPlaceholderPatterns:
    """Tests that placeholder patterns are correctly identified."""

    def test_your_api_key_here_excluded(self, analyzer):
        """'YOUR_API_KEY_HERE' placeholder should be excluded."""
        result = analyze_credential_candidate(
            identifier="apiKey",
            value="YOUR_API_KEY_HERE",
            line=5,
            column=10,
            end_column=27,
            raw_line='apiKey = "YOUR_API_KEY_HERE"',
            file_path="/app/config.ts",
            pattern_name="Generic API Key",
        )
        assert not result.should_report, f"Placeholder should be excluded, got: {result.reason}"

    def test_placeholder_with_angle_brackets(self, analyzer):
        """'<your-secret>' placeholder should be excluded."""
        result = analyze_credential_candidate(
            identifier="secret",
            value="<your-secret>",
            line=3,
            column=10,
            end_column=23,
            raw_line='secret = "<your-secret>"',
            file_path="/app/example.ts",
            pattern_name="Generic Secret/Password",
        )
        # This is too short (13 chars) and looks like placeholder
        # Note: The < character might not be handled by placeholder detector
        # but the value is short and has low entropy
        assert result.confidence < 0.60 or not result.should_report
