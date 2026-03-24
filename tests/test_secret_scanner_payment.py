"""Tests for agent payment credential detection patterns in SecretScanner."""

import pytest
import shutil
import tempfile
from pathlib import Path
from agent_audit.scanners.secret_scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


@pytest.fixture
def production_dir():
    """Create a temp directory without 'test' in the path to avoid false positive filtering."""
    dir_path = tempfile.mkdtemp(prefix='production_scan_')
    yield Path(dir_path)
    shutil.rmtree(dir_path, ignore_errors=True)


class TestAgentJWTDetection:
    """Test Agent JWT token detection."""

    def test_agent_jwt_detected(self, scanner, production_dir):
        """Agent JWT with proper prefix should trigger HIGH."""
        test_file = production_dir / "config.py"
        test_file.write_text(
            'AGENT_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        jwt_secrets = [s for s in secrets if "JWT" in s.pattern_name or "Agent" in s.pattern_name]
        assert len(jwt_secrets) >= 1, f"Expected Agent JWT detection, got: {[s.pattern_name for s in secrets]}"

    def test_agent_token_variant(self, scanner, production_dir):
        """AGENT_TOKEN variant should also trigger."""
        test_file = production_dir / "agent_config.py"
        test_file.write_text(
            'AGENT_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhZ2VudCJ9.signature_value_here\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        assert len(secrets) >= 1


class TestBlockchainPrivateKeyDetection:
    """Test blockchain private key detection."""

    def test_deployer_pk_detected(self, scanner, production_dir):
        """DEPLOYER_PK with 0x + 64 hex should trigger HIGH."""
        test_file = production_dir / ".env"
        test_file.write_text(
            'DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        pk_secrets = [s for s in secrets if "Private Key" in s.pattern_name or "Blockchain" in s.pattern_name]
        assert len(pk_secrets) >= 1, f"Expected PK detection, got: {[s.pattern_name for s in secrets]}"

    def test_settlement_pk_detected(self, scanner, production_dir):
        """SETTLEMENT_PK variant should also trigger."""
        test_file = production_dir / "config.env"
        test_file.write_text(
            'SETTLEMENT_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        assert len(secrets) >= 1


class TestSeedPhraseDetection:
    """Test wallet mnemonic/seed phrase detection."""

    def test_mnemonic_12_words(self, scanner, production_dir):
        """12-word mnemonic should trigger CRITICAL."""
        test_file = production_dir / "wallet.conf"
        test_file.write_text(
            'MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        seed_secrets = [s for s in secrets if "Mnemonic" in s.pattern_name or "Seed" in s.pattern_name]
        assert len(seed_secrets) >= 1, f"Expected seed phrase detection, got: {[s.pattern_name for s in secrets]}"

    def test_seed_phrase_24_words(self, scanner, production_dir):
        """24-word seed phrase should trigger CRITICAL."""
        test_file = production_dir / "keys.env"
        words = " ".join(["abandon"] * 23 + ["about"])
        test_file.write_text(f'seed_phrase="{words}"\n')
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        assert len(secrets) >= 1


class TestRPCURLDetection:
    """Test RPC URL with embedded API key detection."""

    def test_rpc_url_with_apikey(self, scanner, production_dir):
        """RPC URL with embedded API key should trigger MEDIUM."""
        test_file = production_dir / "config.yaml"
        test_file.write_text(
            'RPC_URL=https://mainnet.infura.io/v3/apikey=abc123def456ghi789\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        rpc_secrets = [s for s in secrets if "RPC" in s.pattern_name]
        assert len(rpc_secrets) >= 1, f"Expected RPC URL detection, got: {[s.pattern_name for s in secrets]}"


class TestX402PaymentHeaderDetection:
    """Test x402 payment header credential detection."""

    def test_x402_payment_mandate_header(self, scanner, production_dir):
        """X-Payment-Mandate header should trigger MEDIUM."""
        test_file = production_dir / "api.ts"
        test_file.write_text(
            'X-Payment-Mandate = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        payment_secrets = [s for s in secrets if "Payment" in s.pattern_name or "x402" in s.pattern_name]
        assert len(payment_secrets) >= 1, f"Expected payment header detection, got: {[s.pattern_name for s in secrets]}"


class TestFalsePositiveReduction:
    """Test that placeholders and examples don't trigger."""

    def test_placeholder_pk_no_match(self, scanner, production_dir):
        """Placeholder private key should not match the 0x hex pattern."""
        test_file = production_dir / ".env.example"
        test_file.write_text(
            'DEPLOYER_PK=your_deployer_private_key_here\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        # Placeholder doesn't match 0x + 64 hex pattern, so no blockchain PK match
        pk_secrets = [s for s in secrets if "Blockchain" in s.pattern_name]
        assert len(pk_secrets) == 0, f"Placeholder should not match blockchain PK pattern, got: {pk_secrets}"


class TestNoRegression:
    """Ensure existing patterns still work."""

    def test_openai_key_still_detected(self, scanner, production_dir):
        """OpenAI API key should still be detected after changes."""
        src_dir = production_dir / "src"
        src_dir.mkdir(parents=True)
        test_file = src_dir / "config.py"
        test_file.write_text(
            'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMN"\n'
        )
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        assert len(secrets) >= 1

    def test_github_token_still_detected(self, scanner, production_dir):
        """GitHub PAT should still be detected after changes."""
        src_dir = production_dir / "src"
        src_dir.mkdir(parents=True)
        test_file = src_dir / "config.py"
        # ghp_ + exactly 36 alphanumeric chars
        github_token = "ghp_" + "a" * 36
        test_file.write_text(f'GITHUB_TOKEN = "{github_token}"\n')
        results = scanner.scan(test_file)
        secrets = [s for r in results for s in r.secrets]
        assert len(secrets) >= 1
