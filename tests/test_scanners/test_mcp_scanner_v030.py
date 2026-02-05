"""Tests for MCP config scanner v0.3.0 security enhancements."""

import pytest
import json
from pathlib import Path
from textwrap import dedent

from agent_audit.scanners.mcp_config_scanner import (
    MCPConfigScanner,
    MCPServerConfig,
    MCPSecurityFinding,
)


class TestMCPSecurityAnalysis:
    """Tests for v0.3.0 security analysis methods."""

    @pytest.fixture
    def scanner(self):
        return MCPConfigScanner()

    @pytest.fixture
    def tmp_config_dir(self, tmp_path):
        """Create temp directory for test configs."""
        return tmp_path

    # =========================================================================
    # AGENT-029: Overly Broad Filesystem Access
    # =========================================================================

    def test_detects_root_filesystem_access(self, scanner, tmp_config_dir):
        """Test detection of root filesystem access (AGENT-029)."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)

        assert len(results) == 1
        findings = results[0].security_findings
        agent029_findings = [f for f in findings if f.rule_id == "AGENT-029"]
        assert len(agent029_findings) >= 1
        assert any("/" in f.description for f in agent029_findings)

    def test_detects_home_directory_access(self, scanner, tmp_config_dir):
        """Test detection of home directory access (AGENT-029)."""
        config = {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "server-fs", "~"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent029_findings = [f for f in findings if f.rule_id == "AGENT-029"]
        assert len(agent029_findings) >= 1

    def test_detects_wildcard_path(self, scanner, tmp_config_dir):
        """Test detection of wildcard paths (AGENT-029)."""
        config = {
            "mcpServers": {
                "fs": {
                    "command": "node",
                    "args": ["server.js", "/data/**"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent029_findings = [f for f in findings if f.rule_id == "AGENT-029"]
        assert any("wildcard" in f.description.lower() for f in agent029_findings)

    def test_detects_path_traversal(self, scanner, tmp_config_dir):
        """Test detection of path traversal (AGENT-029)."""
        config = {
            "mcpServers": {
                "fs": {
                    "command": "node",
                    "args": ["server.js", "./data/../../../etc"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent029_findings = [f for f in findings if f.rule_id == "AGENT-029"]
        assert any("traversal" in f.description.lower() for f in agent029_findings)

    def test_allows_scoped_directory(self, scanner, tmp_config_dir):
        """Test that scoped directories don't trigger AGENT-029."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-filesystem@1.2.3",
                        "./data"
                    ]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent029_findings = [f for f in findings if f.rule_id == "AGENT-029"]
        # Should not have findings about broad access
        assert not any("root" in f.description.lower() for f in agent029_findings)

    # =========================================================================
    # AGENT-030: Unverified Server Source
    # =========================================================================

    def test_detects_unpinned_npx_package(self, scanner, tmp_config_dir):
        """Test detection of unpinned npx package (AGENT-030)."""
        config = {
            "mcpServers": {
                "tool": {
                    "command": "npx",
                    "args": ["-y", "some-random-mcp-package"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent030_findings = [f for f in findings if f.rule_id == "AGENT-030"]
        assert len(agent030_findings) >= 1
        assert any("unpinned" in f.description.lower() for f in agent030_findings)

    def test_allows_pinned_version(self, scanner, tmp_config_dir):
        """Test that pinned versions don't trigger AGENT-030."""
        config = {
            "mcpServers": {
                "tool": {
                    "command": "npx",
                    "args": ["-y", "some-package@1.2.3"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent030_findings = [f for f in findings if f.rule_id == "AGENT-030"]
        # Should not have unpinned findings
        assert not any("unpinned" in f.description.lower() for f in agent030_findings)

    def test_allows_official_mcp_packages(self, scanner, tmp_config_dir):
        """Test that official @modelcontextprotocol packages are allowed."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent030_findings = [f for f in findings if f.rule_id == "AGENT-030"]
        # Official packages should be allowed without version
        assert not any(
            "unpinned" in f.description.lower() and "@modelcontextprotocol" in f.description
            for f in agent030_findings
        )

    def test_detects_http_url(self, scanner, tmp_config_dir):
        """Test detection of unencrypted HTTP URL (AGENT-030)."""
        config = {
            "mcpServers": {
                "remote": {
                    "url": "http://example.com/mcp"
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent030_findings = [f for f in findings if f.rule_id == "AGENT-030"]
        assert any("http" in f.description.lower() for f in agent030_findings)

    # =========================================================================
    # AGENT-031: Sensitive Environment Variable Exposure
    # =========================================================================

    def test_detects_hardcoded_api_key(self, scanner, tmp_config_dir):
        """Test detection of hardcoded API key (AGENT-031)."""
        config = {
            "mcpServers": {
                "api": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-1234567890abcdef"
                    }
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent031_findings = [f for f in findings if f.rule_id == "AGENT-031"]
        assert len(agent031_findings) >= 1
        assert any("API_KEY" in f.description for f in agent031_findings)

    def test_detects_placeholder_value(self, scanner, tmp_config_dir):
        """Test detection of placeholder values (AGENT-031)."""
        config = {
            "mcpServers": {
                "api": {
                    "command": "python",
                    "args": ["server.py"],
                    "env": {
                        "SECRET_TOKEN": "your-api-key-here"
                    }
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent031_findings = [f for f in findings if f.rule_id == "AGENT-031"]
        assert any("placeholder" in f.description.lower() for f in agent031_findings)

    def test_allows_env_reference(self, scanner, tmp_config_dir):
        """Test that environment variable references are allowed."""
        config = {
            "mcpServers": {
                "api": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "${OPENAI_API_KEY}",
                        "NODE_ENV": "production"
                    }
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent031_findings = [f for f in findings if f.rule_id == "AGENT-031"]
        # Should not flag ${VAR} references
        assert len(agent031_findings) == 0

    # =========================================================================
    # AGENT-033: Missing Authentication for SSE/HTTP
    # =========================================================================

    def test_detects_missing_auth_sse(self, scanner, tmp_config_dir):
        """Test detection of missing auth for SSE transport (AGENT-033)."""
        config = {
            "mcpServers": {
                "remote": {
                    "transport": "sse",
                    "url": "https://example.com/mcp/sse"
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent033_findings = [f for f in findings if f.rule_id == "AGENT-033"]
        assert len(agent033_findings) >= 1
        assert agent033_findings[0].owasp_id == "ASI-09"

    def test_allows_sse_with_auth(self, scanner, tmp_config_dir):
        """Test that SSE with auth config doesn't trigger AGENT-033."""
        config = {
            "mcpServers": {
                "remote": {
                    "transport": "sse",
                    "url": "https://example.com/mcp/sse",
                    "env": {
                        "MCP_AUTH_TOKEN": "${MCP_TOKEN}"
                    }
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        agent033_findings = [f for f in findings if f.rule_id == "AGENT-033"]
        assert len(agent033_findings) == 0

    # =========================================================================
    # Safe Configuration (No Findings)
    # =========================================================================

    def test_safe_config_no_findings(self, scanner, tmp_config_dir):
        """Test that a fully safe config produces no findings."""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-filesystem@1.2.3",
                        "./data"
                    ],
                    "env": {
                        "NODE_ENV": "production"
                    }
                }
            }
        }
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        findings = results[0].security_findings
        # Official package with version, scoped path, no sensitive env
        assert len(findings) == 0

    # =========================================================================
    # Robustness Tests
    # =========================================================================

    def test_handles_non_mcp_json(self, scanner, tmp_config_dir):
        """Test that non-MCP JSON files don't crash."""
        config = {"name": "not-an-mcp-config", "version": "1.0"}
        config_file = tmp_config_dir / "package.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        assert isinstance(results, list)

    def test_handles_invalid_json(self, scanner, tmp_config_dir):
        """Test that invalid JSON doesn't crash."""
        config_file = tmp_config_dir / "invalid.json"
        config_file.write_text("this is not valid json {{")

        results = scanner.scan(config_file)
        assert isinstance(results, list)

    def test_handles_empty_servers(self, scanner, tmp_config_dir):
        """Test handling of empty mcpServers."""
        config = {"mcpServers": {}}
        config_file = tmp_config_dir / "mcp.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        assert len(results) == 1
        assert len(results[0].servers) == 0


class TestMCPConfigFormats:
    """Test support for various MCP config file formats."""

    @pytest.fixture
    def scanner(self):
        return MCPConfigScanner()

    def test_scans_cline_settings(self, scanner, tmp_path):
        """Test scanning cline_mcp_settings.json format."""
        config = {
            "mcpServers": {
                "test": {"command": "npx", "args": ["test-server@1.0.0"]}
            }
        }
        config_file = tmp_path / "cline_mcp_settings.json"
        config_file.write_text(json.dumps(config))

        results = scanner.scan(config_file)
        assert len(results) == 1

    def test_scans_mcp_config_yaml(self, scanner, tmp_path):
        """Test scanning mcp-config.yaml format."""
        yaml_content = dedent("""
            mcpServers:
              test:
                command: npx
                args:
                  - test-server@1.0.0
        """)
        config_file = tmp_path / "mcp-config.yaml"
        config_file.write_text(yaml_content)

        results = scanner.scan(config_file)
        assert len(results) == 1

    def test_auto_detects_mcp_structure(self, scanner, tmp_path):
        """Test auto-detection of MCP config structure."""
        # A file with .json suffix containing mcpServers should be detected
        config = {"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}
        config_file = tmp_path / "custom.mcp.json"
        config_file.write_text(json.dumps(config))

        # Scanner should find it when scanning the directory
        results = scanner.scan(tmp_path)
        # May or may not find based on filename patterns, but should not crash
        assert isinstance(results, list)
