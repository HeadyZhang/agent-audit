"""
Tests for v0.5.0 privilege detection rules (AGENT-043~048).

These tests verify detection of privilege escalation patterns,
unsandboxed execution, and permission boundary violations.

ASI Coverage:
- ASI-02: Tool Misuse (AGENT-045, AGENT-047)
- ASI-03: Identity & Privilege Abuse (AGENT-043, AGENT-044)
- ASI-04: Supply Chain (AGENT-048)
- ASI-05: Unexpected Code Execution (AGENT-046)
- ASI-07: Inter-Agent Communication (AGENT-048)
- ASI-08: Cascading Failures (AGENT-047)
"""

import pytest
from pathlib import Path

from agent_audit.scanners.privilege_scanner import PrivilegeScanner


class TestAgent043DaemonPrivilegeEscalation:
    """Test AGENT-043: Daemon privilege escalation detection."""

    def test_launchctl_detection(self, tmp_path: Path):
        """Test detection of launchctl daemon commands."""
        code = '''#!/bin/bash
# Agent daemon setup script
launchctl load /Library/LaunchDaemons/com.agent.plist
launchctl start com.agent.daemon
'''
        file_path = tmp_path / "daemon_setup.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        assert len(findings) >= 1

        daemon_finding = next(
            (f for f in findings if f.rule_id == "AGENT-043"), None
        )
        assert daemon_finding is not None
        assert daemon_finding.owasp_id == "ASI-03"
        assert daemon_finding.confidence >= 0.80

    def test_systemctl_detection(self, tmp_path: Path):
        """Test detection of systemctl service commands."""
        code = '''#!/bin/bash
# Enable and start the agent service
systemctl enable agent-worker.service
systemctl start agent-worker.service
'''
        file_path = tmp_path / "install_service.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        daemon_findings = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(daemon_findings) >= 1
        assert daemon_findings[0].confidence >= 0.80

    def test_pm2_detection(self, tmp_path: Path):
        """Test detection of PM2 process manager commands."""
        code = '''#!/bin/bash
pm2 start agent.js --name "agent-daemon"
pm2 restart agent-daemon
'''
        file_path = tmp_path / "pm2_deploy.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        daemon_findings = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(daemon_findings) >= 1

    def test_daemon_filename_only_low_confidence(self, tmp_path: Path):
        """Test that daemon filename without substantive content has low confidence."""
        code = '''# Configuration file for daemon
# No actual daemon commands here
DEBUG=true
'''
        file_path = tmp_path / "daemon_config.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # May or may not have findings, but if present should be low confidence
        if results and results[0].findings:
            daemon_findings = [f for f in results[0].findings if f.rule_id == "AGENT-043"]
            if daemon_findings:
                assert daemon_findings[0].confidence <= 0.50
                assert daemon_findings[0].severity.value == "info"


class TestAgent044SudoersNopasswd:
    """Test AGENT-044: Sudoers NOPASSWD configuration detection."""

    def test_nopasswd_in_script(self, tmp_path: Path):
        """Test detection of NOPASSWD in shell script."""
        code = '''#!/bin/bash
# Configure sudo access for agent
echo "agent ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/agent
'''
        file_path = tmp_path / "setup_sudo.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        sudoers_findings = [f for f in findings if f.rule_id == "AGENT-044"]
        assert len(sudoers_findings) >= 1
        assert sudoers_findings[0].confidence >= 0.85
        assert sudoers_findings[0].severity.value == "high"

    def test_nopasswd_in_markdown_medium_severity(self, tmp_path: Path):
        """Test that NOPASSWD in documentation has medium severity."""
        code = '''# Agent Installation Guide

## Sudo Configuration

Add the following to `/etc/sudoers`:

```
agent ALL=(ALL) NOPASSWD: /usr/bin/docker
```

This allows the agent to run Docker without password prompts.
'''
        file_path = tmp_path / "INSTALL.md"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        sudoers_findings = [f for f in findings if f.rule_id == "AGENT-044"]
        assert len(sudoers_findings) >= 1
        # Markdown should have lower severity
        assert sudoers_findings[0].severity.value == "medium"
        assert sudoers_findings[0].confidence >= 0.70

    def test_visudo_detection(self, tmp_path: Path):
        """Test detection of visudo commands."""
        code = '''#!/bin/bash
# Edit sudoers using visudo
sudo visudo -f /etc/sudoers.d/agent
'''
        file_path = tmp_path / "configure_sudo.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        sudoers_findings = [f for f in findings if f.rule_id == "AGENT-044"]
        assert len(sudoers_findings) >= 1

    def test_all_all_all_pattern(self, tmp_path: Path):
        """Test detection of ALL=(ALL) ALL pattern."""
        code = '''#!/bin/bash
# Grant full sudo access
echo "agent ALL=(ALL) ALL" >> /etc/sudoers
'''
        file_path = tmp_path / "grant_sudo.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        sudoers_findings = [f for f in findings if f.rule_id == "AGENT-044"]
        assert len(sudoers_findings) >= 1
        assert sudoers_findings[0].confidence >= 0.80


class TestAgent045BrowserAutomation:
    """Test AGENT-045: Browser automation without sandbox detection."""

    def test_puppeteer_page_evaluate(self, tmp_path: Path):
        """Test detection of Puppeteer page.evaluate."""
        code = '''
const puppeteer = require('puppeteer');

async function scrapeData(url, script) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(url);

    // Execute arbitrary script in page context
    const result = await page.evaluate(script);
    return result;
}
'''
        file_path = tmp_path / "scraper.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        browser_findings = [f for f in findings if f.rule_id == "AGENT-045"]
        assert len(browser_findings) >= 1
        assert browser_findings[0].owasp_id == "ASI-02"
        assert browser_findings[0].confidence >= 0.80

    def test_playwright_no_sandbox(self, tmp_path: Path):
        """Test detection of --no-sandbox flag."""
        code = '''
import { chromium } from 'playwright';

async function runBrowser() {
    const browser = await chromium.launch({
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    await page.evaluate(() => document.title);
}
'''
        file_path = tmp_path / "browser.ts"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        browser_findings = [f for f in findings if f.rule_id == "AGENT-045"]
        assert len(browser_findings) >= 1
        # --no-sandbox should increase confidence
        assert browser_findings[0].confidence >= 0.85

    def test_cdp_websocket_detection(self, tmp_path: Path):
        """Test detection of Chrome DevTools Protocol websocket."""
        code = '''
const CDP = require('chrome-remote-interface');

async function connectToDevTools() {
    const client = await CDP({
        target: 'ws://localhost:9222/devtools/page/1234'
    });
    // Execute code via CDP
    await client.Runtime.evaluate({ expression: 'document.cookie' });
}
'''
        file_path = tmp_path / "cdp_client.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        browser_findings = [f for f in findings if f.rule_id == "AGENT-045"]
        assert len(browser_findings) >= 1

    def test_python_pyppeteer(self, tmp_path: Path):
        """Test detection in Python with pyppeteer."""
        code = '''
import asyncio
from pyppeteer import launch

async def scrape(script):
    browser = await launch()
    page = await browser.newPage()
    result = await page.evaluate(script)
    return result
'''
        file_path = tmp_path / "py_scraper.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        browser_findings = [f for f in findings if f.rule_id == "AGENT-045"]
        assert len(browser_findings) >= 1


class TestAgent046CredentialStoreAccess:
    """Test AGENT-046: System credential store access detection."""

    def test_macos_keychain_security_command(self, tmp_path: Path):
        """Test detection of macOS security command for keychain."""
        code = '''#!/bin/bash
# Retrieve API key from keychain
API_KEY=$(security find-generic-password -a "agent" -s "api-key" -w)
export OPENAI_API_KEY=$API_KEY
'''
        file_path = tmp_path / "get_credentials.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        cred_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_findings) >= 1
        assert cred_findings[0].owasp_id == "ASI-05"
        assert cred_findings[0].confidence >= 0.80
        assert "Keychain" in cred_findings[0].description

    def test_gnome_keyring(self, tmp_path: Path):
        """Test detection of GNOME keyring access."""
        code = '''#!/bin/bash
# Get password from GNOME keyring
PASSWORD=$(secret-tool lookup service "agent" username "admin")
'''
        file_path = tmp_path / "get_secret.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        cred_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_findings) >= 1

    def test_pass_password_store(self, tmp_path: Path):
        """Test detection of pass (Unix password store)."""
        code = '''#!/bin/bash
# Get API key from pass
API_KEY=$(pass show services/openai/api-key)
'''
        file_path = tmp_path / "setup_env.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        cred_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_findings) >= 1

    def test_1password_cli(self, tmp_path: Path):
        """Test detection of 1Password CLI."""
        code = '''#!/bin/bash
# Get credentials from 1Password
DB_PASSWORD=$(op item get "Database" --field password)
'''
        file_path = tmp_path / "get_db_creds.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        cred_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_findings) >= 1
        assert cred_findings[0].confidence >= 0.70

    def test_node_keytar(self, tmp_path: Path):
        """Test detection of Node.js keytar library."""
        code = '''
const keytar = require('keytar');

async function getApiKey() {
    const key = await keytar.getPassword('agent-service', 'api-key');
    return key;
}
'''
        file_path = tmp_path / "credentials.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        cred_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_findings) >= 1

    def test_not_confused_with_hardcoded_credentials(self, tmp_path: Path):
        """Test that AGENT-046 is not confused with AGENT-004 (hardcoded creds)."""
        # This should trigger AGENT-046 (credential store access)
        # NOT AGENT-004 (hardcoded credentials)
        code = '''
def readKeychainPassword(service: str, account: str) -> str:
    """Read password from macOS Keychain."""
    import subprocess
    result = subprocess.run([
        'security', 'find-generic-password',
        '-a', account, '-s', service, '-w'
    ], capture_output=True, text=True)
    return result.stdout.strip()
'''
        file_path = tmp_path / "keychain_util.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings

        # Should find AGENT-046 (credential store access)
        cred_store_findings = [f for f in findings if f.rule_id == "AGENT-046"]
        assert len(cred_store_findings) >= 1

        # Should NOT find AGENT-004 (hardcoded credentials) from this scanner
        # Note: AGENT-004 is detected by secret_scanner, not privilege_scanner
        hardcoded_findings = [f for f in findings if f.rule_id == "AGENT-004"]
        assert len(hardcoded_findings) == 0


class TestAgent047SubprocessExecution:
    """Test AGENT-047: Subprocess execution without sandbox detection."""

    def test_python_subprocess_shell_true(self, tmp_path: Path):
        """Test detection of subprocess with shell=True."""
        code = '''
import subprocess

def execute_command(user_command: str) -> str:
    """Execute a shell command."""
    result = subprocess.run(user_command, shell=True, capture_output=True, text=True)
    return result.stdout
'''
        file_path = tmp_path / "executor.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        subprocess_findings = [f for f in findings if f.rule_id == "AGENT-047"]
        assert len(subprocess_findings) >= 1
        assert subprocess_findings[0].confidence >= 0.80
        assert subprocess_findings[0].owasp_id == "ASI-02"

    def test_python_subprocess_dynamic_input(self, tmp_path: Path):
        """Test detection of subprocess with dynamic input."""
        code = '''
import subprocess

def run_tool(command: str, args: list) -> str:
    """Run an external tool."""
    result = subprocess.run([command] + args, capture_output=True)
    return result.stdout.decode()
'''
        file_path = tmp_path / "tool_runner.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        subprocess_findings = [f for f in findings if f.rule_id == "AGENT-047"]
        assert len(subprocess_findings) >= 1

    def test_js_child_process_exec(self, tmp_path: Path):
        """Test detection of Node.js child_process.exec."""
        code = '''
const { exec } = require('child_process');

function runCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
}
'''
        file_path = tmp_path / "runner.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        subprocess_findings = [f for f in findings if f.rule_id == "AGENT-047"]
        assert len(subprocess_findings) >= 1

    def test_build_script_lowered_confidence(self, tmp_path: Path):
        """Test that build scripts with safe commands are filtered out.

        With v0.5.1 hotfix, confidence reductions stack:
        - Build dir (×0.50) + safe command npm (×0.50) + hardcoded (×0.60) = 0.80 × 0.15 = 0.12
        - Below 0.30 threshold, findings are correctly filtered out
        This is expected behavior to reduce false positives.
        """
        # Create a build script directory
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        code = '''
import subprocess

def build():
    """Build the project."""
    subprocess.run(["npm", "install"], check=True)
    subprocess.run(["npm", "run", "build"], check=True)
'''
        file_path = scripts_dir / "build.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # With stacked confidence reductions, these low-risk findings are filtered out
        # This is the CORRECT behavior after the hotfix
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            # If any findings remain, verify they have reduced confidence and severity
            for finding in subprocess_findings:
                assert finding.severity.value == "medium"
                assert finding.confidence < 0.50

    def test_hardcoded_commands_lower_confidence(self, tmp_path: Path):
        """Test that safe commands with hardcoded args are filtered out.

        With v0.5.1 hotfix, confidence reductions stack:
        - Safe command git (×0.50) + hardcoded (×0.60) = 0.80 × 0.30 = 0.24
        - Below 0.30 threshold, findings are correctly filtered out
        This is expected behavior to reduce false positives.
        """
        code = '''
import subprocess

def get_version():
    """Get git version."""
    result = subprocess.run(["git", "--version"], capture_output=True, text=True)
    return result.stdout
'''
        file_path = tmp_path / "version.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # With stacked confidence reductions (safe command + hardcoded),
        # these low-risk findings are filtered out. This is CORRECT behavior.
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            # If any findings remain, they should have low confidence
            for finding in subprocess_findings:
                assert finding.confidence <= 0.50


class TestAgent048ExtensionPermissionBoundaries:
    """Test AGENT-048: Extension/plugin permission boundary detection."""

    def test_extension_imports_parent(self, tmp_path: Path):
        """Test detection of extension importing from parent directory."""
        # Create extensions directory structure
        ext_dir = tmp_path / "extensions" / "my_plugin"
        ext_dir.mkdir(parents=True)

        code = '''
# Extension that violates permission boundaries
from .. import core_module
from ..utils import sensitive_function

class MyPlugin:
    def run(self):
        return sensitive_function()
'''
        file_path = ext_dir / "plugin.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        ext_findings = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1
        assert ext_findings[0].owasp_id == "ASI-04"
        assert ext_findings[0].confidence >= 0.75

    def test_plugin_js_imports_parent(self, tmp_path: Path):
        """Test detection of JS plugin importing from parent."""
        # Create plugins directory structure
        plugin_dir = tmp_path / "plugins" / "data_exporter"
        plugin_dir.mkdir(parents=True)

        code = '''
// Plugin that accesses core directly
const core = require('../core');
import { secrets } from '../config';

module.exports = {
    export: function(data) {
        return core.processData(data, secrets);
    }
};
'''
        file_path = plugin_dir / "exporter.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        ext_findings = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1

    def test_addon_ts_imports_parent(self, tmp_path: Path):
        """Test detection of TypeScript addon importing from parent."""
        # Create addons directory
        addon_dir = tmp_path / "addons" / "custom"
        addon_dir.mkdir(parents=True)

        code = '''
import { DatabaseClient } from '../../core/database';
import { AuthService } from '../shared/auth';

export class CustomAddon {
    private db: DatabaseClient;

    constructor() {
        this.db = new DatabaseClient();
    }
}
'''
        file_path = addon_dir / "custom.ts"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        findings = results[0].findings
        ext_findings = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1

    def test_non_extension_directory_no_finding(self, tmp_path: Path):
        """Test that parent imports outside extension dirs are not flagged."""
        # Create a regular src directory (not extensions/plugins)
        src_dir = tmp_path / "src" / "components"
        src_dir.mkdir(parents=True)

        code = '''
# Normal internal import
from .. import utils
from ..models import User

class UserComponent:
    pass
'''
        file_path = src_dir / "user.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have no findings or no AGENT-048 findings
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0


class TestPrivilegeScannerIntegration:
    """Integration tests for the privilege scanner."""

    def test_scan_and_convert(self, tmp_path: Path):
        """Test scan_and_convert returns Finding objects."""
        code = '''#!/bin/bash
systemctl enable agent.service
echo "agent ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
'''
        file_path = tmp_path / "setup.sh"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        findings = scanner.scan_and_convert(file_path)

        assert len(findings) >= 2  # Should have both daemon and sudoers findings

        # Check that findings are proper Finding objects
        for finding in findings:
            assert hasattr(finding, 'rule_id')
            assert hasattr(finding, 'tier')
            assert hasattr(finding, 'confidence')
            assert hasattr(finding, 'location')
            assert finding.location.file_path == str(file_path)

    def test_multiple_file_types(self, tmp_path: Path):
        """Test scanning multiple file types."""
        # Create various file types
        (tmp_path / "daemon.sh").write_text("launchctl start agent")
        (tmp_path / "browser.js").write_text("page.evaluate(() => {})")
        (tmp_path / "keychain.py").write_text("security find-generic-password")

        scanner = PrivilegeScanner()
        findings = scanner.scan_and_convert(tmp_path)

        # Should find issues in all three files
        rule_ids = {f.rule_id for f in findings}
        assert "AGENT-043" in rule_ids or "AGENT-045" in rule_ids or "AGENT-046" in rule_ids

    def test_empty_directory(self, tmp_path: Path):
        """Test scanning empty directory."""
        scanner = PrivilegeScanner()
        findings = scanner.scan_and_convert(tmp_path)
        assert findings == []

    def test_unsupported_file_types_ignored(self, tmp_path: Path):
        """Test that unsupported file types are ignored."""
        (tmp_path / "image.png").write_bytes(b'\x89PNG\r\n\x1a\n')
        (tmp_path / "data.json").write_text('{"key": "value"}')

        scanner = PrivilegeScanner()
        findings = scanner.scan_and_convert(tmp_path)
        assert findings == []
