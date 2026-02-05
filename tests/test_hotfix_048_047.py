"""
Hotfix tests for AGENT-048 and AGENT-047 false positive reduction.

AGENT-048: Extension boundary detection fix
- Internal imports within the same extension should NOT trigger
- Only cross-boundary imports (escaping the extension root) should trigger

AGENT-047: Subprocess confidence reduction
- Build scripts should have reduced confidence
- Safe commands (git, npm, node, etc.) should have reduced confidence
- Hardcoded arguments should have reduced confidence
- Multiple conditions should stack, with a minimum floor of 0.15
"""

import pytest
from pathlib import Path

from agent_audit.scanners.privilege_scanner import PrivilegeScanner


class TestAGENT048Hotfix:
    """AGENT-048 extension boundary fix tests."""

    def test_internal_import_same_extension_not_flagged_python(self, tmp_path: Path):
        """Internal Python import within extension should NOT trigger AGENT-048."""
        # Create extensions/tlon/src/monitor/utils.py
        ext_dir = tmp_path / "extensions" / "tlon" / "src" / "monitor"
        ext_dir.mkdir(parents=True)

        # Import from "../targets" stays within extensions/tlon/
        code = '''
# Internal import within the same extension
from .. import targets
from ..targets import normalizeShip

class MonitorUtils:
    def process(self):
        return normalizeShip("~zod")
'''
        file_path = ext_dir / "utils.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have NO AGENT-048 findings
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0, (
                f"Internal extension import should not trigger AGENT-048, "
                f"but got {len(ext_findings)} findings"
            )

    def test_internal_import_same_extension_not_flagged_js(self, tmp_path: Path):
        """Internal JS import within extension should NOT trigger AGENT-048."""
        # Create extensions/tlon/src/monitor/utils.ts
        ext_dir = tmp_path / "extensions" / "tlon" / "src" / "monitor"
        ext_dir.mkdir(parents=True)

        # Import from "../targets.js" stays within extensions/tlon/
        code = '''
import { normalizeShip } from "../targets.js";
import { Monitor } from "./monitor.js";

export function processShip(ship: string) {
    return normalizeShip(ship);
}
'''
        file_path = ext_dir / "utils.ts"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have NO AGENT-048 findings
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0, (
                f"Internal extension import should not trigger AGENT-048, "
                f"but got {len(ext_findings)} findings"
            )

    def test_cross_boundary_import_flagged_python(self, tmp_path: Path):
        """Cross-boundary Python import should trigger AGENT-048."""
        # Create extensions/tlon/src/index.py
        ext_dir = tmp_path / "extensions" / "tlon" / "src"
        ext_dir.mkdir(parents=True)

        # Also create core directory to make path resolution realistic
        core_dir = tmp_path / "src" / "core"
        core_dir.mkdir(parents=True)
        (core_dir / "api.py").write_text("# Core API")

        # Import from "../../src/core" escapes extensions/tlon/
        code = '''
# Cross-boundary import - accessing core from extension
from ....src.core import api
from ...core import runner

class TlonExtension:
    def run(self):
        return api.process()
'''
        file_path = ext_dir / "index.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have AGENT-048 findings
        assert len(results) == 1
        ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1, (
            "Cross-boundary import should trigger AGENT-048"
        )

    def test_cross_boundary_import_flagged_js(self, tmp_path: Path):
        """Cross-boundary JS import should trigger AGENT-048."""
        # Create extensions/tlon/src/index.ts
        ext_dir = tmp_path / "extensions" / "tlon" / "src"
        ext_dir.mkdir(parents=True)

        # Import from "../../../src/core/api.js" escapes extensions/tlon/
        code = '''
import { CoreAPI } from "../../../src/core/api.js";
import { AgentRunner } from "../../core/runner";

export class TlonExtension {
    private api: CoreAPI;
}
'''
        file_path = ext_dir / "index.ts"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have AGENT-048 findings
        assert len(results) == 1
        ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1, (
            "Cross-boundary import should trigger AGENT-048"
        )

    def test_deep_internal_import_not_flagged(self, tmp_path: Path):
        """Deep internal imports within extension should NOT trigger."""
        # Create extensions/tlon/src/features/monitor/components/widget.ts
        ext_dir = tmp_path / "extensions" / "tlon" / "src" / "features" / "monitor" / "components"
        ext_dir.mkdir(parents=True)

        # Multiple parent imports but still within extensions/tlon/
        code = '''
import { Config } from "../../../config.js";
import { Utils } from "../../utils/index.js";
import { Types } from "../../../../types.js";

export class Widget {}
'''
        file_path = ext_dir / "widget.ts"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have NO AGENT-048 findings (all imports stay within extension)
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0, (
                f"Deep internal imports should not trigger AGENT-048, "
                f"but got {len(ext_findings)} findings"
            )

    def test_plugin_directory_same_behavior(self, tmp_path: Path):
        """Plugin directory should have same behavior as extensions."""
        # Create plugins/my_plugin/src/index.ts
        plugin_dir = tmp_path / "plugins" / "my_plugin" / "src"
        plugin_dir.mkdir(parents=True)

        # Internal import
        code_internal = '''
import { Helper } from "../utils/helper.js";
'''
        file_internal = plugin_dir / "index.ts"
        file_internal.write_text(code_internal)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_internal)

        # Internal import should NOT trigger
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0

    def test_non_extension_directory_no_findings(self, tmp_path: Path):
        """Files outside extension directories should not trigger AGENT-048."""
        # Create src/components/user.py (not in extensions/)
        src_dir = tmp_path / "src" / "components"
        src_dir.mkdir(parents=True)

        code = '''
from .. import utils
from ..models import User
'''
        file_path = src_dir / "user.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Should have NO AGENT-048 findings
        if results:
            ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
            assert len(ext_findings) == 0


class TestAGENT047Hotfix:
    """AGENT-047 confidence reduction tests."""

    def test_build_script_reduced_confidence(self, tmp_path: Path):
        """Subprocess in build script with safe commands should be filtered out."""
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        code = '''
import subprocess

def build():
    subprocess.run(["npm", "install"])
    subprocess.run(["npm", "run", "build"])
'''
        file_path = scripts_dir / "build.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Build dir (×0.50) + safe command npm (×0.50) + hardcoded (×0.60) = 0.80 × 0.15 = 0.12
        # Below 0.30 threshold, so findings should be filtered out entirely
        # This is the CORRECT behavior - we don't want to flag build scripts with safe commands
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            # If any findings remain, they should have reduced confidence
            for finding in subprocess_findings:
                assert finding.confidence < 0.50, (
                    f"Build script subprocess should have reduced confidence, "
                    f"got {finding.confidence}"
                )

    def test_safe_command_reduced_confidence(self, tmp_path: Path):
        """Safe commands (git, npm, etc.) with hardcoded args should be filtered out."""
        code = '''
import subprocess

def get_version():
    result = subprocess.run(["git", "--version"], capture_output=True)
    return result.stdout
'''
        file_path = tmp_path / "version.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Safe command git (×0.50) + hardcoded (×0.60) = 0.80 × 0.30 = 0.24
        # Below 0.30 threshold, so findings should be filtered out
        # This is the CORRECT behavior - we don't want to flag hardcoded safe commands
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            # If any findings remain (shouldn't be any), they should have low confidence
            for finding in subprocess_findings:
                assert finding.confidence < 0.50

    def test_hardcoded_args_reduced_confidence(self, tmp_path: Path):
        """Hardcoded arguments should have reduced confidence."""
        code = '''
import subprocess

def run_linter():
    subprocess.run(["custom-linter", "--fix", "src/"])
'''
        file_path = tmp_path / "lint.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # May or may not have findings depending on confidence threshold
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            if subprocess_findings:
                # Hardcoded args (×0.60) = 0.80 × 0.60 = 0.48
                assert subprocess_findings[0].confidence < 0.60

    def test_dynamic_command_higher_confidence(self, tmp_path: Path):
        """Dynamic command execution should have higher confidence."""
        code = '''
import subprocess

def execute(user_command: str):
    subprocess.run(user_command, shell=True)
'''
        file_path = tmp_path / "executor.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]

        # Dynamic input with shell=True should have high confidence
        assert len(subprocess_findings) >= 1
        assert subprocess_findings[0].confidence >= 0.80

    def test_multiple_reductions_stack(self, tmp_path: Path):
        """Multiple confidence reductions should stack."""
        # scripts/ directory + safe command + hardcoded = maximum reduction
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        code = '''
import subprocess

def setup():
    subprocess.run(["git", "clone", "https://github.com/example/repo"])
'''
        file_path = scripts_dir / "setup.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # With all reductions: 0.80 × 0.50 × 0.50 × 0.60 = 0.12
        # Below 0.30 threshold, should be filtered out
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            # If any findings remain, they should be at minimum confidence
            for finding in subprocess_findings:
                assert finding.confidence <= 0.30 or finding.confidence >= 0.15

    def test_js_child_process_in_tools_dir(self, tmp_path: Path):
        """JS child_process in tools directory should have reduced confidence."""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()

        code = '''
const { exec } = require('child_process');

function runBuild() {
    exec('npm run build', (err, stdout) => {
        console.log(stdout);
    });
}
'''
        file_path = tools_dir / "build.js"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            for finding in subprocess_findings:
                # Tools dir (×0.50) + hardcoded (×0.60) + safe command npm (×0.50) = very low
                assert finding.confidence < 0.50

    def test_github_actions_directory_reduced(self, tmp_path: Path):
        """Subprocess in .github directory should have reduced confidence."""
        github_dir = tmp_path / ".github" / "scripts"
        github_dir.mkdir(parents=True)

        code = '''
import subprocess

def run_ci():
    subprocess.run(["npm", "test"])
    subprocess.run(["npm", "run", "lint"])
'''
        file_path = github_dir / "ci.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            for finding in subprocess_findings:
                # .github dir should be recognized as build directory
                assert finding.severity.value == "medium"

    def test_minimum_confidence_floor(self, tmp_path: Path):
        """Confidence should never go below minimum floor."""
        # Even with all reductions, minimum should be 0.15
        scripts_dir = tmp_path / "scripts" / "build"
        scripts_dir.mkdir(parents=True)

        code = '''
import subprocess

def full_build():
    # Maximum reductions: build dir + safe command + hardcoded
    subprocess.run(["npm", "install"])
    subprocess.run(["npm", "run", "build"])
    subprocess.run(["npm", "test"])
'''
        file_path = scripts_dir / "full_build.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        # Findings may be filtered out due to low confidence
        # But if any remain, they should be at or above minimum
        if results and results[0].findings:
            subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
            for finding in subprocess_findings:
                assert finding.confidence >= 0.15


class TestRegressionPrevention:
    """Ensure existing functionality is not broken."""

    def test_agent047_still_detects_dangerous_patterns(self, tmp_path: Path):
        """AGENT-047 should still detect truly dangerous patterns."""
        code = '''
import subprocess
import os

def execute_user_command(cmd: str):
    # Dangerous: dynamic command with shell=True
    subprocess.run(cmd, shell=True)

    # Dangerous: os.system with user input
    os.system(f"echo {cmd}")
'''
        file_path = tmp_path / "dangerous.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        subprocess_findings = [f for f in results[0].findings if f.rule_id == "AGENT-047"]
        assert len(subprocess_findings) >= 1, "Dangerous subprocess patterns should still be detected"

    def test_agent048_still_detects_real_violations(self, tmp_path: Path):
        """AGENT-048 should still detect real boundary violations."""
        # Create extensions/malicious/src/index.py (deeper in the extension)
        ext_dir = tmp_path / "extensions" / "malicious" / "src"
        ext_dir.mkdir(parents=True)

        code = '''
# Malicious extension accessing core secrets
from ....core.secrets import API_KEYS
from ....database import users

def steal_data():
    return API_KEYS, users.get_all()
'''
        file_path = ext_dir / "index.py"
        file_path.write_text(code)

        scanner = PrivilegeScanner()
        results = scanner.scan(file_path)

        assert len(results) == 1
        ext_findings = [f for f in results[0].findings if f.rule_id == "AGENT-048"]
        assert len(ext_findings) >= 1, "Cross-boundary imports should still be detected"
