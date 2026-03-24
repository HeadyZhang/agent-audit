"""Tests for TypeScript/JavaScript security scanner."""

import tempfile
import textwrap
from pathlib import Path

import pytest

from agent_audit.scanners.typescript_scanner import TypeScriptScanner


@pytest.fixture
def scanner():
    """Create a TypeScriptScanner instance."""
    return TypeScriptScanner()


def _write_ts_file(content: str, suffix: str = ".ts") -> Path:
    """Write content to a temporary TypeScript file and return the path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


class TestEvalDetection:
    """Test detection of eval() calls."""

    def test_eval_detection(self, scanner):
        """eval(userInput) should produce AGENT-034 finding."""
        path = _write_ts_file("""
            function processInput(userInput: string) {
                const result = eval(userInput);
                return result;
            }
        """)
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1
        eval_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(eval_findings) >= 1
        assert eval_findings[0].confidence >= 0.90

    def test_eval_in_js_file(self, scanner):
        """eval() detection should work in .js files too."""
        path = _write_ts_file(
            """
            const x = eval(data);
        """,
            suffix=".js",
        )
        findings = scanner.scan_and_convert(path)
        eval_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(eval_findings) >= 1


class TestNewFunctionDetection:
    """Test detection of new Function() calls."""

    def test_new_function_detection(self, scanner):
        """new Function(code) should produce AGENT-034 finding."""
        path = _write_ts_file("""
            function createDynamic(code: string) {
                const fn = new Function(code);
                return fn();
            }
        """)
        findings = scanner.scan_and_convert(path)
        func_findings = [
            f
            for f in findings
            if f.rule_id == "AGENT-034"
            and ("Function" in f.description or "Function" in f.location.snippet)
        ]
        assert len(func_findings) >= 1


class TestChildProcessExec:
    """Test detection of child_process.exec calls."""

    def test_child_process_exec(self, scanner):
        """child_process.exec(cmd) should produce AGENT-034 finding."""
        path = _write_ts_file("""
            import { exec } from 'child_process';

            function runCommand(cmd: string) {
                exec(cmd, (error, stdout, stderr) => {
                    console.log(stdout);
                });
            }
        """)
        findings = scanner.scan_and_convert(path)
        exec_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(exec_findings) >= 1

    def test_child_process_spawn(self, scanner):
        """child_process.spawn should produce AGENT-034 finding."""
        path = _write_ts_file("""
            import { spawn } from 'child_process';

            function runProcess(cmd: string) {
                const proc = spawn(cmd, []);
                return proc;
            }
        """)
        findings = scanner.scan_and_convert(path)
        spawn_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(spawn_findings) >= 1

    def test_execa_detection(self, scanner):
        """execa() should produce AGENT-034 finding."""
        path = _write_ts_file("""
            import { execa } from 'execa';

            async function run(cmd: string) {
                const result = await execa(cmd);
                return result.stdout;
            }
        """)
        findings = scanner.scan_and_convert(path)
        execa_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(execa_findings) >= 1


class TestTemplateSQLInjection:
    """Test detection of SQL injection via template strings."""

    def test_template_sql_injection(self, scanner):
        """Template string with SQL keywords should produce AGENT-041."""
        path = _write_ts_file("""
            async function getUser(name: string) {
                const query = `SELECT * FROM users WHERE name = '${name}'`;
                return db.query(query);
            }
        """)
        findings = scanner.scan_and_convert(path)
        sql_findings = [f for f in findings if f.rule_id == "AGENT-041"]
        assert len(sql_findings) >= 1

    def test_template_insert_injection(self, scanner):
        """INSERT with template interpolation should produce AGENT-041."""
        path = _write_ts_file("""
            async function addUser(name: string, email: string) {
                const query = `INSERT INTO users (name, email) VALUES ('${name}', '${email}')`;
                return db.execute(query);
            }
        """)
        findings = scanner.scan_and_convert(path)
        sql_findings = [f for f in findings if f.rule_id == "AGENT-041"]
        assert len(sql_findings) >= 1

    def test_safe_parameterized_query_not_flagged(self, scanner):
        """Parameterized queries (no template interpolation) should not flag."""
        path = _write_ts_file("""
            async function getUser(name: string) {
                const query = 'SELECT * FROM users WHERE name = ?';
                return db.query(query, [name]);
            }
        """)
        findings = scanner.scan_and_convert(path)
        sql_findings = [f for f in findings if f.rule_id == "AGENT-041"]
        assert len(sql_findings) == 0


class TestTemplatePromptInjection:
    """Test detection of prompt injection via template strings."""

    def test_template_prompt_injection(self, scanner):
        """Template string in prompt context should produce AGENT-010."""
        path = _write_ts_file("""
            function buildPrompt(role: string) {
                const prompt = `You are ${role}. Follow instructions carefully.`;
                return prompt;
            }
        """)
        findings = scanner.scan_and_convert(path)
        prompt_findings = [f for f in findings if f.rule_id == "AGENT-010"]
        assert len(prompt_findings) >= 1

    def test_system_message_injection(self, scanner):
        """Template string assigned to systemMessage should produce AGENT-010."""
        path = _write_ts_file("""
            function buildSystem(userInput: string) {
                const systemMessage = `You are a helpful assistant. ${userInput}`;
                return systemMessage;
            }
        """)
        findings = scanner.scan_and_convert(path)
        prompt_findings = [f for f in findings if f.rule_id == "AGENT-010"]
        assert len(prompt_findings) >= 1


class TestFetchSSRF:
    """Test detection of SSRF via fetch/axios."""

    def test_fetch_ssrf(self, scanner):
        """fetch(userUrl) should produce AGENT-026 finding."""
        path = _write_ts_file("""
            async function getData(userUrl: string) {
                const response = await fetch(userUrl);
                return response.json();
            }
        """)
        findings = scanner.scan_and_convert(path)
        ssrf_findings = [f for f in findings if f.rule_id == "AGENT-026"]
        assert len(ssrf_findings) >= 1

    def test_hardcoded_fetch_low_confidence(self, scanner):
        """fetch with hardcoded URL should not produce a finding or have low confidence."""
        path = _write_ts_file("""
            async function getWeather() {
                const response = await fetch("https://api.example.com/weather");
                return response.json();
            }
        """)
        findings = scanner.scan_and_convert(path)
        ssrf_findings = [f for f in findings if f.rule_id == "AGENT-026"]
        # Should either have no findings or very low confidence
        for f in ssrf_findings:
            assert f.confidence < 0.50

    def test_axios_ssrf(self, scanner):
        """axios.get(url) with dynamic URL should produce AGENT-026."""
        path = _write_ts_file("""
            import axios from 'axios';

            async function fetchData(url: string) {
                const response = await axios.get(url);
                return response.data;
            }
        """)
        findings = scanner.scan_and_convert(path)
        ssrf_findings = [f for f in findings if f.rule_id == "AGENT-026"]
        assert len(ssrf_findings) >= 1


class TestSafePatterns:
    """Test that safe patterns are not falsely flagged."""

    def test_safe_json_parse_not_flagged(self, scanner):
        """JSON.parse(str) should NOT produce any finding."""
        path = _write_ts_file("""
            function parseConfig(data: string) {
                const config = JSON.parse(data);
                return config;
            }
        """)
        findings = scanner.scan_and_convert(path)
        # JSON.parse is safe - should not trigger any code execution finding
        exec_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(exec_findings) == 0

    def test_safe_template_no_interpolation(self, scanner):
        """Template string without interpolation should not flag SQL injection."""
        path = _write_ts_file("""
            const query = `SELECT * FROM users`;
            db.query(query);
        """)
        findings = scanner.scan_and_convert(path)
        sql_findings = [f for f in findings if f.rule_id == "AGENT-041"]
        assert len(sql_findings) == 0

    def test_comment_not_flagged(self, scanner):
        """Comments containing dangerous patterns should not be flagged."""
        path = _write_ts_file("""
            // eval(something) - this is just a comment
            // child_process.exec(cmd)
            const x = 42;
        """)
        findings = scanner.scan_and_convert(path)
        assert len(findings) == 0


class TestUnsafeDeserialization:
    """Test detection of unsafe deserialization patterns."""

    def test_node_serialize_detection(self, scanner):
        """require('node-serialize') should produce AGENT-049."""
        path = _write_ts_file("""
            const serialize = require('node-serialize');
            const obj = serialize.unserialize(data);
        """)
        findings = scanner.scan_and_convert(path)
        deser_findings = [f for f in findings if f.rule_id == "AGENT-049"]
        assert len(deser_findings) >= 1

    def test_unserialize_detection(self, scanner):
        """Direct unserialize() call should produce AGENT-049."""
        path = _write_ts_file("""
            const result = unserialize(userInput);
        """)
        findings = scanner.scan_and_convert(path)
        deser_findings = [f for f in findings if f.rule_id == "AGENT-049"]
        assert len(deser_findings) >= 1


class TestVmExecution:
    """Test detection of vm.runIn* calls."""

    def test_vm_run_in_context(self, scanner):
        """vm.runInContext should produce AGENT-034."""
        path = _write_ts_file("""
            import * as vm from 'vm';

            function executeCode(code: string) {
                const context = vm.createContext({});
                vm.runInContext(code, context);
            }
        """)
        findings = scanner.scan_and_convert(path)
        vm_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(vm_findings) >= 1

    def test_vm_run_in_new_context(self, scanner):
        """vm.runInNewContext should produce AGENT-034."""
        path = _write_ts_file("""
            import vm from 'vm';
            vm.runInNewContext(userCode, {});
        """)
        findings = scanner.scan_and_convert(path)
        vm_findings = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(vm_findings) >= 1


class TestFileExtensions:
    """Test that various file extensions are supported."""

    def test_tsx_file(self, scanner):
        """TSX files should be scanned."""
        path = _write_ts_file(
            """
            const result = eval(input);
        """,
            suffix=".tsx",
        )
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1

    def test_jsx_file(self, scanner):
        """JSX files should be scanned."""
        path = _write_ts_file(
            """
            const result = eval(input);
        """,
            suffix=".jsx",
        )
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1

    def test_mjs_file(self, scanner):
        """MJS files should be scanned."""
        path = _write_ts_file(
            """
            const result = eval(input);
        """,
            suffix=".mjs",
        )
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1

    def test_py_file_ignored(self, scanner):
        """Python files should NOT be scanned."""
        path = _write_ts_file(
            """
            eval(something)
        """,
            suffix=".py",
        )
        findings = scanner.scan_and_convert(path)
        assert len(findings) == 0


class TestScanAndConvert:
    """Test the scan_and_convert integration."""

    def test_finding_has_correct_location(self, scanner):
        """Findings should have correct file path and line numbers."""
        path = _write_ts_file("""
            const x = 1;
            const y = 2;
            const z = eval(something);
        """)
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.location.file_path == str(path)
        assert finding.location.start_line >= 1
        assert finding.location.snippet is not None

    def test_finding_has_correct_metadata(self, scanner):
        """Findings should have correct CWE and OWASP IDs."""
        path = _write_ts_file("""
            eval(userInput);
        """)
        findings = scanner.scan_and_convert(path)
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.rule_id == "AGENT-034"
        assert finding.cwe_id == "CWE-20"
        assert finding.owasp_id == "ASI-02"
        assert finding.tier in ("BLOCK", "WARN", "INFO", "SUPPRESSED")

    def test_empty_file_no_findings(self, scanner):
        """Empty files should produce no findings."""
        path = _write_ts_file("")
        findings = scanner.scan_and_convert(path)
        assert len(findings) == 0

    def test_directory_scanning(self, scanner, tmp_path):
        """Directory scanning should find files recursively."""
        sub_dir = tmp_path / "src"
        sub_dir.mkdir()

        ts_file = sub_dir / "app.ts"
        ts_file.write_text("const x = eval(input);", encoding="utf-8")

        safe_file = sub_dir / "safe.ts"
        safe_file.write_text("const x = 42;", encoding="utf-8")

        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) >= 1
        assert any("eval" in f.description for f in findings)
