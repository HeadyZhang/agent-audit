"""Tests for Solidity security scanner (AGENT-083, AGENT-084).

v0.20.0: Initial test suite for SolidityScanner with regex fallback.
"""

import pytest
from pathlib import Path
from agent_audit.scanners.solidity_scanner import SolidityScanner, SolidityScanResult


@pytest.fixture
def scanner():
    """Create a SolidityScanner instance."""
    return SolidityScanner()


class TestDelegatecallDetection:
    """AGENT-083: Unsafe delegatecall."""

    def test_delegatecall_detected(self, scanner, tmp_path):
        """delegatecall to storage variable should be flagged."""
        sol_file = tmp_path / "Proxy.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract Proxy {\n'
            '    address public implementation;\n'
            '\n'
            '    fallback() external payable {\n'
            '        implementation.delegatecall(msg.data);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent083 = [f for f in findings if f.rule_id == 'AGENT-083']
        assert len(agent083) >= 1
        assert agent083[0].severity.value == 'high'
        assert agent083[0].cwe_id == 'CWE-829'

    def test_delegatecall_with_param_high_confidence(self, scanner, tmp_path):
        """delegatecall to parameter variable should have high confidence."""
        sol_file = tmp_path / "DelegateParam.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract DelegateParam {\n'
            '    function forward(address target, bytes memory data) external {\n'
            '        target.delegatecall(data);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent083 = [f for f in findings if f.rule_id == 'AGENT-083']
        assert len(agent083) >= 1
        # Confidence is 0.80 from regex or 0.75/0.90 from Slither depending on availability
        assert agent083[0].confidence >= 0.60

    def test_no_delegatecall_safe(self, scanner, tmp_path):
        """Contract without delegatecall should not trigger AGENT-083."""
        sol_file = tmp_path / "Safe.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract Safe {\n'
            '    function transfer(address to, uint amount) external {\n'
            '        payable(to).transfer(amount);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent083 = [f for f in findings if f.rule_id == 'AGENT-083']
        assert len(agent083) == 0

    def test_delegatecall_in_comment_ignored(self, scanner, tmp_path):
        """delegatecall in a comment should not trigger."""
        sol_file = tmp_path / "Comment.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract Comment {\n'
            '    // target.delegatecall(msg.data); - old pattern\n'
            '    function safe() external pure returns (uint) {\n'
            '        return 42;\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent083 = [f for f in findings if f.rule_id == 'AGENT-083']
        assert len(agent083) == 0


class TestTxOriginDetection:
    """AGENT-084: tx.origin authentication."""

    def test_tx_origin_require_detected(self, scanner, tmp_path):
        """require(tx.origin == ...) should be flagged."""
        sol_file = tmp_path / "Auth.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract Auth {\n'
            '    address public owner;\n'
            '\n'
            '    function withdraw() external {\n'
            '        require(tx.origin == owner, "Not owner");\n'
            '        payable(owner).transfer(address(this).balance);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent084 = [f for f in findings if f.rule_id == 'AGENT-084']
        assert len(agent084) >= 1
        # Severity is HIGH from regex or MEDIUM from Slither depending on availability
        assert agent084[0].severity.value in ('high', 'medium')
        assert agent084[0].cwe_id == 'CWE-287'
        # Confidence is 0.90 from regex or 0.75 from Slither
        assert agent084[0].confidence >= 0.60

    def test_tx_origin_owner_assign_detected(self, scanner, tmp_path):
        """owner = tx.origin should be flagged."""
        sol_file = tmp_path / "OwnerAssign.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract OwnerAssign {\n'
            '    address public owner;\n'
            '\n'
            '    constructor() {\n'
            '        owner = tx.origin;\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent084 = [f for f in findings if f.rule_id == 'AGENT-084']
        assert len(agent084) >= 1

    def test_msg_sender_safe(self, scanner, tmp_path):
        """msg.sender authentication should NOT trigger AGENT-084."""
        sol_file = tmp_path / "SafeAuth.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract SafeAuth {\n'
            '    address public owner;\n'
            '\n'
            '    function withdraw() external {\n'
            '        require(msg.sender == owner, "Not owner");\n'
            '        payable(owner).transfer(address(this).balance);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        agent084 = [f for f in findings if f.rule_id == 'AGENT-084']
        assert len(agent084) == 0


class TestGracefulDegradation:
    """Test scanner works without Slither."""

    def test_regex_fallback_works(self, scanner, tmp_path):
        """Both patterns should be detected via regex even without Slither."""
        sol_file = tmp_path / "Mixed.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            '\n'
            'contract Mixed {\n'
            '    address public impl;\n'
            '\n'
            '    function exec(bytes memory data) external {\n'
            '        impl.delegatecall(data);\n'
            '    }\n'
            '\n'
            '    modifier onlyOwner() {\n'
            '        require(tx.origin == msg.sender);\n'
            '        _;\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert 'AGENT-083' in rule_ids
        assert 'AGENT-084' in rule_ids

    def test_single_file_scan(self, scanner, tmp_path):
        """Scanner should work on a single file path."""
        sol_file = tmp_path / "Single.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Single {\n'
            '    function exec(address t) external {\n'
            '        t.delegatecall("");\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(sol_file)
        assert len(findings) >= 1
        assert findings[0].rule_id == 'AGENT-083'

    def test_empty_directory_returns_empty(self, scanner, tmp_path):
        """Empty directory should return no findings."""
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) == 0

    def test_non_sol_files_ignored(self, scanner, tmp_path):
        """Non-Solidity files should be skipped."""
        py_file = tmp_path / "contract.py"
        py_file.write_text("# delegatecall not relevant here\n")
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) == 0


class TestFileDiscovery:
    """Test file discovery and exclusion."""

    def test_skip_node_modules(self, scanner, tmp_path):
        """Files in node_modules should be skipped."""
        nm_dir = tmp_path / "node_modules" / "lib"
        nm_dir.mkdir(parents=True)
        sol_file = nm_dir / "Proxy.sol"
        sol_file.write_text(
            'contract Proxy { function f() { impl.delegatecall(""); } }\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) == 0

    def test_skip_forge_std(self, scanner, tmp_path):
        """Files in forge-std should be skipped."""
        lib_dir = tmp_path / "forge-std" / "src"
        lib_dir.mkdir(parents=True)
        sol_file = lib_dir / "Vm.sol"
        sol_file.write_text(
            'contract Vm { function f() { impl.delegatecall(""); } }\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) == 0

    def test_exclude_patterns(self, tmp_path):
        """Files matching exclude patterns should be skipped."""
        scanner = SolidityScanner(exclude_patterns=["test_contracts"])
        test_dir = tmp_path / "test_contracts"
        test_dir.mkdir()
        sol_file = test_dir / "TestProxy.sol"
        sol_file.write_text(
            'contract TestProxy { function f() { impl.delegatecall(""); } }\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) == 0


class TestScanResult:
    """Test SolidityScanResult structure."""

    def test_result_has_correct_fields(self, scanner, tmp_path):
        """SolidityScanResult should have findings and slither_available."""
        sol_file = tmp_path / "Test.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Test {\n'
            '    function f(address t) external {\n'
            '        t.delegatecall("");\n'
            '    }\n'
            '}\n'
        )
        results = scanner.scan(tmp_path)
        assert len(results) >= 1
        result = results[0]
        assert isinstance(result, SolidityScanResult)
        assert result.source_file == str(sol_file)
        assert isinstance(result.findings, list)
        assert isinstance(result.slither_available, bool)

    def test_finding_fields(self, scanner, tmp_path):
        """Findings should have all required fields."""
        sol_file = tmp_path / "Fields.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Fields {\n'
            '    function f() external {\n'
            '        require(tx.origin == msg.sender);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == 'AGENT-084'
        assert f.title is not None
        assert f.description is not None
        assert f.severity is not None
        assert f.category is not None
        assert f.location is not None
        assert f.location.file_path == str(sol_file)
        assert f.location.start_line == 4
        assert f.cwe_id == 'CWE-287'
        assert f.confidence == 0.90
        assert f.tier is not None
        assert f.remediation is not None


class TestMultipleFiles:
    """Test scanning across multiple files."""

    def test_multiple_sol_files(self, scanner, tmp_path):
        """Scanner should find issues across multiple files."""
        file1 = tmp_path / "Proxy.sol"
        file1.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Proxy {\n'
            '    function f(address t) external {\n'
            '        t.delegatecall("");\n'
            '    }\n'
            '}\n'
        )
        file2 = tmp_path / "Auth.sol"
        file2.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Auth {\n'
            '    function f() external {\n'
            '        require(tx.origin == msg.sender);\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert 'AGENT-083' in rule_ids
        assert 'AGENT-084' in rule_ids
        # Verify different files
        file_paths = {f.location.file_path for f in findings}
        assert len(file_paths) == 2

    def test_nested_directory_scan(self, scanner, tmp_path):
        """Scanner should find files in nested directories."""
        sub_dir = tmp_path / "contracts" / "proxy"
        sub_dir.mkdir(parents=True)
        sol_file = sub_dir / "Proxy.sol"
        sol_file.write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Proxy {\n'
            '    function f(address t) external {\n'
            '        t.delegatecall("");\n'
            '    }\n'
            '}\n'
        )
        findings = scanner.scan_and_convert(tmp_path)
        assert len(findings) >= 1
