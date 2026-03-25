"""Tests for DeFi agent security profile (AGENT-090 through AGENT-109).

Covers all DeFi profile scanners: web3_ast_visitor, defi_secret_scanner,
js_ts_scanner, agent_payment_scanner, rpc_analyzer, and the profile
entry point.
"""

import pytest

from agent_audit.profiles.defi import scan_target, RULE_COUNT, PROFILE_NAME
from agent_audit.profiles.defi.rules import (
    DEFI_RULES, DeFiFinding, Severity, Tier, make_finding, confidence_to_tier,
)
from agent_audit.profiles.defi.scanners.web3_ast_visitor import Web3ASTVisitor
from agent_audit.profiles.defi.scanners.defi_secret_scanner import DeFiSecretScanner
from agent_audit.profiles.defi.scanners.js_ts_scanner import JsTsScanner
from agent_audit.profiles.defi.scanners.agent_payment_scanner import scan_agent_payment
from agent_audit.profiles.defi.analysis.rpc_analyzer import RPCAnalyzer
from agent_audit.profiles.defi.analysis.defi_taint_extensions import SimpleDeFiTaintTracker


# ================================================================
# Profile metadata
# ================================================================

class TestProfileMetadata:
    def test_profile_name(self):
        assert PROFILE_NAME == "defi"

    def test_rule_count(self):
        assert RULE_COUNT == 20

    def test_all_rules_renumbered(self):
        for rule_id in DEFI_RULES:
            num = int(rule_id.split('-')[1])
            assert 90 <= num <= 109, f"{rule_id} outside AGENT-090..109 range"


# ================================================================
# Rules and findings model
# ================================================================

class TestDeFiRules:
    def test_make_finding_populates_metadata(self):
        f = make_finding(
            rule_id='AGENT-090',
            pattern_type='test',
            file_path='test.py',
            line=1,
            confidence=0.95,
        )
        assert f.rule_id == 'AGENT-090'
        assert f.cwe == 'CWE-798'
        assert f.owasp_agentic == 'ASI-03'
        assert f.severity == Severity.CRITICAL
        assert f.tier == Tier.BLOCK

    def test_make_finding_unknown_rule(self):
        f = make_finding(
            rule_id='AGENT-999',
            pattern_type='test',
            file_path='test.py',
            line=1,
            confidence=0.50,
            message='custom message',
        )
        assert f.message == 'custom message'
        assert f.severity == Severity.MEDIUM

    def test_confidence_to_tier(self):
        assert confidence_to_tier(0.95) == Tier.BLOCK
        assert confidence_to_tier(0.70) == Tier.WARN
        assert confidence_to_tier(0.40) == Tier.INFO
        assert confidence_to_tier(0.10) == Tier.SUPPRESSED

    def test_finding_to_dict(self):
        f = make_finding('AGENT-091', 'test', 'f.py', 1, 0.80)
        d = f.to_dict()
        assert d['rule_id'] == 'AGENT-091'
        assert d['tier'] == 'WARN'
        assert isinstance(d['confidence'], float)


# ================================================================
# AGENT-090: DeFi private key / seed phrase exposure
# ================================================================

class TestDeFiSecretScanner:
    @pytest.fixture
    def scanner(self):
        return DeFiSecretScanner()

    def test_hardcoded_private_key_detected(self, scanner):
        code = 'private_key = "0x' + 'a1b2c3d4' * 8 + '"'
        findings = scanner.scan_content('wallet.py', code)
        assert any(f.rule_id == 'AGENT-090' for f in findings)

    def test_placeholder_key_suppressed(self, scanner):
        code = 'private_key = "0x' + '00' * 32 + '"'
        findings = scanner.scan_content('wallet.py', code)
        high_conf = [f for f in findings if f.confidence >= 0.30]
        assert len(high_conf) == 0

    def test_mnemonic_detected(self, scanner):
        words = 'abandon ' * 11 + 'about'
        code = f'mnemonic = "{words}"'
        findings = scanner.scan_content('config.py', code)
        assert any(f.pattern_type == 'defi_hardcoded_mnemonic' for f in findings)

    def test_test_file_reduced_confidence(self, scanner):
        code = 'private_key = "0x' + 'a1b2c3d4' * 8 + '"'
        findings = scanner.scan_content('test_wallet.py', code)
        if findings:
            assert all(f.confidence < 0.30 for f in findings)

    def test_key_in_api_call(self, scanner):
        code = 'account = Account.from_key("0x' + 'ab12cd34' * 8 + '")'
        findings = scanner.scan_content('deploy.py', code)
        assert any(f.pattern_type == 'defi_key_in_api_call' for f in findings)


# ================================================================
# AGENT-091: Transaction without amount limit
# ================================================================

class TestTransactionNoAmountLimit:
    def test_send_transaction_no_limit(self):
        code = '''
from web3 import Web3
def transfer(w3):
    w3.eth.send_transaction({'to': addr, 'value': amount})
'''
        visitor = Web3ASTVisitor('agent.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-091' for f in findings)

    def test_send_transaction_with_limit_check(self):
        code = '''
from web3 import Web3
def transfer(w3, amount):
    if amount > MAX_LIMIT:
        raise ValueError("too much")
    w3.eth.send_transaction({'to': addr, 'value': amount})
'''
        visitor = Web3ASTVisitor('agent.py')
        findings = visitor.scan(code)
        limit_findings = [f for f in findings if f.rule_id == 'AGENT-091'
                         and f.pattern_type == 'defi_tx_no_amount_limit']
        assert len(limit_findings) == 0

    def test_swap_zero_slippage_detected(self):
        code = '''
from web3 import Web3
def do_swap(router):
    router.functions.swapExactTokensForETH(amount, 0, path, to, deadline)
'''
        visitor = Web3ASTVisitor('swap.py')
        findings = visitor.scan(code)
        assert any(f.pattern_type == 'defi_swap_no_slippage_protection' for f in findings)


# ================================================================
# AGENT-092: Transaction without human approval
# ================================================================

class TestNoHumanApproval:
    def test_tool_sends_tx_no_approval(self):
        code = '''
from langchain.tools import tool
@tool
def send_funds(recipient: str, amount: int):
    w3.eth.send_transaction({'to': recipient, 'value': amount})
'''
        visitor = Web3ASTVisitor('tools.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-092' for f in findings)

    def test_tool_with_approval_gate_ok(self):
        code = '''
from langchain.tools import tool
@tool
def send_funds(recipient: str, amount: int):
    if not human_approval(recipient, amount):
        return "rejected"
    w3.eth.send_transaction({'to': recipient, 'value': amount})
'''
        visitor = Web3ASTVisitor('tools.py')
        findings = visitor.scan(code)
        assert not any(f.rule_id == 'AGENT-092' for f in findings)


# ================================================================
# AGENT-093: Prompt input to blockchain transaction (taint)
# ================================================================

class TestTaintFlow:
    def test_tainted_param_to_tx_sink(self):
        import ast
        code = '''
def send(recipient, amount):
    tx = {'to': recipient, 'value': amount}
    w3.eth.send_transaction(tx)
'''
        tree = ast.parse(code)
        func = tree.body[0]
        tracker = SimpleDeFiTaintTracker('tools.py')
        findings = tracker.analyze_function(func, is_tool=True)
        assert any(f.rule_id == 'AGENT-093' for f in findings)

    def test_sanitized_param_no_finding(self):
        import ast
        code = '''
def send(recipient, amount):
    if not is_address(recipient):
        raise ValueError("bad address")
    if amount > MAX_LIMIT:
        raise ValueError("too much")
    w3.eth.send_transaction({'to': recipient, 'value': amount})
'''
        tree = ast.parse(code)
        func = tree.body[0]
        tracker = SimpleDeFiTaintTracker('tools.py')
        findings = tracker.analyze_function(func, is_tool=True)
        assert not any(f.rule_id == 'AGENT-093' for f in findings)


# ================================================================
# AGENT-094: RPC without TLS
# ================================================================

class TestRPCAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return RPCAnalyzer()

    def test_http_rpc_detected(self, analyzer):
        code = 'w3 = Web3(HTTPProvider("http://mainnet.infura.io/v3/key"))'
        findings = analyzer.analyze_file('config.py', code)
        assert any(f.rule_id == 'AGENT-094' for f in findings)

    def test_https_rpc_ok(self, analyzer):
        code = 'w3 = Web3(HTTPProvider("https://mainnet.infura.io/v3/key"))'
        findings = analyzer.analyze_file('config.py', code)
        tls_findings = [f for f in findings if f.pattern_type == 'defi_rpc_no_tls']
        assert len(tls_findings) == 0

    def test_localhost_reduced_confidence(self, analyzer):
        code = 'w3 = Web3(HTTPProvider("http://localhost:8545"))'
        findings = analyzer.analyze_file('config.py', code)
        if findings:
            assert all(f.confidence < 0.50 for f in findings)

    def test_public_rpc_no_auth(self, analyzer):
        code = 'w3 = Web3(HTTPProvider("https://eth.llamarpc.com"))'
        findings = analyzer.analyze_file('config.py', code)
        assert any(f.pattern_type == 'defi_public_rpc_no_auth' for f in findings)


# ================================================================
# AGENT-095 / AGENT-097: Transaction dict checks
# ================================================================

class TestTransactionDict:
    def test_missing_gas_limit(self):
        code = '''
tx = {'to': addr, 'value': 100, 'nonce': 0}
'''
        visitor = Web3ASTVisitor('send.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-095' for f in findings)

    def test_missing_nonce(self):
        code = '''
tx = {'to': addr, 'value': 100, 'gas': 21000}
'''
        visitor = Web3ASTVisitor('send.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-097' for f in findings)

    def test_complete_tx_dict_ok(self):
        code = '''
tx = {'to': addr, 'value': 100, 'gas': 21000, 'nonce': 0}
'''
        visitor = Web3ASTVisitor('send.py')
        findings = visitor.scan(code)
        assert not any(f.rule_id == 'AGENT-095' for f in findings)
        assert not any(f.rule_id == 'AGENT-097' for f in findings)


# ================================================================
# AGENT-096: Unlimited token approval
# ================================================================

class TestUnlimitedApprove:
    def test_max_uint256_approve(self):
        code = '''
token.functions.approve(spender, 2**256 - 1).transact()
'''
        visitor = Web3ASTVisitor('defi.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-096' for f in findings)

    def test_exact_amount_approve_ok(self):
        code = '''
token.functions.approve(spender, 1000).transact()
'''
        visitor = Web3ASTVisitor('defi.py')
        findings = visitor.scan(code)
        assert not any(f.rule_id == 'AGENT-096' for f in findings)


# ================================================================
# AGENT-098: Missing MEV protection
# ================================================================

class TestMEVProtection:
    def test_swap_without_flashbots(self):
        code = '''
from web3 import Web3
def do_swap(router):
    router.functions.swapExactTokensForETH(amount, min_out, path, to, deadline)
'''
        visitor = Web3ASTVisitor('swap.py')
        findings = visitor.scan(code)
        assert any(f.rule_id == 'AGENT-098' for f in findings)

    def test_swap_with_flashbots_ok(self):
        code = '''
from web3 import Web3
from flashbots import flashbot
def do_swap(router):
    router.functions.swapExactTokensForETH(amount, min_out, path, to, deadline)
'''
        visitor = Web3ASTVisitor('swap.py')
        findings = visitor.scan(code)
        assert not any(f.rule_id == 'AGENT-098' for f in findings)


# ================================================================
# AGENT-103..109: Agent payment scanner
# ================================================================

class TestAgentPaymentScanner:
    def test_mandate_without_cap(self):
        code = 'mandate = {"type": "payment", "amount": 500, "recipient": addr}'
        findings = scan_agent_payment('pay.py', code)
        assert any(f.rule_id == 'AGENT-103' for f in findings)

    def test_hardcoded_settlement_address(self):
        code = 'settlement_processor = "0x' + 'aB' * 20 + '"'
        findings = scan_agent_payment('pay.py', code)
        assert any(f.rule_id == 'AGENT-104' for f in findings)

    def test_payment_header_no_replay_protect(self):
        code = 'headers["X-Payment-Mandate"] = token'
        findings = scan_agent_payment('api.py', code)
        assert any(f.rule_id == 'AGENT-105' for f in findings)

    def test_withdrawal_no_delay(self):
        code = 'def process(): withdraw(amount)'
        findings = scan_agent_payment('vault.py', code)
        assert any(f.rule_id == 'AGENT-106' for f in findings)

    def test_skips_test_files(self):
        code = 'settlement_processor = "0x' + 'aB' * 20 + '"'
        findings = scan_agent_payment('test_pay.py', code)
        assert len(findings) == 0


# ================================================================
# JS/TS scanner
# ================================================================

class TestJsTsScanner:
    @pytest.fixture
    def scanner(self):
        return JsTsScanner()

    def test_hardcoded_private_key_js(self, scanner):
        code = 'const privateKey = "0x' + 'ab12cd34' * 8 + '";'
        findings = scanner.scan_content('wallet.ts', code)
        assert any(f.rule_id == 'AGENT-090' for f in findings)

    def test_http_rpc_js(self, scanner):
        code = 'const provider = new JsonRpcProvider("http://mainnet.example.com");'
        findings = scanner.scan_content('config.ts', code)
        assert any(f.rule_id == 'AGENT-094' for f in findings)

    def test_node_modules_skipped(self, scanner):
        code = 'const privateKey = "0x' + 'ab12cd34' * 8 + '";'
        findings = scanner.scan_content('node_modules/pkg/index.js', code)
        assert len(findings) == 0

    def test_unlimited_approve_js(self, scanner):
        code = 'await token.approve(spender, ethers.MaxUint256);'
        findings = scanner.scan_content('defi.ts', code)
        assert any(f.rule_id == 'AGENT-096' for f in findings)


# ================================================================
# Profile entry point (scan_target)
# ================================================================

class TestProfileScanTarget:
    def test_scan_vulnerable_file(self, tmp_path):
        vuln = tmp_path / "agent.py"
        vuln.write_text(
            'private_key = "0x' + 'a1b2c3d4' * 8 + '"\n'
            'tx = {"to": addr, "value": 100}\n'
        )
        findings = scan_target(str(tmp_path))
        assert len(findings) > 0
        rule_ids = {f.rule_id for f in findings}
        assert 'AGENT-090' in rule_ids

    def test_scan_safe_file(self, tmp_path):
        safe = tmp_path / "hello.py"
        safe.write_text('print("hello world")\n')
        findings = scan_target(str(tmp_path))
        assert len(findings) == 0

    def test_scan_js_file(self, tmp_path):
        vuln = tmp_path / "config.ts"
        vuln.write_text(
            'const privateKey = "0x' + 'ab12cd34' * 8 + '";\n'
        )
        findings = scan_target(str(tmp_path))
        assert any(f.rule_id == 'AGENT-090' for f in findings)

    def test_scan_skips_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        hidden = git_dir / "config.py"
        hidden.write_text('private_key = "0x' + 'a1b2c3d4' * 8 + '"\n')
        findings = scan_target(str(tmp_path))
        assert len(findings) == 0
