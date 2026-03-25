"""JS/TS DeFi security scanner - regex-based multi-pattern detection.

Scans .js, .ts, .mjs, .mts, .jsx, .tsx files for DeFi-specific
security vulnerabilities using regular expressions. No Node.js
toolchain required.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from agent_audit.profiles.defi.rules import DeFiFinding, Severity


# Each pattern: (name, pattern_type, rule_id, regex, base_confidence, severity, message_template)
JS_TS_PATTERNS: List[Tuple[str, str, str, str, float, Severity, str]] = [
    # === AGENT-090: Private keys / credentials ===
    (
        'js_hardcoded_private_key',
        'defi_hardcoded_private_key', 'AGENT-090',
        r'''(?:privateKey|private_key|signingKey|secretKey|PRIVATE_KEY)\s*[:=]\s*["'`](0x[0-9a-fA-F]{64})["'`]''',
        0.95, Severity.CRITICAL,
        'Hardcoded Ethereum private key in JavaScript/TypeScript source code',
    ),
    (
        'js_wallet_constructor_key',
        'defi_key_in_api_call', 'AGENT-090',
        r'''new\s+(?:ethers\.)?Wallet\s*\(\s*["'`]0x[0-9a-fA-F]{64}["'`]''',
        0.98, Severity.CRITICAL,
        'Private key hardcoded in ethers.js Wallet constructor',
    ),
    (
        'js_mnemonic_phrase',
        'defi_hardcoded_mnemonic', 'AGENT-090',
        r'''(?:mnemonic|seedPhrase|seed_phrase|MNEMONIC)\s*[:=]\s*["'`]([a-z]+(?:\s+[a-z]+){11,23})["'`]''',
        0.93, Severity.CRITICAL,
        'BIP-39 mnemonic seed phrase hardcoded in source',
    ),

    # === AGENT-090: Private key exposure (logging/printing) ===
    (
        'js_private_key_exposure',
        'defi_key_exposure_log', 'AGENT-090',
        # console.log/warn/error with privateKey, or string interpolation with .privateKey
        r'''console\.(?:log|warn|error|info)\s*\([^)]*(?:privateKey|private_key|\.privateKey)''',
        0.92, Severity.CRITICAL,
        'Private key logged to console — key material exposed in stdout/stderr',
    ),

    # === AGENT-096: Unlimited approve via variable ===
    (
        'js_max_uint256_approve_variable',
        'defi_unlimited_token_approve', 'AGENT-096',
        # ethers.MaxUint256 assigned to variable, then used in approve flow
        r'''(?:MaxUint256|MAX_UINT256|UINT256_MAX|maxAmount\s*=\s*ethers\.MaxUint256)''',
        0.75, Severity.HIGH,
        'MaxUint256 value used — likely unlimited token approval pattern',
    ),

    # === AGENT-091: Transaction without amount limit ===
    (
        'js_send_no_limit',
        'defi_tx_no_amount_limit', 'AGENT-091',
        r'''\.sendTransaction\s*\(\s*\{[^}]*value\s*:''',
        0.60, Severity.HIGH,
        'Transaction sent via sendTransaction() — verify amount limits exist',
    ),
    (
        'js_swap_zero_slippage',
        'defi_swap_no_slippage_protection', 'AGENT-091',
        r'''swap(?:Exact)?(?:Tokens|ETH)(?:For)?(?:Tokens|ETH)\s*\([^,]+,\s*0\s*[,)]''',
        0.88, Severity.HIGH,
        'DEX swap with amountOutMin=0 — no slippage protection, vulnerable to sandwich attack',
    ),

    # === AGENT-093: Prompt to transaction ===
    (
        'js_dynamic_contract_address',
        'defi_tainted_contract_call', 'AGENT-093',
        r'''new\s+(?:ethers\.)?Contract\s*\(\s*(?:req\.|args\.|params\.|input\.|body\.)''',
        0.85, Severity.CRITICAL,
        'Contract instantiated with user-supplied address — potential contract injection',
    ),

    # === AGENT-094: RPC without TLS ===
    (
        'js_http_rpc',
        'defi_rpc_no_tls', 'AGENT-094',
        r'''(?:JsonRpcProvider|WebSocketProvider|HTTPProvider)\s*\(\s*["'`]http://(?!localhost|127\.0\.0\.1)''',
        0.85, Severity.MEDIUM,
        'Web3 provider uses unencrypted HTTP — transactions visible in plaintext',
    ),
    (
        'js_public_rpc',
        'defi_public_rpc_no_auth', 'AGENT-094',
        r'''(?:JsonRpcProvider|HTTPProvider)\s*\(\s*["'`]https?://(?:eth\.llamarpc\.com|rpc\.ankr\.com|ethereum\.publicnode\.com|1rpc\.io|cloudflare-eth\.com)''',
        0.65, Severity.MEDIUM,
        'Public RPC endpoint without API key — no rate limiting or authentication',
    ),

    # === AGENT-096: Unlimited approve ===
    (
        'js_unlimited_approve',
        'defi_unlimited_token_approve', 'AGENT-096',
        r'''\.approve\s*\([^,]+,\s*(?:ethers\.(?:constants\.)?MaxUint256|BigNumber\.from\s*\(\s*["'`]0x[fF]+["'`]\)|2\s*\*\*\s*256|"0x[fF]{64}")''',
        0.90, Severity.HIGH,
        'Unlimited token approval (MaxUint256) — grants permanent spending rights',
    ),

    # === AGENT-092: No human approval ===
    (
        'js_tool_sends_tx',
        'defi_tx_no_human_approval', 'AGENT-092',
        r'''(?:tool|handler|execute|run)\s*(?:[:=]|async)\s*(?:function)?\s*\([^)]*\)\s*(?:=>)?\s*\{[^}]*\.sendTransaction''',
        0.70, Severity.HIGH,
        'Tool/handler function sends blockchain transaction without human approval gate',
    ),

    # === AGENT-095: Missing gas limit ===
    (
        'js_missing_gas_limit',
        'defi_missing_gas_limit', 'AGENT-095',
        r'''\.sendTransaction\s*\(\s*\{(?![\s\S]*gasLimit)[\s\S]*?\}''',
        0.55, Severity.MEDIUM,
        'Transaction dictionary missing explicit gasLimit field',
    ),
]


class JsTsScanner:
    """JS/TS DeFi security scanner."""

    SUPPORTED_EXTENSIONS = {'.js', '.ts', '.mjs', '.mts', '.jsx', '.tsx'}

    def scan_file(self, file_path: str) -> List[DeFiFinding]:
        """Scan a file if it has a supported extension."""
        if not any(file_path.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
            return []
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
        except (OSError, IOError):
            return []
        return self.scan_content(file_path, content)

    def scan_content(self, file_path: str, content: str) -> List[DeFiFinding]:
        """Scan content string for JS/TS DeFi vulnerabilities."""
        findings: List[DeFiFinding] = []
        lines = content.split('\n')

        for name, pattern_type, rule_id, regex, base_conf, severity, msg_template in JS_TS_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                confidence = self._adjust_confidence(base_conf, file_path, lines, line_num)
                if confidence < 0.30:
                    continue
                findings.append(DeFiFinding(
                    rule_id=rule_id,
                    pattern_type=pattern_type,
                    file_path=file_path,
                    line=line_num,
                    confidence=confidence,
                    severity=severity,
                    message=msg_template,
                ))
        return findings

    def _adjust_confidence(
        self, base: float, path: str, lines: list, line: int
    ) -> float:
        """Reduce confidence for test files, comments, node_modules."""
        conf = base

        # node_modules: skip entirely
        if 'node_modules' in path:
            return 0.0

        # Test files: reduce significantly
        basename = path.split('/')[-1]
        if (
            basename.startswith('test')
            or '.test.' in basename
            or '.spec.' in basename
        ):
            conf *= 0.20

        # Comment lines: reduce
        if line <= len(lines):
            stripped = lines[line - 1].strip()
            if (
                stripped.startswith('//')
                or stripped.startswith('*')
                or stripped.startswith('/*')
            ):
                conf *= 0.10

        return conf
