"""DeFi profile rule definitions and Finding data model.

Renumbered from defi-shield AGENT-063..082 to AGENT-090..109
to avoid collision with agent-audit core rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum




class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Tier(Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    INFO = "INFO"
    SUPPRESSED = "SUPPRESSED"


def confidence_to_tier(confidence: float) -> Tier:
    if confidence >= 0.92:
        return Tier.BLOCK
    if confidence >= 0.60:
        return Tier.WARN
    if confidence >= 0.30:
        return Tier.INFO
    return Tier.SUPPRESSED


@dataclass
class DeFiFinding:
    rule_id: str
    pattern_type: str
    file_path: str
    line: int
    column: int = 0
    message: str = ""
    confidence: float = 0.0
    severity: Severity = Severity.MEDIUM
    tier: Tier = field(init=False)
    cwe: str = ""
    owasp_agentic: str = ""
    remediation: str = ""

    def __post_init__(self):
        self.tier = confidence_to_tier(self.confidence)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "pattern_type": self.pattern_type,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "tier": self.tier.value,
            "cwe": self.cwe,
            "owasp_agentic": self.owasp_agentic,
            "remediation": self.remediation,
        }


DEFI_RULES = {
    'AGENT-090': {
        'name': 'DeFi Private Key / Seed Phrase Exposure',
        'cwe': 'CWE-798',
        'owasp': 'ASI-03',
        'severity': Severity.CRITICAL,
        'description': (
            'Hardcoded blockchain private key, mnemonic seed phrase, '
            'or keystore password detected. This enables complete control '
            'over associated wallet funds.'
        ),
        'remediation': (
            'Store private keys in environment variables, use HSM/KMS, '
            'or implement MPC wallet solutions. Never hardcode keys in source code.'
        ),
    },
    'AGENT-091': {
        'name': 'DeFi Transaction Without Amount Limit',
        'cwe': 'CWE-770',
        'owasp': 'ASI-02',
        'severity': Severity.HIGH,
        'description': (
            'Blockchain transaction sent without amount validation or spending limits. '
            'An AI agent could be manipulated into sending unlimited funds.'
        ),
        'remediation': (
            'Implement per-transaction and daily cumulative spending limits. '
            'Validate transaction amounts against configurable thresholds before signing.'
        ),
    },
    'AGENT-092': {
        'name': 'DeFi Transaction Without Human Approval',
        'cwe': 'CWE-862',
        'owasp': 'ASI-09',
        'severity': Severity.HIGH,
        'description': (
            'AI agent tool function sends blockchain transactions without '
            'human-in-the-loop approval gate. Prompt injection could trigger '
            'unauthorized fund transfers.'
        ),
        'remediation': (
            'Require human approval for transactions above a threshold. '
            'Implement multi-signature or time-delayed transaction execution.'
        ),
    },
    'AGENT-093': {
        'name': 'Prompt Input to Blockchain Transaction (Taint Flow)',
        'cwe': 'CWE-74',
        'owasp': 'ASI-01',
        'severity': Severity.CRITICAL,
        'description': (
            'User/prompt input flows unsanitized into blockchain transaction '
            'parameters (recipient address, amount, or contract call data). '
            'This enables prompt injection to fund theft attacks.'
        ),
        'remediation': (
            'Validate all transaction parameters against allowlists. '
            'Never pass raw user input to transaction signing. '
            'Implement address whitelisting and amount bounds checking.'
        ),
    },
    'AGENT-094': {
        'name': 'Blockchain RPC Endpoint Without TLS',
        'cwe': 'CWE-319',
        'owasp': 'ASI-07',
        'severity': Severity.MEDIUM,
        'description': (
            'Web3 provider connects via unencrypted HTTP/WS. '
            'Signed transactions and private data are transmitted in cleartext.'
        ),
        'remediation': (
            'Use HTTPS/WSS endpoints. For local development, '
            'ensure RPC is not exposed to the network.'
        ),
    },
    'AGENT-095': {
        'name': 'Missing Gas Limit Configuration',
        'cwe': 'CWE-770',
        'owasp': 'ASI-08',
        'severity': Severity.MEDIUM,
        'description': (
            'Transaction dictionary missing explicit gas limit. '
            'Node auto-estimation may result in excessive gas consumption.'
        ),
        'remediation': (
            'Always set explicit gas limits in transaction parameters. '
            'Implement gas price monitoring and caps.'
        ),
    },
    'AGENT-096': {
        'name': 'Unlimited Token Approval (Allowance)',
        'cwe': 'CWE-250',
        'owasp': 'ASI-03',
        'severity': Severity.HIGH,
        'description': (
            'ERC-20 approve() called with MAX_UINT256 or extremely large value. '
            'Grants permanent unlimited spending rights to the approved address.'
        ),
        'remediation': (
            'Approve only the exact amount needed for the current transaction. '
            'Reset allowance to 0 after use.'
        ),
    },
    'AGENT-097': {
        'name': 'Missing Transaction Nonce Management',
        'cwe': 'CWE-362',
        'owasp': 'ASI-08',
        'severity': Severity.LOW,
        'description': (
            'Transaction sent without explicit nonce. '
            'Concurrent transactions may conflict or be replayed.'
        ),
        'remediation': (
            'Implement local nonce tracking with atomic increments '
            'for concurrent transaction scenarios.'
        ),
    },
    'AGENT-098': {
        'name': 'Missing MEV Protection',
        'cwe': 'CWE-311',
        'owasp': 'ASI-02',
        'severity': Severity.MEDIUM,
        'description': (
            'DEX swap transactions sent through public mempool without MEV protection. '
            'Vulnerable to sandwich attacks and front-running.'
        ),
        'remediation': (
            'Use Flashbots Protect, MEV Blocker, or private transaction relayers '
            'for swap transactions.'
        ),
    },
    'AGENT-099': {
        'name': 'Reentrancy Vulnerability (Solidity)',
        'cwe': 'CWE-841',
        'owasp': 'ASI-02',
        'severity': Severity.CRITICAL,
        'description': (
            'Smart contract contains reentrancy vulnerability — external call '
            'before state update allows attacker to re-enter and drain funds.'
        ),
        'remediation': (
            'Apply checks-effects-interactions pattern. Use OpenZeppelin '
            'ReentrancyGuard. Update state before external calls.'
        ),
    },
    'AGENT-100': {
        'name': 'Integer Overflow / Unchecked Arithmetic (Solidity)',
        'cwe': 'CWE-190',
        'owasp': 'ASI-02',
        'severity': Severity.MEDIUM,
        'description': (
            'Arithmetic operation without overflow protection. Solidity < 0.8.0 '
            'is vulnerable by default; >= 0.8.0 with unchecked blocks reintroduces risk.'
        ),
        'remediation': (
            'Use Solidity >= 0.8.0. Avoid unchecked blocks for user-facing math. '
            'Use SafeMath for legacy contracts.'
        ),
    },
    'AGENT-101': {
        'name': 'Access Control Violation (Solidity)',
        'cwe': 'CWE-284',
        'owasp': 'ASI-03',
        'severity': Severity.HIGH,
        'description': (
            'Sensitive contract function missing access control modifier. '
            'Unauthorized users can call privileged operations.'
        ),
        'remediation': (
            'Add onlyOwner / onlyRole modifiers. Use OpenZeppelin AccessControl. '
            'Implement multi-sig for critical operations.'
        ),
    },
    'AGENT-102': {
        'name': 'Flash Loan / Oracle Manipulation Risk (Solidity)',
        'cwe': 'CWE-840',
        'owasp': 'ASI-02',
        'severity': Severity.HIGH,
        'description': (
            'Contract relies on manipulable price oracle or spot price, '
            'vulnerable to flash loan price manipulation attacks.'
        ),
        'remediation': (
            'Use TWAP oracles, multiple oracle sources, or Chainlink price feeds. '
            'Add flash loan guards and price deviation checks.'
        ),
    },
    'AGENT-103': {
        'name': 'Agent Payment Mandate Without Amount Cap',
        'cwe': 'CWE-770',
        'owasp': 'ASI-02',
        'severity': Severity.HIGH,
        'description': (
            'Payment mandate/authorization object constructed without maximum amount cap. '
            'An AI agent could be manipulated into authorizing unlimited payments.'
        ),
        'remediation': (
            'Always include maxAmount or amount_cap field in payment mandate objects. '
            'Implement per-transaction and daily cumulative spending limits.'
        ),
    },
    'AGENT-104': {
        'name': 'Hardcoded Settlement Processor Address',
        'cwe': 'CWE-798',
        'owasp': 'ASI-03',
        'severity': Severity.HIGH,
        'description': (
            'Settlement processor contract address hardcoded in source code. '
            'Address rotation or migration requires code changes and redeployment.'
        ),
        'remediation': (
            'Store settlement processor addresses in environment variables or '
            'configuration files. Use address registry contracts for on-chain lookups.'
        ),
    },
    'AGENT-105': {
        'name': 'Payment Header Without Replay Protection',
        'cwe': 'CWE-294',
        'owasp': 'ASI-07',
        'severity': Severity.HIGH,
        'description': (
            'Payment authorization header (X-Payment-Mandate/X-Payment) constructed '
            'without nonce, deadline, or chainId. Vulnerable to replay attacks.'
        ),
        'remediation': (
            'Include nonce, deadline/expiration, and chainId in all payment headers. '
            'Implement server-side nonce tracking to prevent replay.'
        ),
    },
    'AGENT-106': {
        'name': 'Withdrawal Delay Bypass Risk',
        'cwe': 'CWE-269',
        'owasp': 'ASI-02',
        'severity': Severity.MEDIUM,
        'description': (
            'Withdrawal or fund transfer operation without time-delay mechanism. '
            'Compromised agent can immediately drain funds without recovery window.'
        ),
        'remediation': (
            'Implement configurable withdrawal delays for amounts above threshold. '
            'Add cancellation window for pending withdrawals.'
        ),
    },
    'AGENT-107': {
        'name': 'Agent JWT/Bearer Token in Code',
        'cwe': 'CWE-798',
        'owasp': 'ASI-03',
        'severity': Severity.HIGH,
        'description': (
            'Agent authentication token (JWT/Bearer) hardcoded in source code. '
            'Exposed token enables unauthorized agent impersonation.'
        ),
        'remediation': (
            'Store agent tokens in environment variables or secure vault. '
            'Implement token rotation and short-lived token issuance.'
        ),
    },
    'AGENT-108': {
        'name': 'MCP Tool Without Payment Amount Validation',
        'cwe': 'CWE-20',
        'owasp': 'ASI-09',
        'severity': Severity.MEDIUM,
        'description': (
            'MCP tool definition accepts amount/value/price parameter without '
            'schema-level validation (maximum, minimum, enum constraint). '
            'Agent can be tricked into processing arbitrary payment amounts.'
        ),
        'remediation': (
            'Add maximum/minimum constraints to amount parameters in MCP tool schema. '
            'Implement server-side amount validation before processing.'
        ),
    },
    'AGENT-109': {
        'name': 'Settlement Without Event Emission',
        'cwe': 'CWE-778',
        'owasp': 'ASI-08',
        'severity': Severity.MEDIUM,
        'description': (
            'Settlement or payment state change executed without emitting events/logs. '
            'Makes auditing and monitoring of agent payment activity difficult.'
        ),
        'remediation': (
            'Emit events for all settlement state changes. '
            'Include transaction hash, amount, parties, and timestamp in events.'
        ),
    },
}


def make_finding(
    rule_id: str,
    pattern_type: str,
    file_path: str,
    line: int,
    confidence: float,
    message: str = "",
    column: int = 0,
) -> DeFiFinding:
    """Create a DeFiFinding with rule metadata auto-populated."""
    rule = DEFI_RULES.get(rule_id, {})
    return DeFiFinding(
        rule_id=rule_id,
        pattern_type=pattern_type,
        file_path=file_path,
        line=line,
        column=column,
        message=message or str(rule.get('description', '')),
        confidence=confidence,
        severity=rule.get('severity') or Severity.MEDIUM,  # type: ignore[arg-type]
        cwe=str(rule.get('cwe', '')),
        owasp_agentic=str(rule.get('owasp', '')),
        remediation=str(rule.get('remediation', '')),
    )
