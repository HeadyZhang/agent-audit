"""Agent Payment Security Scanner.

Detects security issues in AI agent payment patterns including:
- Payment mandates without caps (AGENT-103)
- Hardcoded settlement addresses (AGENT-104)
- Payment headers without replay protection (AGENT-105)
- Withdrawal without delays (AGENT-106)
- Agent JWT in code (AGENT-107)
- Settlement without events (AGENT-109)
"""

from __future__ import annotations

import re
from typing import List

from agent_audit.profiles.defi.rules import make_finding, DeFiFinding


# AGENT-103: Payment mandate without amount cap
MANDATE_PATTERNS = [
    re.compile(
        r'(?:mandate|payment|authorization)\s*[=:]\s*\{[^}]*\bamount\b[^}]*\}',
        re.IGNORECASE | re.DOTALL,
    ),
]
MANDATE_CAP_KEYWORDS = re.compile(
    r'\b(?:max_?amount|amount_?cap|amount_?limit|maximum|max_?value|spending_?limit)\b',
    re.IGNORECASE,
)

# AGENT-104: Hardcoded settlement processor address
SETTLEMENT_ADDRESS_PATTERN = re.compile(
    r'(?:settlement|processor|paymaster|escrow)[\w_]*\s*[=:]\s*["\']?(0x[0-9a-fA-F]{40})["\']?',
    re.IGNORECASE,
)

# AGENT-105: Payment header without replay protection
PAYMENT_HEADER_PATTERN = re.compile(
    r'X-Payment(?:-Mandate|-Authorization|-Signature)?',
    re.IGNORECASE,
)
REPLAY_PROTECTION_KEYWORDS = re.compile(
    r'\b(?:nonce|deadline|expir|chain_?id|chainId|ttl|timestamp)\b',
    re.IGNORECASE,
)

# AGENT-106: Withdrawal without delay
WITHDRAWAL_PATTERN = re.compile(
    r'\b(?:withdraw|withdrawal|transfer_?out|drain|sweep)\s*[\(\{]',
    re.IGNORECASE,
)
DELAY_KEYWORDS = re.compile(
    r'\b(?:delay|timelock|time_?lock|cooldown|pending|queue|schedule)\b',
    re.IGNORECASE,
)

# AGENT-107: Agent JWT in code
AGENT_JWT_IN_CODE = re.compile(
    r'["\']Authorization["\']\s*:\s*[`"\']Bearer\s+(?!.*process\.env)(?!.*config\.)(?!.*os\.environ)',
)

# AGENT-109: Settlement without event emission
SETTLEMENT_STATE_CHANGE = re.compile(
    r'\b(?:settle|finalize|complete_?payment|process_?settlement|execute_?payment)\s*[\(\{]',
    re.IGNORECASE,
)
EVENT_EMISSION_KEYWORDS = re.compile(
    r'\b(?:emit|event|log|EventEmitter|\.emit\(|console\.log|logger\.|logging\.)\b',
    re.IGNORECASE,
)


def scan_agent_payment(file_path: str, content: str) -> List[DeFiFinding]:
    """Scan file content for agent payment security issues."""
    findings: List[DeFiFinding] = []
    lines = content.splitlines()
    path_lower = file_path.lower()

    # Skip test files and examples
    if any(kw in path_lower for kw in ['test', 'spec', 'example', 'fixture', 'mock']):
        return findings

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue

        # Get surrounding context (function-level, ~30 lines)
        context_start = max(0, line_num - 15)
        context_end = min(len(lines), line_num + 15)
        context = '\n'.join(lines[context_start:context_end])

        # AGENT-103: Mandate without amount cap
        for pattern in MANDATE_PATTERNS:
            if pattern.search(line) or pattern.search(context):
                if 'amount' in context.lower() and not MANDATE_CAP_KEYWORDS.search(context):
                    findings.append(make_finding(
                        rule_id='AGENT-103',
                        pattern_type='mandate_without_amount_cap',
                        file_path=file_path,
                        line=line_num,
                        confidence=0.75,
                        message='Payment mandate constructed without amount cap/limit',
                    ))
                    break

        # AGENT-104: Hardcoded settlement address
        match = SETTLEMENT_ADDRESS_PATTERN.search(line)
        if match:
            findings.append(make_finding(
                rule_id='AGENT-104',
                pattern_type='hardcoded_settlement_processor',
                file_path=file_path,
                line=line_num,
                confidence=0.80,
                message=f'Hardcoded settlement processor address: {match.group(1)[:10]}...',
            ))

        # AGENT-105: Payment header without replay protection
        if PAYMENT_HEADER_PATTERN.search(line):
            if not REPLAY_PROTECTION_KEYWORDS.search(context):
                findings.append(make_finding(
                    rule_id='AGENT-105',
                    pattern_type='payment_header_no_replay_protect',
                    file_path=file_path,
                    line=line_num,
                    confidence=0.70,
                    message='Payment header without nonce/deadline/chainId replay protection',
                ))

        # AGENT-106: Withdrawal without delay
        if WITHDRAWAL_PATTERN.search(line):
            if not DELAY_KEYWORDS.search(context):
                findings.append(make_finding(
                    rule_id='AGENT-106',
                    pattern_type='withdrawal_delay_bypass',
                    file_path=file_path,
                    line=line_num,
                    confidence=0.65,
                    message='Withdrawal operation without time-delay mechanism',
                ))

        # AGENT-107: Agent JWT in code
        if AGENT_JWT_IN_CODE.search(line):
            findings.append(make_finding(
                rule_id='AGENT-107',
                pattern_type='agent_jwt_in_code',
                file_path=file_path,
                line=line_num,
                confidence=0.85,
                message='Agent JWT/Bearer token hardcoded in source code',
            ))

        # AGENT-109: Settlement without event emission
        if SETTLEMENT_STATE_CHANGE.search(line):
            if not EVENT_EMISSION_KEYWORDS.search(context):
                findings.append(make_finding(
                    rule_id='AGENT-109',
                    pattern_type='settlement_no_event_emission',
                    file_path=file_path,
                    line=line_num,
                    confidence=0.65,
                    message='Settlement state change without event/log emission',
                ))

    return findings
