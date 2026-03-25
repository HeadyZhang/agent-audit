"""DeFi-specialized credential detection scanner.

Detects hardcoded Ethereum private keys, BIP-39 mnemonic phrases,
and keystore passwords with confidence-based false positive control.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List

from agent_audit.profiles.defi.constants.defi_protocols import (
    BIP39_COMMON_WORDS,
    KNOWN_TEST_PRIVATE_KEYS,
)
from agent_audit.profiles.defi.rules import DeFiFinding, make_finding


# Placeholder patterns that indicate non-real keys
_PLACEHOLDER_PATTERNS = [
    re.compile(r'^(0x)?0{64}$'),                    # all zeros
    re.compile(r'^(0x)?[0]{32}[0-9a-fA-F]{32}$'),   # half zeros
    re.compile(r'^(0x)?dead(dead){15}$', re.I),      # deadbeef...
    re.compile(r'^(0x)?(1234){16}$'),                # repeating 1234
    re.compile(r'^(0x)?(abcd){16}$', re.I),          # repeating abcd
    re.compile(r'^(0x)?[0-9a-fA-F]{2}(\1){31}$'),   # single byte repeated
]

# Core detection patterns
DEFI_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        'name': 'ethereum_private_key_0x',
        'pattern': re.compile(
            r'(?:private[_-]?key|signing[_-]?key|secret[_-]?key|wallet[_-]?key|'
            r'deployer[_-]?key|eth[_-]?key|account[_-]?key|owner[_-]?key|'
            r'signer[_-]?key)\s*[=:]\s*["\']?(0x[0-9a-fA-F]{64})["\']?',
            re.IGNORECASE,
        ),
        'rule_id': 'AGENT-090',
        'pattern_type': 'defi_hardcoded_private_key',
        'base_confidence': 0.95,
    },
    {
        'name': 'ethereum_private_key_raw',
        'pattern': re.compile(
            r'(?:private[_-]?key|signing[_-]?key|wallet[_-]?key)\s*[=:]\s*'
            r'["\']([0-9a-fA-F]{64})["\']',
            re.IGNORECASE,
        ),
        'rule_id': 'AGENT-090',
        'pattern_type': 'defi_hardcoded_private_key',
        'base_confidence': 0.85,
    },
    {
        'name': 'ethereum_key_in_api_call',
        'pattern': re.compile(
            r'(?:from_key|sign_transaction|SigningKey|Wallet|from_mnemonic)\s*\(\s*'
            r'["\'](?:0x)?[0-9a-fA-F]{64}["\']',
        ),
        'rule_id': 'AGENT-090',
        'pattern_type': 'defi_key_in_api_call',
        'base_confidence': 0.98,
    },
    {
        'name': 'bip39_mnemonic',
        'pattern': re.compile(
            r'(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase|wallet[_-]?words|'
            r'backup[_-]?phrase)\s*[=:]\s*["\']([a-z]+(?:\s+[a-z]+){11,23})["\']',
            re.IGNORECASE,
        ),
        'rule_id': 'AGENT-090',
        'pattern_type': 'defi_hardcoded_mnemonic',
        'base_confidence': 0.93,
    },
    {
        'name': 'keystore_hardcoded_password',
        'pattern': re.compile(
            r'(?:decrypt|unlock[_-]?account)\s*\([^,]+,\s*["\'][^"\']{4,}["\']',
        ),
        'rule_id': 'AGENT-090',
        'pattern_type': 'defi_keystore_hardcoded_password',
        'base_confidence': 0.80,
    },
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _is_placeholder(value: str) -> bool:
    """Check if value matches a known placeholder pattern."""
    normalized = value.lower().lstrip('0x')
    if not normalized:
        return True
    # All same character
    if len(set(normalized)) <= 2:
        return True
    for pat in _PLACEHOLDER_PATTERNS:
        if pat.match(value):
            return True
    return False


def _extract_hex_value(match: re.Match) -> str:
    """Extract the hex key value from a regex match."""
    groups = match.groups()
    for g in groups:
        if g and re.match(r'^(?:0x)?[0-9a-fA-F]{64}$', g):
            return g
    return match.group(0)


class DeFiSecretScanner:
    """Scans source code for DeFi-specific credential exposure."""

    def scan_content(
        self,
        file_path: str,
        content: str,
    ) -> List[DeFiFinding]:
        """Scan source content for hardcoded DeFi credentials."""
        findings: List[DeFiFinding] = []
        lines = content.split('\n')

        for pattern_def in DEFI_SECRET_PATTERNS:
            regex: re.Pattern[str] = pattern_def['pattern']
            for i, line_text in enumerate(lines, start=1):
                for match in regex.finditer(line_text):
                    confidence = self._compute_confidence(
                        pattern_def, match, file_path, line_text,
                    )
                    if confidence < 0.30:
                        continue
                    finding = make_finding(
                        rule_id=str(pattern_def['rule_id']),
                        pattern_type=str(pattern_def['pattern_type']),
                        file_path=file_path,
                        line=i,
                        confidence=confidence,
                        message=self._build_message(pattern_def, match),
                        column=match.start(),
                    )
                    findings.append(finding)

        return findings

    def _compute_confidence(
        self,
        pattern_def: dict,
        match: re.Match,
        file_path: str,
        line_text: str,
    ) -> float:
        """Compute confidence with false-positive reduction."""
        confidence = pattern_def['base_confidence']

        # Check for test/mock context in variable name
        lower_line = line_text.lower()
        test_indicators = ['test', 'mock', 'example', 'dummy', 'fake', 'sample']
        if any(ind in lower_line for ind in test_indicators):
            confidence *= 0.15

        # Check for test file path
        path_lower = file_path.lower()
        basename = path_lower.rsplit('/', 1)[-1] if '/' in path_lower else path_lower
        is_test_file = (
            basename.startswith('test_')
            or basename.endswith('_test.py')
            or basename.startswith('spec_')
            or basename.endswith('_spec.py')
            or '/mock' in path_lower
        )
        if is_test_file:
            confidence *= 0.20

        # Pattern-specific checks
        if pattern_def['pattern_type'] in (
            'defi_hardcoded_private_key', 'defi_key_in_api_call',
        ):
            hex_value = _extract_hex_value(match)
            normalized = hex_value.lower().lstrip('0x')

            # Known test keys
            if normalized in KNOWN_TEST_PRIVATE_KEYS:
                confidence *= 0.15

            # Placeholder detection
            if _is_placeholder(hex_value):
                confidence *= 0.10

            # Shannon entropy check
            entropy = _shannon_entropy(normalized)
            if entropy < 3.0:
                confidence *= 0.30

        if pattern_def['pattern_type'] == 'defi_hardcoded_mnemonic':
            # Validate words against BIP-39 list
            groups = match.groups()
            mnemonic_text = groups[0] if groups else ''
            if mnemonic_text:
                words = mnemonic_text.split()
                bip39_count = sum(1 for w in words if w in BIP39_COMMON_WORDS)
                ratio = bip39_count / len(words) if words else 0
                if ratio < 0.5:
                    confidence *= 0.30

        return confidence

    def _build_message(self, pattern_def: dict, match: re.Match) -> str:
        """Build a human-readable finding message."""
        name = pattern_def['name']
        messages = {
            'ethereum_private_key_0x': (
                'Hardcoded Ethereum private key (0x-prefixed) detected.'
            ),
            'ethereum_private_key_raw': (
                'Hardcoded Ethereum private key (raw hex) detected.'
            ),
            'ethereum_key_in_api_call': (
                'Hardcoded private key passed directly to crypto API call.'
            ),
            'bip39_mnemonic': (
                'Hardcoded BIP-39 mnemonic seed phrase detected.'
            ),
            'keystore_hardcoded_password': (
                'Hardcoded password in keystore decrypt call.'
            ),
        }
        return messages.get(name, f'DeFi credential exposure: {name}')
