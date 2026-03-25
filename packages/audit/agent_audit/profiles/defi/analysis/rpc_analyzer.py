"""RPC endpoint security analyzer.

Detects unencrypted (HTTP/WS) RPC connections and usage of public
RPC endpoints without API key authentication.
"""
from __future__ import annotations

import os
import re
from typing import List
from urllib.parse import urlparse

from agent_audit.profiles.defi.constants.rpc_endpoints import (
    MEV_PROTECTED_RPC_DOMAINS,
    PUBLIC_RPC_DOMAINS,
)
from agent_audit.profiles.defi.rules import DeFiFinding, make_finding

# Regex to find RPC provider URLs in source code
_RPC_URL_PATTERN = re.compile(
    r'(?:HTTPProvider|WebsocketProvider|AsyncHTTPProvider|'
    r'JsonRpcProvider|WebSocketProvider)\s*\(\s*'
    r'["\']'
    r'((?:https?|wss?)://[^"\']+)'
    r'["\']',
)

# Broader pattern for any URL assigned to web3/provider-related variables
_RPC_VAR_PATTERN = re.compile(
    r'(?:rpc[_-]?url|rpc[_-]?endpoint|provider[_-]?url|'
    r'web3[_-]?url|node[_-]?url|eth[_-]?url)\s*[=:]\s*'
    r'["\']'
    r'((?:https?|wss?)://[^"\']+)'
    r'["\']',
    re.IGNORECASE,
)

_LOCAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '[::]', '[::1]'}


class RPCAnalyzer:
    """Analyzes source files for RPC endpoint security issues."""

    def analyze_file(
        self,
        file_path: str,
        content: str,
    ) -> List[DeFiFinding]:
        """Scan file content for RPC security issues.

        Returns findings for:
        - AGENT-094: HTTP/WS (non-TLS) RPC endpoints
        - AGENT-094 (public_rpc_no_auth): Public RPC without API key
        """
        findings: List[DeFiFinding] = []
        lines = content.split('\n')

        for i, line_text in enumerate(lines, start=1):
            for pattern in (_RPC_URL_PATTERN, _RPC_VAR_PATTERN):
                for match in pattern.finditer(line_text):
                    url = match.group(1)
                    findings.extend(
                        self._analyze_url(file_path, i, match.start(), url)
                    )

        return findings

    def _analyze_url(
        self,
        file_path: str,
        line: int,
        column: int,
        url: str,
    ) -> List[DeFiFinding]:
        """Analyze a single RPC URL for security issues."""
        results: List[DeFiFinding] = []

        try:
            parsed = urlparse(url)
        except Exception:
            return results

        hostname = (parsed.hostname or '').lower()
        scheme = (parsed.scheme or '').lower()

        is_local = hostname in _LOCAL_HOSTS

        # Check 1: Non-TLS (HTTP or WS without S)
        if scheme in ('http', 'ws'):
            confidence = 0.85
            if is_local:
                confidence *= 0.30
            if self._is_test_file(file_path):
                confidence *= 0.25
            if confidence >= 0.30:
                results.append(make_finding(
                    rule_id='AGENT-094',
                    pattern_type='defi_rpc_no_tls',
                    file_path=file_path,
                    line=line,
                    column=column,
                    confidence=confidence,
                    message=f'RPC endpoint uses unencrypted {scheme.upper()}: {url}',
                ))

        # Check 2: Public RPC without authentication
        if any(domain in hostname for domain in PUBLIC_RPC_DOMAINS):
            confidence = 0.70
            if self._is_test_file(file_path):
                confidence *= 0.25
            if confidence >= 0.30:
                results.append(make_finding(
                    rule_id='AGENT-094',
                    pattern_type='defi_public_rpc_no_auth',
                    file_path=file_path,
                    line=line,
                    column=column,
                    confidence=confidence,
                    message=f'Public RPC endpoint without API key authentication: {url}',
                ))

        return results

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is an actual test file."""
        basename = os.path.basename(file_path).lower()
        return (
            basename.startswith('test_')
            or basename.endswith('_test.py')
            or basename.startswith('spec_')
            or basename.endswith('_spec.py')
            or basename.endswith('.test.js')
            or basename.endswith('.test.ts')
            or basename.endswith('.spec.js')
            or basename.endswith('.spec.ts')
        )

    def is_mev_protected_rpc(self, url: str) -> bool:
        """Check if URL uses a MEV-protected RPC endpoint."""
        try:
            hostname = urlparse(url).hostname or ''
        except Exception:
            return False
        return any(
            domain in hostname.lower()
            for domain in MEV_PROTECTED_RPC_DOMAINS
        )
