"""DeFi Agent Security Profile.

Provides 20 DeFi-specific detection rules (AGENT-090 through AGENT-109)
for AI agents that interact with blockchain/DeFi protocols.

Usage:
    agent-audit scan . --profile defi
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

from agent_audit.profiles.defi.rules import DeFiFinding, DEFI_RULES


PROFILE_NAME = "defi"
RULE_COUNT = len(DEFI_RULES)

# File extensions scanned by the DeFi profile
_SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.mts'}


def scan_target(target_path: str, exclude_patterns: List[str] | None = None) -> List[DeFiFinding]:
    """Run all DeFi profile scanners on a target path.

    Args:
        target_path: Directory or file to scan.
        exclude_patterns: Glob patterns to exclude.

    Returns:
        List of DeFiFinding objects from all DeFi scanners.
    """
    from agent_audit.profiles.defi.scanners.defi_secret_scanner import DeFiSecretScanner
    from agent_audit.profiles.defi.scanners.web3_ast_visitor import Web3ASTVisitor
    from agent_audit.profiles.defi.scanners.js_ts_scanner import JsTsScanner
    from agent_audit.profiles.defi.scanners.agent_payment_scanner import scan_agent_payment
    from agent_audit.profiles.defi.analysis.rpc_analyzer import RPCAnalyzer
    from agent_audit.profiles.defi.scanners.solidity_scanner import SolidityScanner

    secret_scanner = DeFiSecretScanner()
    js_ts_scanner = JsTsScanner()
    rpc_analyzer = RPCAnalyzer()

    all_findings: List[DeFiFinding] = []
    files = _collect_files(target_path, exclude_patterns)

    for file_path in files:
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except (OSError, IOError):
            continue

        file_str = str(file_path)

        # Python files: AST analysis + secrets + RPC + payment
        if file_path.suffix == '.py':
            visitor = Web3ASTVisitor(file_str)
            all_findings.extend(visitor.scan(content))
            all_findings.extend(secret_scanner.scan_content(file_str, content))
            all_findings.extend(rpc_analyzer.analyze_file(file_str, content))
            all_findings.extend(scan_agent_payment(file_str, content))

        # JS/TS files: regex scanner + RPC + payment
        elif file_path.suffix in {'.js', '.ts', '.jsx', '.tsx', '.mjs', '.mts'}:
            all_findings.extend(js_ts_scanner.scan_content(file_str, content))
            all_findings.extend(rpc_analyzer.analyze_file(file_str, content))
            all_findings.extend(scan_agent_payment(file_str, content))

    # Solidity scanner (runs on directory level via Slither)
    target = Path(target_path)
    if target.is_dir():
        sol_scanner = SolidityScanner()
        all_findings.extend(sol_scanner.scan(str(target)))

    return all_findings


def _collect_files(
    target: str,
    exclude_patterns: List[str] | None = None,
) -> List[Path]:
    """Collect scannable files from a target path."""
    target_path = Path(target)
    if target_path.is_file():
        if target_path.suffix in _SCAN_EXTENSIONS:
            return [target_path]
        return []

    if not target_path.is_dir():
        return []

    skip_dirs = {'node_modules', '.git', '__pycache__', '.venv', 'venv'}
    files: List[Path] = []
    for root, dirs, filenames in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(root) / fname
            if fpath.suffix in _SCAN_EXTENSIONS:
                files.append(fpath)

    return sorted(files)
