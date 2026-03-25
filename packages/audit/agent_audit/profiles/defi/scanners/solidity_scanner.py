"""Solidity scanner - Slither CLI bridge (DeFi profile).

Slither is an optional dependency. When not installed, the scanner
degrades gracefully: detects .sol files and outputs an INFO-level
suggestion to install slither-analyzer.

Runs slither as a subprocess and parses its JSON output.
Does not directly import slither Python API.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List

from agent_audit.profiles.defi.rules import DeFiFinding, Severity


class SolidityScanner:
    """Analyze Solidity contracts via Slither CLI."""

    # Slither detector -> defi-shield rule mapping
    # (rule_id, pattern_type, severity, confidence)
    SLITHER_TO_DEFI_RULES = {
        # Reentrancy
        'reentrancy-eth': ('AGENT-099', 'solidity_reentrancy_eth', Severity.CRITICAL, 0.90),
        'reentrancy-no-eth': ('AGENT-099', 'solidity_reentrancy_no_eth', Severity.HIGH, 0.80),
        'reentrancy-benign': ('AGENT-099', 'solidity_reentrancy_benign', Severity.LOW, 0.50),
        'reentrancy-events': ('AGENT-099', 'solidity_reentrancy_events', Severity.LOW, 0.45),
        # Access Control
        'unprotected-upgrade': ('AGENT-101', 'solidity_unprotected_upgrade', Severity.CRITICAL, 0.95),
        'suicidal': ('AGENT-101', 'solidity_suicidal', Severity.CRITICAL, 0.95),
        'protected-vars': ('AGENT-101', 'solidity_protected_vars', Severity.HIGH, 0.80),
        'arbitrary-send-eth': ('AGENT-101', 'solidity_arbitrary_send', Severity.HIGH, 0.85),
        'arbitrary-send-erc20': ('AGENT-101', 'solidity_arbitrary_send_erc20', Severity.HIGH, 0.85),
        'tx-origin': ('AGENT-101', 'solidity_tx_origin', Severity.MEDIUM, 0.75),
        # Integer Overflow (pre-0.8.0)
        'unchecked-lowlevel': ('AGENT-100', 'solidity_unchecked_lowlevel', Severity.MEDIUM, 0.70),
        # Flash Loan related
        'oracle-price': ('AGENT-102', 'solidity_oracle_manipulation', Severity.HIGH, 0.80),
        'incorrect-equality': ('AGENT-102', 'solidity_incorrect_equality', Severity.MEDIUM, 0.65),
        # General high-impact
        'unchecked-transfer': ('AGENT-101', 'solidity_unchecked_transfer', Severity.HIGH, 0.80),
        'locked-ether': ('AGENT-101', 'solidity_locked_ether', Severity.MEDIUM, 0.65),
        'controlled-delegatecall': ('AGENT-101', 'solidity_controlled_delegatecall', Severity.CRITICAL, 0.95),
    }

    def is_available(self) -> bool:
        """Check if slither CLI is installed."""
        return shutil.which('slither') is not None

    def find_sol_files(self, target_dir: str) -> List[str]:
        """Find .sol files in target directory, skipping node_modules."""
        sol_files: List[str] = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d != 'node_modules']
            for f in files:
                if f.endswith('.sol'):
                    sol_files.append(os.path.join(root, f))
        return sol_files

    def scan(self, target_dir: str) -> List[DeFiFinding]:
        """Run Slither scan and return DeFi findings."""
        if not self.is_available():
            sol_files = self.find_sol_files(target_dir)
            if sol_files:
                return [DeFiFinding(
                    rule_id='INFO',
                    pattern_type='slither_not_installed',
                    file_path=target_dir,
                    line=0,
                    confidence=1.0,
                    severity=Severity.INFO,
                    message=(
                        f'Found {len(sol_files)} Solidity files but Slither is not installed. '
                        f'Install with: pip install slither-analyzer'
                    ),
                )]
            return []

        return self._run_slither(target_dir)

    def _detect_framework(self, target_dir: str) -> str:
        """Detect Solidity compilation framework."""
        hardhat_cfg = os.path.join(target_dir, 'hardhat.config.js')
        hardhat_ts = os.path.join(target_dir, 'hardhat.config.ts')
        foundry_cfg = os.path.join(target_dir, 'foundry.toml')
        has_hardhat = os.path.exists(hardhat_cfg) or os.path.exists(hardhat_ts)
        has_foundry = os.path.exists(foundry_cfg)
        if has_hardhat and has_foundry:
            if shutil.which('forge'):
                return 'foundry'
            return 'hardhat'
        if has_foundry and shutil.which('forge'):
            return 'foundry'
        if has_hardhat:
            return 'hardhat'
        return ''

    def _run_slither(self, target_dir: str) -> List[DeFiFinding]:
        """Execute slither CLI and parse JSON output."""
        try:
            cmd = ['slither', target_dir, '--json', '-']
            framework = self._detect_framework(target_dir)
            if framework:
                cmd.extend(['--compile-force-framework', framework])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if not result.stdout.strip():
                return []
            data = json.loads(result.stdout)
            return self._parse_slither_results(data)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            return [DeFiFinding(
                rule_id='INFO',
                pattern_type='slither_error',
                file_path=target_dir,
                line=0,
                confidence=1.0,
                severity=Severity.INFO,
                message=f'Slither execution error: {str(e)[:100]}',
            )]

    def _parse_slither_results(self, data: dict) -> List[DeFiFinding]:
        """Convert Slither JSON results to DeFiFinding list."""
        findings: List[DeFiFinding] = []
        for detector_result in data.get('results', {}).get('detectors', []):
            check = detector_result.get('check', '')
            if check not in self.SLITHER_TO_DEFI_RULES:
                continue

            rule_id, pattern_type, severity, confidence = self.SLITHER_TO_DEFI_RULES[check]

            # Extract location info
            elements = detector_result.get('elements', [])
            file_path = ''
            line = 0
            if elements:
                src = elements[0].get('source_mapping', {})
                file_path = src.get('filename_relative', src.get('filename_absolute', ''))
                line = src.get('lines', [0])[0] if src.get('lines') else 0

            findings.append(DeFiFinding(
                rule_id=rule_id,
                pattern_type=pattern_type,
                file_path=file_path,
                line=line,
                confidence=confidence,
                severity=severity,
                message=detector_result.get('description', f'Slither: {check}')[:200],
                cwe=detector_result.get('id', ''),
            ))

        return findings
