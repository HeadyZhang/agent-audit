"""
Solidity Security Scanner for agent-audit.

Provides smart contract security analysis with:
- Slither integration (via subprocess, optional)
- Regex-based fallback for common vulnerability patterns
- New rules: AGENT-083 (delegatecall), AGENT-084 (tx.origin)

v0.20.0: Initial implementation.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from agent_audit.scanners.base import BaseScanner, ScanResult
from agent_audit.models.finding import Finding, Remediation, confidence_to_tier
from agent_audit.models.risk import Severity, Category, Location

logger = logging.getLogger(__name__)


@dataclass
class SolidityScanResult(ScanResult):
    """Result of Solidity scanning."""
    findings: List[Finding] = field(default_factory=list)
    slither_available: bool = False


class SolidityScanner(BaseScanner):
    """
    Solidity smart contract security scanner.

    Uses Slither (via subprocess) for deep analysis when available,
    falls back to regex patterns for basic detection.
    """

    name = "Solidity Scanner"

    # Regex patterns for Solidity vulnerabilities
    # AGENT-083: Unsafe delegatecall
    DELEGATECALL_PATTERN = re.compile(
        r'\.delegatecall\s*\(',
        re.MULTILINE,
    )
    DELEGATECALL_USER_ADDR = re.compile(
        r'(\w+)\.delegatecall\s*\(',
    )

    # AGENT-084: tx.origin for authentication
    TX_ORIGIN_AUTH = re.compile(
        r'require\s*\(\s*tx\.origin\s*==',
        re.MULTILINE,
    )
    TX_ORIGIN_ASSIGN = re.compile(
        r'(?:owner|admin|authorized)\s*=\s*tx\.origin',
        re.IGNORECASE,
    )

    # Additional pattern: selfdestruct (informational, supplements defi-shield)
    SELFDESTRUCT_PATTERN = re.compile(
        r'\bselfdestruct\s*\(|\bsuicide\s*\(',
    )

    # Directories to skip during file discovery
    SKIP_DIRS = frozenset({
        'node_modules', '.git', 'lib', 'forge-std', 'openzeppelin',
        '.deps', 'cache', 'artifacts', 'out',
    })

    def __init__(self, exclude_patterns: Optional[List[str]] = None) -> None:
        """
        Initialize the Solidity scanner.

        Args:
            exclude_patterns: Optional list of glob patterns to exclude.
        """
        self.exclude_patterns = set(exclude_patterns or [])

    def scan(self, path: Path) -> Sequence[SolidityScanResult]:
        """
        Scan Solidity files for security issues.

        Args:
            path: File or directory to scan.

        Returns:
            Sequence of SolidityScanResult objects.
        """
        results: List[SolidityScanResult] = []
        sol_files = self._find_sol_files(path)

        if not sol_files:
            return results

        for sol_file in sol_files:
            result = self._analyze_file(sol_file)
            if result is not None and result.findings:
                results.append(result)

        return results

    def scan_and_convert(self, path: Path) -> List[Finding]:
        """
        Scan and return Finding objects directly.

        Args:
            path: File or directory to scan.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []
        for result in self.scan(path):
            findings.extend(result.findings)
        return findings

    def _find_sol_files(self, path: Path) -> List[Path]:
        """
        Find .sol files, excluding vendor/library directories.

        Args:
            path: File or directory to search.

        Returns:
            List of discovered Solidity file paths.
        """
        if path.is_file() and path.suffix == '.sol':
            return [path]

        sol_files: List[Path] = []
        if path.is_dir():
            for f in path.rglob('*.sol'):
                # Skip vendor/library directories
                if any(skip in f.parts for skip in self.SKIP_DIRS):
                    continue
                # Skip files matching exclude patterns
                if self._is_excluded(f):
                    continue
                sol_files.append(f)

        return sol_files

    def _is_excluded(self, file_path: Path) -> bool:
        """Check if a file matches any exclude pattern."""
        file_str = str(file_path)
        for pattern in self.exclude_patterns:
            if pattern in file_str:
                return True
        return False

    def _analyze_file(self, sol_file: Path) -> Optional[SolidityScanResult]:
        """
        Analyze a single Solidity file.

        Args:
            sol_file: Path to the Solidity file.

        Returns:
            SolidityScanResult or None if the file cannot be read.
        """
        try:
            content = sol_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning("Error reading %s: %s", sol_file, e)
            return None

        findings: List[Finding] = []

        # Try Slither first
        slither_available = False
        slither_result = self._run_slither(sol_file)
        if slither_result is not None:
            slither_available = True
            findings.extend(self._process_slither_output(slither_result, sol_file))

        # Always run regex patterns (catches things Slither might miss,
        # and provides coverage when Slither is not installed)
        regex_findings = self._regex_analysis(content, sol_file)

        # Deduplicate: if Slither already found a rule on the same line, skip regex dupe
        slither_keys = {
            (f.rule_id, f.location.start_line) for f in findings
        }
        for rf in regex_findings:
            key = (rf.rule_id, rf.location.start_line)
            if key not in slither_keys:
                findings.append(rf)

        return SolidityScanResult(
            source_file=str(sol_file),
            findings=findings,
            slither_available=slither_available,
        )

    def _run_slither(self, sol_file: Path) -> Optional[Dict[str, Any]]:
        """
        Run Slither and return JSON output.

        Args:
            sol_file: Path to the Solidity file.

        Returns:
            Parsed JSON dict from Slither, or None if unavailable.
        """
        try:
            result = subprocess.run(
                ['slither', str(sol_file), '--json', '-'],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.stdout:
                return json.loads(result.stdout)
        except FileNotFoundError:
            logger.debug("Slither not installed, using regex-only analysis")
        except subprocess.TimeoutExpired:
            logger.warning("Slither timed out for %s", sol_file)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Slither output for %s", sol_file)
        except Exception as e:
            logger.debug("Slither error for %s: %s", sol_file, e)
        return None

    def _process_slither_output(
        self,
        slither_data: Dict[str, Any],
        sol_file: Path,
    ) -> List[Finding]:
        """
        Process Slither JSON output into findings.

        Only maps detectors for AGENT-083 (delegatecall) and AGENT-084 (tx.origin).
        Other detectors are left to defi-shield.

        Args:
            slither_data: Parsed Slither JSON output.
            sol_file: Path to the source file.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []
        detectors = slither_data.get('results', {}).get('detectors', [])

        for detector in detectors:
            check = detector.get('check', '')
            impact = detector.get('impact', 'Medium')
            confidence_str = detector.get('confidence', 'Medium')

            # Map Slither detectors to our rules
            # Focus on delegatecall and tx.origin (not covered by defi-shield)
            rule_id: Optional[str] = None
            title = ''
            category = Category.UNEXPECTED_CODE_EXECUTION
            cwe_id = ''

            if 'delegatecall' in check:
                rule_id = 'AGENT-083'
                title = 'Unsafe Delegatecall'
                category = Category.UNEXPECTED_CODE_EXECUTION
                cwe_id = 'CWE-829'
            elif 'tx-origin' in check:
                rule_id = 'AGENT-084'
                title = 'tx.origin Used for Authentication'
                category = Category.IDENTITY_PRIVILEGE_ABUSE
                cwe_id = 'CWE-287'
            else:
                continue  # Skip detectors covered by defi-shield

            # Map Slither confidence to our scale
            conf_map: Dict[str, float] = {
                'High': 0.90,
                'Medium': 0.75,
                'Low': 0.60,
            }
            confidence = conf_map.get(confidence_str, 0.70)

            sev_map: Dict[str, Severity] = {
                'High': Severity.HIGH,
                'Medium': Severity.MEDIUM,
                'Low': Severity.LOW,
                'Informational': Severity.LOW,
            }
            severity = sev_map.get(impact, Severity.MEDIUM)

            # Get source location
            elements = detector.get('elements', [])
            line = 1
            snippet = detector.get('description', '')[:200]
            if elements:
                first = elements[0]
                src = first.get('source_mapping', {})
                lines = src.get('lines', [1])
                line = lines[0] if lines else 1

            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                description=detector.get('description', f'Slither: {check}'),
                severity=severity,
                category=category,
                location=Location(
                    file_path=str(sol_file),
                    start_line=line,
                    end_line=line,
                    snippet=snippet,
                ),
                cwe_id=cwe_id,
                confidence=confidence,
                tier=confidence_to_tier(confidence),
                remediation=Remediation(
                    description=f"Review Slither finding: {check}",
                ),
            ))

        return findings

    def _regex_analysis(
        self,
        content: str,
        sol_file: Path,
    ) -> List[Finding]:
        """
        Regex-based Solidity analysis (fallback when Slither unavailable).

        Args:
            content: File content as string.
            sol_file: Path to the Solidity file.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            # AGENT-083: delegatecall
            if self.DELEGATECALL_PATTERN.search(line):
                match = self.DELEGATECALL_USER_ADDR.search(line)
                target_var = match.group(1) if match else 'unknown'
                # Higher confidence if target is a parameter name
                # (lowercase, not 'this' or 'self')
                safe_targets = frozenset({'this', 'self', 'address'})
                conf = 0.80 if target_var not in safe_targets else 0.60
                findings.append(Finding(
                    rule_id='AGENT-083',
                    title='Unsafe Delegatecall',
                    description=(
                        f'delegatecall to potentially user-controlled '
                        f'address ({target_var})'
                    ),
                    severity=Severity.HIGH,
                    category=Category.UNEXPECTED_CODE_EXECUTION,
                    location=Location(
                        file_path=str(sol_file),
                        start_line=line_num,
                        end_line=line_num,
                        snippet=stripped[:200],
                    ),
                    cwe_id='CWE-829',
                    confidence=conf,
                    tier=confidence_to_tier(conf),
                    remediation=Remediation(
                        description=(
                            'Validate delegatecall target address '
                            'against an allowlist'
                        ),
                    ),
                ))

            # AGENT-084: tx.origin authentication
            if (self.TX_ORIGIN_AUTH.search(line)
                    or self.TX_ORIGIN_ASSIGN.search(line)):
                findings.append(Finding(
                    rule_id='AGENT-084',
                    title='tx.origin Used for Authentication',
                    description=(
                        'Using tx.origin for authentication is vulnerable '
                        'to phishing attacks'
                    ),
                    severity=Severity.HIGH,
                    category=Category.IDENTITY_PRIVILEGE_ABUSE,
                    location=Location(
                        file_path=str(sol_file),
                        start_line=line_num,
                        end_line=line_num,
                        snippet=stripped[:200],
                    ),
                    cwe_id='CWE-287',
                    confidence=0.90,
                    tier=confidence_to_tier(0.90),
                    remediation=Remediation(
                        description=(
                            'Use msg.sender instead of tx.origin '
                            'for authentication'
                        ),
                    ),
                ))

        return findings
