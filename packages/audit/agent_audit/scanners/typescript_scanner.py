"""
TypeScript/JavaScript Security Scanner for AI Agent Code.

Detects dangerous patterns in TypeScript and JavaScript agent code:
- Code execution (eval, new Function, vm.runIn*)
- Shell execution (child_process.exec, execSync, spawn, execa)
- SQL injection via template strings
- Prompt injection via template strings
- SSRF via fetch/axios with dynamic URLs
- Unsafe deserialization (serialize-javascript, node-serialize)

Uses TreeSitterParser for AST analysis where available,
falls back to regex-based detection.

Maps findings to existing OWASP Agentic rule IDs:
- AGENT-034: Code/shell execution without input validation
- AGENT-041: SQL injection
- AGENT-010: Prompt injection
- AGENT-026: SSRF
- AGENT-049: Unsafe deserialization
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Sequence, Tuple

from agent_audit.models.finding import (
    Finding,
    Remediation,
    confidence_to_tier,
)
from agent_audit.models.risk import Severity, Category, Location
from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


# ============================================================================
# Dangerous call patterns for TypeScript/JavaScript
# Format: call_name -> (rule_id, pattern_type, base_confidence)
# ============================================================================

TS_DANGEROUS_CALLS: Dict[str, Tuple[str, str, float]] = {
    # Code execution
    "eval": ("AGENT-034", "ts_eval_exec", 0.95),
    "Function": ("AGENT-034", "ts_eval_exec", 0.90),
    "vm.runInContext": ("AGENT-034", "ts_eval_exec", 0.90),
    "vm.runInNewContext": ("AGENT-034", "ts_eval_exec", 0.90),
    "vm.runInThisContext": ("AGENT-034", "ts_eval_exec", 0.90),
    # Shell execution
    "child_process.exec": ("AGENT-034", "ts_child_process_exec", 0.90),
    "child_process.execSync": ("AGENT-034", "ts_child_process_exec", 0.90),
    "child_process.spawn": ("AGENT-034", "ts_child_process_exec", 0.85),
    "child_process.spawnSync": ("AGENT-034", "ts_child_process_exec", 0.85),
    "execa": ("AGENT-034", "ts_child_process_exec", 0.85),
    "execaSync": ("AGENT-034", "ts_child_process_exec", 0.85),
    # SQL (only when template string used - checked separately)
    "query": ("AGENT-041", "ts_sql_template_injection", 0.75),
    "execute": ("AGENT-041", "ts_sql_template_injection", 0.75),
    "knex.raw": ("AGENT-041", "ts_sql_template_injection", 0.85),
    "prisma.$queryRaw": ("AGENT-041", "ts_sql_template_injection", 0.85),
    "prisma.$executeRaw": ("AGENT-041", "ts_sql_template_injection", 0.85),
    # Network requests (SSRF)
    "fetch": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "axios.get": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "axios.post": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "axios.put": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "axios.delete": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "axios.patch": ("AGENT-026", "ts_ssrf_fetch", 0.70),
    "http.request": ("AGENT-026", "ts_ssrf_fetch", 0.75),
    "https.request": ("AGENT-026", "ts_ssrf_fetch", 0.75),
}

# SQL keywords used to identify SQL template strings
SQL_KEYWORDS: Set[str] = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "CREATE", "TRUNCATE", "MERGE", "REPLACE", "GRANT", "REVOKE",
}

# Prompt-related variable/function names
PROMPT_CONTEXT_NAMES: Set[str] = {
    "prompt", "system_prompt", "systemPrompt", "system_message",
    "systemMessage", "user_prompt", "userPrompt", "instruction",
    "instructions", "message", "messages", "template",
    "system", "role",
}

# Unsafe deserialization patterns for JS/TS
UNSAFE_DESER_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (
        re.compile(r'\bnode-serialize\b|\brequire\s*\(\s*["\']node-serialize["\']\s*\)'),
        "node-serialize (known RCE vulnerability)",
        0.95,
    ),
    (
        re.compile(r'\bunserialize\s*\('),
        "unserialize() call (potential RCE)",
        0.85,
    ),
    (
        re.compile(r'\bserialize-javascript\b.*\bdeserialize\b'),
        "serialize-javascript deserialize",
        0.80,
    ),
    (
        re.compile(r'\byaml\.load\s*\((?!.*safe)', re.IGNORECASE),
        "yaml.load without safe option",
        0.80,
    ),
]

# File extensions supported by this scanner
TS_EXTENSIONS: Set[str] = {".ts", ".tsx", ".js", ".jsx", ".mjs"}

# Directories to skip during scanning
SKIP_DIRS: Set[str] = {
    ".git", "venv", ".venv", "__pycache__", "dist",
    "build", "node_modules", ".tox", ".pytest_cache",
    ".next", ".nuxt", "coverage", ".nyc_output",
}

# OWASP ID mapping for rule IDs
RULE_OWASP_MAP: Dict[str, str] = {
    "AGENT-034": "ASI-02",
    "AGENT-041": "ASI-02",
    "AGENT-010": "ASI-01",
    "AGENT-026": "ASI-02",
    "AGENT-049": "ASI-04",
}

# CWE ID mapping for rule IDs
RULE_CWE_MAP: Dict[str, str] = {
    "AGENT-034": "CWE-20",
    "AGENT-041": "CWE-89",
    "AGENT-010": "CWE-74",
    "AGENT-026": "CWE-918",
    "AGENT-049": "CWE-502",
}

# Category mapping for rule IDs
RULE_CATEGORY_MAP: Dict[str, Category] = {
    "AGENT-034": Category.TOOL_MISUSE,
    "AGENT-041": Category.COMMAND_INJECTION,
    "AGENT-010": Category.PROMPT_INJECTION,
    "AGENT-026": Category.SUPPLY_CHAIN_AGENTIC,
    "AGENT-049": Category.SUPPLY_CHAIN_AGENTIC,
}

# Severity mapping for pattern types
PATTERN_SEVERITY_MAP: Dict[str, Severity] = {
    "ts_eval_exec": Severity.CRITICAL,
    "ts_child_process_exec": Severity.CRITICAL,
    "ts_sql_template_injection": Severity.HIGH,
    "ts_template_prompt_injection": Severity.HIGH,
    "ts_ssrf_fetch": Severity.MEDIUM,
    "ts_unsafe_deserialization": Severity.HIGH,
}


@dataclass
class TSFinding:
    """Internal finding from TypeScript scanner before conversion."""

    rule_id: str
    pattern_type: str
    title: str
    description: str
    severity: Severity
    category: Category
    owasp_id: str
    cwe_id: str
    line: int
    snippet: str
    confidence: float
    file_path: str
    remediation: str


@dataclass
class TSScanResult(ScanResult):
    """Result of TypeScript scanning."""

    findings: List[TSFinding] = field(default_factory=list)


class TypeScriptScanner(BaseScanner):
    """
    Scanner for TypeScript/JavaScript security issues in AI agent code.

    Detects dangerous function calls, template string injections,
    SSRF patterns, and unsafe deserialization using tree-sitter AST
    analysis with regex fallback.
    """

    name = "TypeScript Scanner"

    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        """Initialize the TypeScript scanner.

        Args:
            exclude_patterns: List of glob patterns to exclude from scanning
        """
        self.exclude_patterns = exclude_patterns or []

    def scan(self, path: Path) -> Sequence[TSScanResult]:
        """
        Scan path for TypeScript/JavaScript security issues.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results with TypeScript findings
        """
        results: List[TSScanResult] = []
        files_to_scan = self._find_files(path)

        for file_path in files_to_scan:
            try:
                result = self._scan_file(file_path)
                if result and result.findings:
                    results.append(result)
            except Exception as e:
                logger.warning("Error scanning %s: %s", file_path, e)

        return results

    def scan_and_convert(self, path: Path) -> List[Finding]:
        """
        Scan and convert results to Finding objects.

        Args:
            path: File or directory to scan

        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        scan_results = self.scan(path)

        for result in scan_results:
            for ts_finding in result.findings:
                finding = self._convert_to_finding(ts_finding)
                findings.append(finding)

        return findings

    # ========================================================================
    # File discovery
    # ========================================================================

    def _find_files(self, path: Path) -> List[Path]:
        """Find TypeScript/JavaScript files to scan."""
        if path.is_file():
            if path.suffix in TS_EXTENSIONS:
                return [path]
            return []

        files: List[Path] = []
        for ext in TS_EXTENSIONS:
            for file_path in path.rglob(f"*{ext}"):
                if any(part in SKIP_DIRS for part in file_path.parts):
                    continue
                if self._is_excluded(file_path):
                    continue
                files.append(file_path)

        return files

    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file matches any exclude pattern."""
        file_str = str(file_path)
        for pattern in self.exclude_patterns:
            if pattern in file_str:
                return True
        return False

    # ========================================================================
    # File scanning
    # ========================================================================

    def _scan_file(self, file_path: Path) -> Optional[TSScanResult]:
        """Scan a single TypeScript/JavaScript file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning("Cannot read %s: %s", file_path, e)
            return None

        if not content.strip():
            return None

        file_str = str(file_path)
        findings: List[TSFinding] = []
        lines = content.splitlines()

        # Attempt tree-sitter-based analysis first
        ts_findings = self._scan_with_treesitter(file_path, content, file_str)
        if ts_findings is not None:
            findings.extend(ts_findings)
        else:
            # Fallback to regex-based analysis
            findings.extend(self._scan_dangerous_calls_regex(lines, file_str))
            findings.extend(self._scan_template_sql_regex(lines, file_str))
            findings.extend(self._scan_template_prompt_regex(lines, file_str))
            findings.extend(self._scan_ssrf_regex(lines, file_str))

        # Unsafe deserialization detection (always regex-based, patterns are simple)
        findings.extend(self._scan_unsafe_deserialization(lines, file_str))

        if findings:
            return TSScanResult(source_file=file_str, findings=findings)
        return None

    # ========================================================================
    # Tree-sitter-based analysis
    # ========================================================================

    def _scan_with_treesitter(
        self, file_path: Path, content: str, file_str: str
    ) -> Optional[List[TSFinding]]:
        """
        Attempt tree-sitter-based scanning.

        Returns None if tree-sitter is not available, otherwise returns
        a list of findings (possibly empty).
        """
        try:
            from agent_audit.parsers.treesitter_parser import TreeSitterParser
        except ImportError:
            return None

        parser = TreeSitterParser(
            source=content,
            file_path=str(file_path),
        )

        if not parser.is_tree_sitter_available:
            return None

        findings: List[TSFinding] = []

        # Analyze function calls from tree-sitter
        function_calls = parser.find_function_calls()
        for call in function_calls:
            call_findings = self._analyze_ts_call(call, content, file_str)
            findings.extend(call_findings)

        # Analyze string literals for SQL/prompt injection
        string_literals = parser.find_string_literals()
        for literal in string_literals:
            literal_findings = self._analyze_ts_literal(
                literal, content, file_str
            )
            findings.extend(literal_findings)

        return findings

    def _analyze_ts_call(
        self, call: "FunctionCall", content: str, file_str: str  # noqa: F821
    ) -> List[TSFinding]:
        """Analyze a function call from tree-sitter for dangerous patterns."""
        findings: List[TSFinding] = []
        call_name = call.name

        # Direct match in dangerous calls table
        match_entry = TS_DANGEROUS_CALLS.get(call_name)

        # Try qualified name matching (e.g., child_process.exec)
        if match_entry is None:
            # Check if the call name ends with a known dangerous suffix
            for dangerous_name, entry in TS_DANGEROUS_CALLS.items():
                if call_name.endswith(dangerous_name):
                    match_entry = entry
                    break

        if match_entry is None:
            return findings

        rule_id, pattern_type, base_confidence = match_entry

        # For SQL-related calls, only flag if template string is used as argument
        if pattern_type == "ts_sql_template_injection":
            if not self._has_template_arg_with_sql(call.args, call.raw_text):
                return findings

        # For SSRF calls, adjust confidence based on argument type
        if pattern_type == "ts_ssrf_fetch":
            confidence = self._compute_ssrf_confidence(
                call.args, base_confidence
            )
            if confidence < 0.30:
                return findings
            base_confidence = confidence

        # For new Function() - check for "new" keyword in raw text
        if call_name == "Function" and "new" not in call.raw_text:
            return findings

        findings.append(
            TSFinding(
                rule_id=rule_id,
                pattern_type=pattern_type,
                title=self._get_title(pattern_type),
                description=self._get_description(pattern_type, call_name),
                severity=PATTERN_SEVERITY_MAP.get(
                    pattern_type, Severity.MEDIUM
                ),
                category=RULE_CATEGORY_MAP.get(
                    rule_id, Category.TOOL_MISUSE
                ),
                owasp_id=RULE_OWASP_MAP.get(rule_id, "ASI-02"),
                cwe_id=RULE_CWE_MAP.get(rule_id, "CWE-20"),
                line=call.line,
                snippet=call.raw_text[:200],
                confidence=base_confidence,
                file_path=file_str,
                remediation=self._get_remediation(pattern_type),
            )
        )

        return findings

    def _analyze_ts_literal(
        self, literal: "StringLiteral", content: str, file_str: str  # noqa: F821
    ) -> List[TSFinding]:
        """Analyze a string literal for SQL/prompt injection patterns."""
        findings: List[TSFinding] = []

        # Only interested in template strings with interpolation
        if not literal.is_fstring:
            return findings

        value_upper = literal.value.upper()

        # Check for SQL keywords in template string
        has_sql = any(kw in value_upper for kw in SQL_KEYWORDS)
        if has_sql and "${" in literal.raw_value:
            findings.append(
                TSFinding(
                    rule_id="AGENT-041",
                    pattern_type="ts_sql_template_injection",
                    title="SQL Injection via Template String",
                    description=(
                        "SQL query constructed using template string interpolation. "
                        "User input may be injected into the query without sanitization."
                    ),
                    severity=Severity.HIGH,
                    category=Category.COMMAND_INJECTION,
                    owasp_id="ASI-02",
                    cwe_id="CWE-89",
                    line=literal.line,
                    snippet=literal.raw_value[:200],
                    confidence=0.85,
                    file_path=file_str,
                    remediation=(
                        "Use parameterized queries instead of template string "
                        "interpolation for SQL queries."
                    ),
                )
            )

        # Check for prompt injection in template strings
        if self._is_prompt_context(literal, content):
            findings.append(
                TSFinding(
                    rule_id="AGENT-010",
                    pattern_type="ts_template_prompt_injection",
                    title="Prompt Injection via Template String",
                    description=(
                        "System/user prompt constructed using template string "
                        "interpolation. Untrusted input may manipulate agent behavior."
                    ),
                    severity=Severity.HIGH,
                    category=Category.PROMPT_INJECTION,
                    owasp_id="ASI-01",
                    cwe_id="CWE-74",
                    line=literal.line,
                    snippet=literal.raw_value[:200],
                    confidence=0.75,
                    file_path=file_str,
                    remediation=(
                        "Sanitize user input before including in prompts. "
                        "Use structured prompt templates with explicit boundaries."
                    ),
                )
            )

        return findings

    # ========================================================================
    # Regex-based fallback analysis
    # ========================================================================

    def _scan_dangerous_calls_regex(
        self, lines: List[str], file_str: str
    ) -> List[TSFinding]:
        """Scan for dangerous function calls using regex."""
        findings: List[TSFinding] = []

        # Patterns: (regex, rule_id, pattern_type, confidence, display_name)
        patterns: List[Tuple[re.Pattern, str, str, float, str]] = [
            # eval()
            (
                re.compile(r"\beval\s*\("),
                "AGENT-034",
                "ts_eval_exec",
                0.95,
                "eval",
            ),
            # new Function()
            (
                re.compile(r"\bnew\s+Function\s*\("),
                "AGENT-034",
                "ts_eval_exec",
                0.90,
                "new Function",
            ),
            # vm.runIn*
            (
                re.compile(r"\bvm\.runIn(?:Context|NewContext|ThisContext)\s*\("),
                "AGENT-034",
                "ts_eval_exec",
                0.90,
                "vm.runInContext",
            ),
            # child_process.exec/execSync
            (
                re.compile(
                    r"\b(?:child_process\.)?(?:exec|execSync)\s*\("
                ),
                "AGENT-034",
                "ts_child_process_exec",
                0.90,
                "exec",
            ),
            # child_process.spawn/spawnSync
            (
                re.compile(
                    r"\b(?:child_process\.)?(?:spawn|spawnSync)\s*\("
                ),
                "AGENT-034",
                "ts_child_process_exec",
                0.85,
                "spawn",
            ),
            # execa
            (
                re.compile(r"\bexeca(?:Sync)?\s*\("),
                "AGENT-034",
                "ts_child_process_exec",
                0.85,
                "execa",
            ),
        ]

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, rule_id, pattern_type, confidence, call_name in patterns:
                if pattern.search(line):
                    findings.append(
                        TSFinding(
                            rule_id=rule_id,
                            pattern_type=pattern_type,
                            title=self._get_title(pattern_type),
                            description=self._get_description(
                                pattern_type, call_name
                            ),
                            severity=PATTERN_SEVERITY_MAP.get(
                                pattern_type, Severity.MEDIUM
                            ),
                            category=RULE_CATEGORY_MAP.get(
                                rule_id, Category.TOOL_MISUSE
                            ),
                            owasp_id=RULE_OWASP_MAP.get(rule_id, "ASI-02"),
                            cwe_id=RULE_CWE_MAP.get(rule_id, "CWE-20"),
                            line=line_num,
                            snippet=stripped[:200],
                            confidence=confidence,
                            file_path=file_str,
                            remediation=self._get_remediation(pattern_type),
                        )
                    )

        return findings

    def _scan_template_sql_regex(
        self, lines: List[str], file_str: str
    ) -> List[TSFinding]:
        """Scan for SQL injection via template strings using regex."""
        findings: List[TSFinding] = []

        # Match template strings containing SQL keywords and interpolation
        template_sql_pattern = re.compile(
            r"`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{[^}]+\}[^`]*`",
            re.IGNORECASE,
        )

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            if template_sql_pattern.search(line):
                findings.append(
                    TSFinding(
                        rule_id="AGENT-041",
                        pattern_type="ts_sql_template_injection",
                        title="SQL Injection via Template String",
                        description=(
                            "SQL query constructed using template string "
                            "interpolation. User input may be injected "
                            "into the query without sanitization."
                        ),
                        severity=Severity.HIGH,
                        category=Category.COMMAND_INJECTION,
                        owasp_id="ASI-02",
                        cwe_id="CWE-89",
                        line=line_num,
                        snippet=stripped[:200],
                        confidence=0.85,
                        file_path=file_str,
                        remediation=(
                            "Use parameterized queries instead of "
                            "template string interpolation for SQL queries."
                        ),
                    )
                )

        return findings

    def _scan_template_prompt_regex(
        self, lines: List[str], file_str: str
    ) -> List[TSFinding]:
        """Scan for prompt injection via template strings using regex."""
        findings: List[TSFinding] = []

        # Pattern: variable assignment to a prompt-related name with template string
        prompt_template_pattern = re.compile(
            r"(?:const|let|var)\s+("
            + "|".join(re.escape(n) for n in PROMPT_CONTEXT_NAMES)
            + r")\s*=\s*`[^`]*\$\{[^}]+\}[^`]*`",
            re.IGNORECASE,
        )

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            match = prompt_template_pattern.search(line)
            if match:
                findings.append(
                    TSFinding(
                        rule_id="AGENT-010",
                        pattern_type="ts_template_prompt_injection",
                        title="Prompt Injection via Template String",
                        description=(
                            f"Prompt variable '{match.group(1)}' constructed "
                            "using template string interpolation. Untrusted "
                            "input may manipulate agent behavior."
                        ),
                        severity=Severity.HIGH,
                        category=Category.PROMPT_INJECTION,
                        owasp_id="ASI-01",
                        cwe_id="CWE-74",
                        line=line_num,
                        snippet=stripped[:200],
                        confidence=0.75,
                        file_path=file_str,
                        remediation=(
                            "Sanitize user input before including in prompts. "
                            "Use structured prompt templates with explicit boundaries."
                        ),
                    )
                )

        return findings

    def _scan_ssrf_regex(
        self, lines: List[str], file_str: str
    ) -> List[TSFinding]:
        """Scan for SSRF patterns using regex."""
        findings: List[TSFinding] = []

        # Pattern: fetch/axios with variable argument (not hardcoded string)
        # Negative lookahead excludes calls where the first arg is a string literal
        _quote_lookahead = r"""(?!['"\x60])"""
        ssrf_patterns: List[Tuple[re.Pattern, str, float]] = [
            (
                re.compile(r"\bfetch\s*\(\s*" + _quote_lookahead),
                "fetch",
                0.70,
            ),
            (
                re.compile(
                    r"\baxios\.(?:get|post|put|delete|patch)\s*\(\s*" + _quote_lookahead
                ),
                "axios",
                0.70,
            ),
            (
                re.compile(
                    r"\bhttps?\.request\s*\(\s*" + _quote_lookahead
                ),
                "http.request",
                0.75,
            ),
        ]

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, call_name, confidence in ssrf_patterns:
                if pattern.search(line):
                    findings.append(
                        TSFinding(
                            rule_id="AGENT-026",
                            pattern_type="ts_ssrf_fetch",
                            title="Server-Side Request Forgery (SSRF)",
                            description=(
                                f"Network request via {call_name}() with "
                                "dynamic URL. User-controlled input may be "
                                "used to access internal services."
                            ),
                            severity=Severity.MEDIUM,
                            category=Category.SUPPLY_CHAIN_AGENTIC,
                            owasp_id="ASI-02",
                            cwe_id="CWE-918",
                            line=line_num,
                            snippet=stripped[:200],
                            confidence=confidence,
                            file_path=file_str,
                            remediation=(
                                "Validate and allowlist URLs before making "
                                "network requests. Use URL parsing to verify "
                                "the hostname against an allowlist."
                            ),
                        )
                    )

        return findings

    def _scan_unsafe_deserialization(
        self, lines: List[str], file_str: str
    ) -> List[TSFinding]:
        """Scan for unsafe deserialization patterns."""
        findings: List[TSFinding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, description, confidence in UNSAFE_DESER_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        TSFinding(
                            rule_id="AGENT-049",
                            pattern_type="ts_unsafe_deserialization",
                            title="Unsafe Deserialization",
                            description=(
                                f"Unsafe deserialization detected: {description}. "
                                "Deserializing untrusted data can lead to "
                                "remote code execution."
                            ),
                            severity=Severity.HIGH,
                            category=Category.SUPPLY_CHAIN_AGENTIC,
                            owasp_id="ASI-04",
                            cwe_id="CWE-502",
                            line=line_num,
                            snippet=stripped[:200],
                            confidence=confidence,
                            file_path=file_str,
                            remediation=(
                                "Avoid deserializing untrusted data. "
                                "Use safe alternatives like JSON.parse() for "
                                "data interchange."
                            ),
                        )
                    )

        return findings

    # ========================================================================
    # Helper methods
    # ========================================================================

    def _has_template_arg_with_sql(
        self, args: List[str], raw_text: str
    ) -> bool:
        """Check if any argument is a template string containing SQL keywords."""
        combined = " ".join(args) + " " + raw_text
        combined_upper = combined.upper()
        has_sql = any(kw in combined_upper for kw in SQL_KEYWORDS)
        has_interpolation = "${" in combined
        return has_sql and has_interpolation

    def _compute_ssrf_confidence(
        self, args: List[str], base_confidence: float
    ) -> float:
        """
        Compute confidence for SSRF finding based on argument analysis.

        Hardcoded string URLs get low confidence; dynamic URLs get high.
        """
        if not args:
            return base_confidence

        first_arg = args[0].strip()

        # Hardcoded string literal - low confidence
        if (
            first_arg.startswith(("'", '"', "`"))
            and "${" not in first_arg
        ):
            return 0.25

        # Template string with interpolation - high confidence
        if "`" in first_arg and "${" in first_arg:
            return base_confidence * 1.1

        # Variable reference - standard confidence
        return base_confidence

    def _is_prompt_context(
        self, literal: "StringLiteral", content: str  # noqa: F821
    ) -> bool:
        """Check if a template string is used in a prompt context."""
        # Check if template string has interpolation
        if "${" not in literal.raw_value:
            return False

        # Get the surrounding lines for context
        content_lines = content.splitlines()
        start = max(0, literal.line - 3)
        end = min(len(content_lines), literal.line + 2)
        context_window = "\n".join(content_lines[start:end]).lower()

        # Check if any prompt-related names appear nearby
        return any(
            name.lower() in context_window
            for name in PROMPT_CONTEXT_NAMES
        )

    def _get_title(self, pattern_type: str) -> str:
        """Get human-readable title for a pattern type."""
        titles: Dict[str, str] = {
            "ts_eval_exec": "Dangerous Code Execution",
            "ts_child_process_exec": "Shell Command Execution",
            "ts_sql_template_injection": "SQL Injection via Template String",
            "ts_template_prompt_injection": "Prompt Injection via Template String",
            "ts_ssrf_fetch": "Server-Side Request Forgery (SSRF)",
            "ts_unsafe_deserialization": "Unsafe Deserialization",
        }
        return titles.get(pattern_type, "Security Issue")

    def _get_description(self, pattern_type: str, call_name: str) -> str:
        """Get human-readable description for a pattern type."""
        descriptions: Dict[str, str] = {
            "ts_eval_exec": (
                f"Dangerous code execution via {call_name}(). "
                "Executing untrusted code can lead to remote code execution."
            ),
            "ts_child_process_exec": (
                f"Shell command execution via {call_name}(). "
                "Command injection is possible if user input is included "
                "in the command string."
            ),
            "ts_sql_template_injection": (
                f"SQL query via {call_name}() uses template string interpolation. "
                "User input may be injected without sanitization."
            ),
            "ts_template_prompt_injection": (
                "Prompt constructed using template string interpolation. "
                "Untrusted input may manipulate agent behavior."
            ),
            "ts_ssrf_fetch": (
                f"Network request via {call_name}() with potentially "
                "user-controlled URL. May allow access to internal services."
            ),
            "ts_unsafe_deserialization": (
                f"Unsafe deserialization via {call_name}(). "
                "Deserializing untrusted data can lead to remote code execution."
            ),
        }
        return descriptions.get(pattern_type, f"Security issue in {call_name}()")

    def _get_remediation(self, pattern_type: str) -> str:
        """Get remediation guidance for a pattern type."""
        remediations: Dict[str, str] = {
            "ts_eval_exec": (
                "Avoid eval() and new Function(). Use safe alternatives "
                "like JSON.parse() for data or a sandboxed VM for code execution."
            ),
            "ts_child_process_exec": (
                "Use execFile() or spawn() with an argument array instead of "
                "exec() with a command string. Never include user input in "
                "shell commands."
            ),
            "ts_sql_template_injection": (
                "Use parameterized queries instead of template string "
                "interpolation for SQL queries."
            ),
            "ts_template_prompt_injection": (
                "Sanitize user input before including in prompts. "
                "Use structured prompt templates with explicit boundaries."
            ),
            "ts_ssrf_fetch": (
                "Validate and allowlist URLs before making network requests. "
                "Use URL parsing to verify the hostname against an allowlist."
            ),
            "ts_unsafe_deserialization": (
                "Avoid deserializing untrusted data. Use safe alternatives "
                "like JSON.parse() for data interchange."
            ),
        }
        return remediations.get(pattern_type, "Review and secure this code pattern.")

    def _convert_to_finding(self, ts_finding: TSFinding) -> Finding:
        """Convert TSFinding to Finding model."""
        confidence = ts_finding.confidence
        tier = confidence_to_tier(confidence)

        return Finding(
            rule_id=ts_finding.rule_id,
            title=ts_finding.title,
            description=ts_finding.description,
            severity=ts_finding.severity,
            category=ts_finding.category,
            location=Location(
                file_path=ts_finding.file_path,
                start_line=ts_finding.line,
                end_line=ts_finding.line,
                snippet=ts_finding.snippet,
            ),
            cwe_id=ts_finding.cwe_id,
            owasp_id=ts_finding.owasp_id,
            confidence=confidence,
            tier=tier,
            remediation=Remediation(description=ts_finding.remediation),
        )
