"""Secret scanner for detecting hardcoded credentials."""

import fnmatch
import re
import logging
from pathlib import Path
from typing import List, Optional, Pattern, Tuple
from dataclasses import dataclass, field

from agent_audit.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Lazy import for semantic analyzer to avoid circular imports
_semantic_analyzer = None


def _get_semantic_analyzer():
    """Lazy load the semantic analyzer."""
    global _semantic_analyzer
    if _semantic_analyzer is None:
        from agent_audit.analysis.semantic_analyzer import get_analyzer
        _semantic_analyzer = get_analyzer()
    return _semantic_analyzer


@dataclass
class SecretMatch:
    """A detected secret."""
    pattern_name: str
    line_number: int
    line_content: str
    matched_text: str
    start_col: int
    end_col: int
    severity: str  # critical, high, medium
    # v0.5.0: Semantic analysis fields
    confidence: float = 1.0
    tier: str = "BLOCK"
    format_matched: Optional[str] = None


@dataclass
class SecretScanResult(ScanResult):
    """Result of secret scanning."""
    secrets: List[SecretMatch] = field(default_factory=list)


class SecretScanner(BaseScanner):
    """
    Regex-based secret detection scanner.

    Detects:
    - AWS access keys
    - API keys (OpenAI, Anthropic, GitHub, etc.)
    - Generic tokens and passwords
    - Private keys
    """

    name = "Secret Scanner"

    # Secret patterns with severity levels
    SECRET_PATTERNS: List[Tuple[Pattern, str, str]] = [
        # AWS
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID", "critical"),
        (re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
         "Potential AWS Secret Key", "high"),

        # OpenAI
        (re.compile(r'sk-[a-zA-Z0-9]{48,}'), "OpenAI API Key", "critical"),
        (re.compile(r'sk-proj-[a-zA-Z0-9]{48,}'), "OpenAI Project API Key", "critical"),

        # Anthropic
        (re.compile(r'sk-ant-[a-zA-Z0-9-]{40,}'), "Anthropic API Key", "critical"),

        # GitHub
        (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token", "critical"),
        (re.compile(r'gho_[a-zA-Z0-9]{36}'), "GitHub OAuth Token", "critical"),
        (re.compile(r'ghs_[a-zA-Z0-9]{36}'), "GitHub App Token", "critical"),
        (re.compile(r'ghr_[a-zA-Z0-9]{36}'), "GitHub Refresh Token", "critical"),

        # Google
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key", "critical"),

        # Stripe
        (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'), "Stripe Live Secret Key", "critical"),
        (re.compile(r'sk_test_[a-zA-Z0-9]{24,}'), "Stripe Test Secret Key", "high"),
        (re.compile(r'pk_live_[a-zA-Z0-9]{24,}'), "Stripe Live Publishable Key", "medium"),

        # Generic patterns
        (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
         "Generic API Key", "high"),
        (re.compile(r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
         "Generic Secret/Password", "high"),
        (re.compile(r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
         "Generic Token", "high"),

        # Private keys
        (re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
         "Private Key Header", "critical"),
        (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
         "PGP Private Key", "critical"),

        # Database connection strings
        (re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s"\']+:[^\s"\']+@'),
         "Database Connection String with Credentials", "critical"),

        # JWT secrets
        (re.compile(r'(?i)jwt[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
         "JWT Secret", "high"),

        # Slack
        (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
         "Slack Token", "critical"),

        # Twilio
        (re.compile(r'SK[a-f0-9]{32}'), "Twilio API Key", "critical"),

        # SendGrid
        (re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
         "SendGrid API Key", "critical"),
    ]

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml',
        '.env', '.cfg', '.conf', '.config', '.ini', '.properties',
        '.sh', '.bash', '.zsh', '.toml', '.xml', '.md', '.txt'
    }

    # Files to always skip
    SKIP_FILES = {
        'package-lock.json', 'yarn.lock', 'poetry.lock',
        'Cargo.lock', 'go.sum', 'pnpm-lock.yaml'
    }

    def __init__(
        self,
        exclude_paths: Optional[List[str]] = None,
        custom_patterns: Optional[List[Tuple[str, str, str]]] = None
    ):
        """
        Initialize the secret scanner.

        Args:
            exclude_paths: Path patterns to exclude
            custom_patterns: Additional patterns as (regex, name, severity) tuples
        """
        self.exclude_paths = set(exclude_paths or [])
        self.patterns = list(self.SECRET_PATTERNS)

        # Add custom patterns
        if custom_patterns:
            for regex_str, name, severity in custom_patterns:
                self.patterns.append((re.compile(regex_str), name, severity))

    def scan(self, path: Path) -> List[SecretScanResult]:
        """
        Scan for secrets in files.

        Args:
            path: File or directory to scan

        Returns:
            List of scan results
        """
        results = []
        files = self._find_files(path)

        for file_path in files:
            result = self._scan_file(file_path)
            if result and result.secrets:
                results.append(result)

        return results

    def _find_files(self, path: Path) -> List[Path]:
        """Find files to scan."""
        if path.is_file():
            if self._should_scan_file(path):
                return [path]
            return []

        files = []
        for file_path in path.rglob('*'):
            if not file_path.is_file():
                continue

            if not self._should_scan_file(file_path):
                continue

            # Check exclude patterns using glob matching
            rel_path = str(file_path.relative_to(path))
            if self._should_exclude(rel_path):
                continue

            files.append(file_path)

        return files

    def _should_exclude(self, rel_path: str) -> bool:
        """Check if a relative path matches any exclude pattern."""
        # Normalize path separators
        normalized_path = rel_path.replace('\\', '/')

        for pattern in self.exclude_paths:
            normalized_pattern = pattern.replace('\\', '/')

            # Simple substring matching (backward compatibility)
            if normalized_pattern in normalized_path:
                return True

            # Direct fnmatch for glob patterns
            if fnmatch.fnmatch(normalized_path, normalized_pattern):
                return True

            # Handle "tests/**" style patterns
            if normalized_pattern.endswith('/**'):
                prefix = normalized_pattern[:-3]
                if normalized_path.startswith(prefix + '/') or normalized_path == prefix:
                    return True

            # Handle "**/test_*" style patterns
            if normalized_pattern.startswith('**/'):
                suffix_pattern = normalized_pattern[3:]
                # Match against filename
                filename = Path(normalized_path).name
                if fnmatch.fnmatch(filename, suffix_pattern):
                    return True
                # Match against any path segment
                for part in Path(normalized_path).parts:
                    if fnmatch.fnmatch(part, suffix_pattern):
                        return True

        return False

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Skip known non-secret files
        if file_path.name in self.SKIP_FILES:
            return False

        # Skip hidden directories
        if any(part.startswith('.') and part not in {'.env'}
              for part in file_path.parts[:-1]):
            return False

        # Skip common non-source directories
        skip_dirs = {'node_modules', 'venv', '.venv', '__pycache__',
                    'dist', 'build', '.git'}
        if any(part in skip_dirs for part in file_path.parts):
            return False

        # Check extension
        if file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS:
            return True

        # Also scan .env files regardless of extension
        if '.env' in file_path.name:
            return True

        return False

    def _scan_file(self, file_path: Path) -> Optional[SecretScanResult]:
        """Scan a single file for secrets."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return None

        secrets = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Check each pattern
            for pattern, name, severity in self.patterns:
                for match in pattern.finditer(line):
                    # v0.5.0: Use semantic analyzer for enhanced FP detection
                    analysis_result = self._analyze_with_semantic(
                        match=match,
                        line=line,
                        line_num=line_num,
                        file_path=file_path,
                        pattern_name=name,
                        content=content
                    )

                    # Skip if semantic analysis says it's not a real credential
                    if analysis_result is not None and not analysis_result.should_report:
                        logger.debug(
                            f"Semantic filter: {file_path}:{line_num} - {analysis_result.reason}"
                        )
                        continue

                    # Legacy fallback - use original FP detection if semantic fails
                    if analysis_result is None:
                        if self._is_false_positive(line, match, file_path):
                            continue

                    # Get confidence and tier from semantic analysis
                    confidence = 1.0
                    tier = "BLOCK"
                    format_matched = None
                    if analysis_result is not None:
                        confidence = analysis_result.confidence
                        tier = analysis_result.tier
                        format_matched = analysis_result.format_matched

                    secret = SecretMatch(
                        pattern_name=name,
                        line_number=line_num,
                        line_content=self._mask_secret(line, match),
                        matched_text=self._mask_match(match.group()),
                        start_col=match.start(),
                        end_col=match.end(),
                        severity=severity,
                        confidence=confidence,
                        tier=tier,
                        format_matched=format_matched,
                    )
                    secrets.append(secret)

        return SecretScanResult(
            source_file=str(file_path),
            secrets=secrets
        )

    def _analyze_with_semantic(
        self,
        match: re.Match,
        line: str,
        line_num: int,
        file_path: Path,
        pattern_name: str,
        content: str
    ):
        """
        Analyze a match using the semantic analyzer.

        Returns None if semantic analysis is not available or fails.
        """
        try:
            analyzer = _get_semantic_analyzer()

            # Extract identifier from assignment if possible
            identifier = self._extract_identifier(line, match)

            # v0.5.1: For patterns with capture groups (like Generic Secret/Password),
            # extract the value part (group 2) if available, otherwise use whole match
            value = match.group()
            if match.lastindex and match.lastindex >= 2:
                # Pattern has capture groups, use the value group (usually group 2)
                value = match.group(2) if match.group(2) else match.group()

            return analyzer.analyze_single_match(
                identifier=identifier,
                value=value,
                line=line_num,
                column=match.start(),
                end_column=match.end(),
                raw_line=line,
                file_path=str(file_path),
                pattern_name=pattern_name,
                content=content,
            )
        except Exception as e:
            logger.debug(f"Semantic analysis failed: {e}")
            return None

    def _extract_identifier(self, line: str, match: re.Match) -> str:
        """Extract variable/key identifier from line context."""
        # Look for assignment pattern before the match
        before_match = line[:match.start()].strip()

        # Python/JS assignment: identifier =
        assign_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*$', before_match)
        if assign_match:
            return assign_match.group(1)

        # Dict/JSON key: "key":
        key_match = re.search(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*$', before_match)
        if key_match:
            return key_match.group(1)

        # Generic key-value: key =
        kv_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*$', before_match)
        if kv_match:
            return kv_match.group(1)

        return ""

    def _is_false_positive(
        self,
        line: str,
        match: re.Match,
        file_path: Path
    ) -> bool:
        """
        Check if a match is likely a false positive.

        Filters out:
        - Example/placeholder values
        - Test fixtures
        - Documentation
        - Variable/class/function names containing keywords
        - Environment variable lookups
        - Secure wrappers (SecretStr, etc.)
        """
        matched_text = match.group().lower()
        line_lower = line.lower()
        stripped = line.strip()

        # Common placeholder patterns
        placeholders = [
            'example', 'placeholder', 'your_', 'my_', 'xxx',
            'test', 'fake', 'dummy', 'sample', 'demo', '<your',
            'insert_', 'replace_', 'changeme', 'undefined'
        ]
        if any(p in matched_text for p in placeholders):
            return True

        # Check if this looks like documentation
        if '# example' in line_lower or '// example' in line_lower:
            return True

        # Check file path for test/example indicators
        path_str = str(file_path).lower()
        if any(p in path_str for p in ['test', 'example', 'fixture', 'mock', 'sample']):
            return True

        # Skip class definitions (class FooTokenBar:)
        if stripped.startswith('class '):
            return True

        # Skip function definitions (def get_api_key(...):)
        if stripped.startswith('def '):
            return True

        # Skip import statements
        if stripped.startswith('import ') or stripped.startswith('from '):
            return True

        # Skip type annotations (variable: SecretStr)
        if re.search(r':\s*(Optional\[)?SecretStr', line):
            return True

        # Check for environment variable lookups - value is not hardcoded
        env_patterns = [
            r'os\.environ\.get\s*\(',
            r'os\.environ\[',
            r'os\.getenv\s*\(',
            r'getenv\s*\(',
            r'environ\.get\s*\(',
            r'settings\.\w+',  # e.g., settings.API_KEY
            r'config\.\w+',    # e.g., config.api_key
            r'Config\.\w+',
            r'get_from_\w+\s*\(',  # get_from_env, get_from_dict_or_env, etc.
        ]
        for pattern in env_patterns:
            if re.search(pattern, line):
                return True

        # Check for secure wrappers - value is wrapped, not exposed
        secure_wrappers = [
            r'SecretStr\s*\(',
            r'Secret\s*\(',
            r'SecureString\s*\(',
            r'Field\s*\([^)]*secret\s*=\s*True',
        ]
        for pattern in secure_wrappers:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # For generic patterns (api_key=, token=, etc.), verify the right side
        # is a string literal that looks like a real secret, not a variable
        if self._is_generic_pattern_match(match):
            if not self._has_literal_secret_value(line, match):
                return True

        # Check if match looks like a PascalCase class/type name (e.g., ConversationTokenBufferMemory)
        matched_text_raw = match.group()
        if self._looks_like_class_name(matched_text_raw, line):
            return True

        # Environment variable references (not actual values)
        if '${' in line or '$(' in line:
            if matched_text in line[match.start():match.end()+5]:
                # Check if the match is inside a variable reference
                before = line[:match.start()]
                if '${' in before[-10:] or '$(' in before[-10:]:
                    return True

        return False

    def _looks_like_class_name(self, matched_text: str, line: str) -> bool:
        """
        Check if the matched text looks like a class/type name rather than a secret.

        PascalCase identifiers with multiple capital letters are likely class names,
        not secrets. Real secrets don't follow PascalCase naming conventions.
        """
        # Check for PascalCase pattern: starts with capital, has multiple capitals
        # Also allow all-alpha strings that follow PascalCase (no numbers, no special chars)
        text_to_check = matched_text

        # If match contains '=' (from AWS pattern [A-Za-z0-9/+=]), extract the part after '='
        # This handles cases like 'factory=PairwiseStringResultOutputParser'
        if '=' in matched_text:
            parts = matched_text.split('=')
            # Check if the part after = looks like a class name
            text_to_check = parts[-1]

        if re.match(r'^[A-Z][a-zA-Z]+$', text_to_check):
            # Count capital letters - class names typically have several
            capital_count = sum(1 for c in text_to_check if c.isupper())
            if capital_count >= 2:
                return True

            # Check for common class name suffixes
            class_suffixes = [
                'Memory', 'Buffer', 'Parser', 'Handler', 'Manager',
                'Factory', 'Builder', 'Wrapper', 'Provider', 'Service',
                'Client', 'Server', 'Controller', 'Processor', 'Validator'
            ]
            if any(text_to_check.endswith(suffix) for suffix in class_suffixes):
                return True

        return False

    def _is_generic_pattern_match(self, match: re.Match) -> bool:
        """Check if this match is from a generic pattern (api_key=, token=, etc.)."""
        pattern_str = match.re.pattern
        # Generic patterns have the keyword group followed by = or :
        generic_indicators = [
            r'\(api[_-]?key|apikey\)',
            r'\(secret|password|passwd|pwd\)',
            r'\(token|auth[_-]?token\)',
            r'jwt[_-]?secret',
        ]
        for indicator in generic_indicators:
            if indicator in pattern_str.lower():
                return True
        return False

    def _has_literal_secret_value(self, line: str, match: re.Match) -> bool:
        """
        Check if the matched assignment has a string literal value that looks like a secret.

        Returns True if it looks like a real hardcoded secret, False if it's likely
        a variable reference, function call, or non-secret value.
        """
        # Extract the part after the = or :
        match_text = match.group()
        eq_pos = -1
        for sep in ['=', ':']:
            pos = match_text.find(sep)
            if pos != -1:
                eq_pos = pos
                break

        if eq_pos == -1:
            return True  # Not an assignment pattern, let other checks handle it

        # Get the value part (after = or :)
        value_part = match_text[eq_pos + 1:].strip()

        # Remove leading quotes
        if value_part.startswith('"') or value_part.startswith("'"):
            value_part = value_part[1:]
        if value_part.endswith('"') or value_part.endswith("'"):
            value_part = value_part[:-1]

        # Check if value is empty or too short
        if len(value_part) < 8:
            return False

        # Check if value looks like a variable name (all lowercase/uppercase, underscores)
        if re.match(r'^[a-z_][a-z0-9_]*$', value_part) and not any(c.isdigit() for c in value_part[-4:]):
            return False

        # Check if it's a common non-secret pattern
        non_secret_patterns = [
            r'^[A-Z_]+$',  # All caps constant name like API_KEY
            r'^None$',
            r'^null$',
            r'^""$',
            r"^''$",
            r'^\.\.\.$',  # Ellipsis
        ]
        for pattern in non_secret_patterns:
            if re.match(pattern, value_part, re.IGNORECASE):
                return False

        # Check for mixed characters (letters, numbers, special chars) typical of secrets
        has_letters = bool(re.search(r'[a-zA-Z]', value_part))
        has_numbers = bool(re.search(r'[0-9]', value_part))
        has_special = bool(re.search(r'[-_/+=]', value_part))

        # Real secrets typically have a mix of character types
        char_types = sum([has_letters, has_numbers, has_special])
        if char_types < 2 and len(value_part) < 20:
            return False

        return True

    def _mask_secret(self, line: str, match: re.Match) -> str:
        """Mask the secret value in a line for safe display."""
        start = match.start()
        end = match.end()
        matched_len = end - start

        if matched_len <= 8:
            masked = '*' * matched_len
        else:
            # Show first and last 4 chars
            original = match.group()
            masked = original[:4] + '*' * (matched_len - 8) + original[-4:]

        return line[:start] + masked + line[end:]

    def _mask_match(self, text: str) -> str:
        """Mask a matched secret for display."""
        if len(text) <= 8:
            return '*' * len(text)
        return text[:4] + '*' * (len(text) - 8) + text[-4:]
