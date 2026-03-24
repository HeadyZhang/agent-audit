"""
Base Taint Tracker - Language-agnostic shared layer for taint analysis.

Extracted from taint_tracker.py (v0.13.0) to enable multi-language support.

This module provides:
1. Shared enums: TaintSource, SinkType, SanitizationType
2. Shared dataclasses: TaintedValue, DataFlowEdge, SinkReach, TaintAnalysisResult
3. Shared pattern constants: DANGEROUS_SINKS, ENV_VAR_PATTERNS, etc.
4. Abstract BaseTaintTracker class with shared algorithms

Language-specific implementations (Python, TypeScript, Go) inherit from
BaseTaintTracker and implement the abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# === Shared Enums ===


class TaintSource(Enum):
    """Classification of taint sources."""

    FUNCTION_PARAM = "function_param"  # Function parameter (from LLM/user)
    USER_INPUT = "user_input"  # request.json(), input(), etc.
    ENV_VAR = "env_var"  # os.getenv(), os.environ[]
    NETWORK = "network"  # HTTP requests, sockets
    FILE_READ = "file_read"  # File reads
    LLM_OUTPUT = "llm_output"  # LLM completion results
    HARDCODED = "hardcoded"  # String/number literals (NOT tainted)
    DERIVED = "derived"  # Derived from tainted variable
    UNKNOWN = "unknown"  # Cannot determine source


class SinkType(Enum):
    """Classification of dangerous sinks."""

    SHELL_EXEC = "shell_exec"  # subprocess, os.system, etc.
    CODE_EXEC = "code_exec"  # eval, exec, compile
    SQL_EXEC = "sql_exec"  # cursor.execute, raw SQL
    FILE_WRITE = "file_write"  # File writes with tainted path/content
    NETWORK_REQ = "network_req"  # Network requests with tainted URL/data
    MEMORY_WRITE = "memory_write"  # Agent memory operations
    CRYPTO_SIGN = "crypto_sign"  # Signing operations with tainted key/data


class SanitizationType(Enum):
    """Classification of sanitization operations."""

    TYPE_CHECK = "type_check"  # isinstance, type()
    STRING_CHECK = "string_check"  # startswith, endswith, isalnum, etc.
    LENGTH_CHECK = "length_check"  # len() comparison
    ALLOWLIST_CHECK = "allowlist_check"  # x in ALLOWED, x not in BLOCKED
    EXPLICIT_VALIDATION = "explicit_validation"  # validate(), sanitize(), etc.
    ESCAPE_TRANSFORM = "escape_transform"  # escape(), quote(), html.escape()


# === Shared Dataclasses ===


@dataclass
class TaintedValue:
    """Represents a value with taint information."""

    name: str
    source: TaintSource
    line: int
    original_param: Optional[str] = None  # Original param if derived
    is_sanitized: bool = False
    sanitization_type: Optional[SanitizationType] = None
    sanitization_line: Optional[int] = None


@dataclass
class DataFlowEdge:
    """Represents a data flow edge in the flow graph."""

    source: str  # Source variable/expression
    target: str  # Target variable/expression
    edge_type: str  # 'assign', 'call_arg', 'format', 'concat', 'attribute'
    line: int


@dataclass
class SinkReach:
    """Represents a tainted value reaching a dangerous sink."""

    tainted_var: str
    sink_function: str
    sink_type: SinkType
    line: int
    is_sanitized: bool
    flow_path: List[str]  # Variable chain from source to sink
    source: TaintSource
    confidence: float


@dataclass
class TaintAnalysisResult:
    """Result of taint analysis for a function."""

    function_name: str
    tainted_params: List[str]
    dangerous_flows: List[SinkReach]
    sanitization_points: Dict[str, Tuple[SanitizationType, int]]
    has_unsanitized_flow: bool
    confidence: float
    analysis_notes: List[str] = field(default_factory=list)

    def to_metadata_dict(self) -> Dict[str, Any]:
        """
        Export taint analysis as metadata dict for engine.py.

        v0.14.0: Returns format expected by oracle_eval.validates_taint_flow():
        {
            'dangerous_flows': [
                {
                    'var': str,
                    'sink': str,
                    'sink_type': str,  # 'eval', 'code_execution', 'shell_execution'
                    'source': str,     # 'user_input', 'llm_output', 'config'
                    'line': int,
                    'path': List[str],
                    'confidence': float,
                }
            ],
            'sanitization_points': [...]
        }
        """
        # Map internal sink types to oracle-compatible types
        # Oracle expects: 'eval', 'code_execution', 'shell_execution', 'sql_execution'
        sink_type_map = {
            SinkType.CODE_EXEC: 'code_execution',
            SinkType.SHELL_EXEC: 'shell_execution',
            SinkType.SQL_EXEC: 'sql_execution',
            SinkType.FILE_WRITE: 'file_write',
            SinkType.NETWORK_REQ: 'http_request',
            SinkType.MEMORY_WRITE: 'memory_write',
            SinkType.CRYPTO_SIGN: 'crypto_sign',
        }

        # Map internal source types to oracle-compatible types
        # Oracle expects: 'user_input', 'llm_output', 'config'
        source_type_map = {
            TaintSource.FUNCTION_PARAM: 'user_input',
            TaintSource.ENV_VAR: 'config',
            TaintSource.USER_INPUT: 'user_input',
            TaintSource.LLM_OUTPUT: 'llm_output',
            TaintSource.NETWORK: 'user_input',
            TaintSource.FILE_READ: 'user_input',
            TaintSource.DERIVED: 'user_input',
            TaintSource.UNKNOWN: 'user_input',
        }

        exported_flows = []
        for flow in self.dangerous_flows:
            # v0.14.0: Map sink functions to oracle-compatible types
            # Oracle expects 'code_execution' for eval/exec, 'shell_execution' for subprocess
            sink_func = flow.sink_function
            if sink_func in ('eval', 'exec', 'compile'):
                sink_type_str = 'code_execution'
            elif sink_func.startswith('subprocess.') or sink_func in ('os.system', 'os.popen'):
                sink_type_str = 'shell_execution'
            else:
                sink_type_str = sink_type_map.get(flow.sink_type, str(flow.sink_type.value))

            exported_flows.append({
                'var': flow.tainted_var,
                'sink': flow.sink_function,
                'sink_type': sink_type_str,
                'source': source_type_map.get(flow.source, 'user_input'),
                'line': flow.line,
                'path': flow.flow_path,
                'confidence': flow.confidence,
            })

        # Export sanitization points
        exported_sanitization = []
        for var_name, (san_type, line) in self.sanitization_points.items():
            exported_sanitization.append({
                'var': var_name,
                'type': san_type.value,
                'line': line,
            })

        return {
            'dangerous_flows': exported_flows,
            'sanitization_points': exported_sanitization,
        }

    @property
    def has_dangerous_flows(self) -> bool:
        """Check if there are any unsanitized dangerous flows."""
        return self.has_unsanitized_flow


# === Shared Pattern Constants ===

DANGEROUS_SINKS: Dict[str, SinkType] = {
    # Shell execution
    "subprocess.run": SinkType.SHELL_EXEC,
    "subprocess.Popen": SinkType.SHELL_EXEC,
    "subprocess.call": SinkType.SHELL_EXEC,
    "subprocess.check_output": SinkType.SHELL_EXEC,
    "subprocess.check_call": SinkType.SHELL_EXEC,
    "os.system": SinkType.SHELL_EXEC,
    "os.popen": SinkType.SHELL_EXEC,
    "os.spawn": SinkType.SHELL_EXEC,
    "os.spawnl": SinkType.SHELL_EXEC,
    "os.spawnle": SinkType.SHELL_EXEC,
    "os.spawnlp": SinkType.SHELL_EXEC,
    "os.spawnlpe": SinkType.SHELL_EXEC,
    "os.spawnv": SinkType.SHELL_EXEC,
    "os.spawnve": SinkType.SHELL_EXEC,
    "os.spawnvp": SinkType.SHELL_EXEC,
    "os.spawnvpe": SinkType.SHELL_EXEC,
    "os.execl": SinkType.SHELL_EXEC,
    "os.execle": SinkType.SHELL_EXEC,
    "os.execlp": SinkType.SHELL_EXEC,
    "os.execlpe": SinkType.SHELL_EXEC,
    "os.execv": SinkType.SHELL_EXEC,
    "os.execve": SinkType.SHELL_EXEC,
    "os.execvp": SinkType.SHELL_EXEC,
    "os.execvpe": SinkType.SHELL_EXEC,
    # Code execution
    "eval": SinkType.CODE_EXEC,
    "exec": SinkType.CODE_EXEC,
    "compile": SinkType.CODE_EXEC,
    "__import__": SinkType.CODE_EXEC,
    "importlib.import_module": SinkType.CODE_EXEC,
    # SQL execution
    "cursor.execute": SinkType.SQL_EXEC,
    "cursor.executemany": SinkType.SQL_EXEC,
    "connection.execute": SinkType.SQL_EXEC,
    "session.execute": SinkType.SQL_EXEC,
    "engine.execute": SinkType.SQL_EXEC,
    "db.execute": SinkType.SQL_EXEC,
}

# Patterns for env var access
ENV_VAR_PATTERNS: Set[str] = {
    "os.getenv",
    "os.environ.get",
    "os.environ",
    "environ.get",
    "dotenv.get_key",
}

# Patterns for user input
USER_INPUT_PATTERNS: Set[str] = {
    "input",
    "request.json",
    "request.form",
    "request.args",
    "request.data",
    "request.get_json",
    "request.values",
    "flask.request.json",
    "fastapi.Request",
    "sys.stdin.read",
    "sys.stdin.readline",
}

# Patterns for LLM output
LLM_OUTPUT_PATTERNS: Set[str] = {
    "completion.choices",
    "response.content",
    "response.text",
    "chat.completions.create",
    "messages.create",
    "llm.invoke",
    "llm.predict",
    "chain.invoke",
    "chain.run",
    "agent.run",
    "agent.invoke",
}

# Sanitization function patterns
SANITIZATION_PATTERNS: Dict[str, SanitizationType] = {
    # Type checks
    "isinstance": SanitizationType.TYPE_CHECK,
    "type": SanitizationType.TYPE_CHECK,
    # String checks
    "startswith": SanitizationType.STRING_CHECK,
    "endswith": SanitizationType.STRING_CHECK,
    "isalnum": SanitizationType.STRING_CHECK,
    "isalpha": SanitizationType.STRING_CHECK,
    "isdigit": SanitizationType.STRING_CHECK,
    "isnumeric": SanitizationType.STRING_CHECK,
    "isidentifier": SanitizationType.STRING_CHECK,
    "match": SanitizationType.STRING_CHECK,
    "fullmatch": SanitizationType.STRING_CHECK,
    "search": SanitizationType.STRING_CHECK,
    # Length checks
    "len": SanitizationType.LENGTH_CHECK,
    # Explicit validation
    "validate": SanitizationType.EXPLICIT_VALIDATION,
    "sanitize": SanitizationType.EXPLICIT_VALIDATION,
    "check": SanitizationType.EXPLICIT_VALIDATION,
    "verify": SanitizationType.EXPLICIT_VALIDATION,
    "is_valid": SanitizationType.EXPLICIT_VALIDATION,
    "is_safe": SanitizationType.EXPLICIT_VALIDATION,
    # Escape/transform
    "escape": SanitizationType.ESCAPE_TRANSFORM,
    "quote": SanitizationType.ESCAPE_TRANSFORM,
    "html.escape": SanitizationType.ESCAPE_TRANSFORM,
    "shlex.quote": SanitizationType.ESCAPE_TRANSFORM,
    "urllib.parse.quote": SanitizationType.ESCAPE_TRANSFORM,
    "markupsafe.escape": SanitizationType.ESCAPE_TRANSFORM,
    "bleach.clean": SanitizationType.ESCAPE_TRANSFORM,
}


# === Abstract Base Class ===


class BaseTaintTracker(ABC):
    """
    Abstract base class for language-specific taint trackers.

    Provides shared algorithms (BFS reachability, confidence calculation)
    while requiring language-specific implementations for source classification,
    data flow building, sanitization detection, and sink identification.

    Subclasses:
    - TaintTracker (Python) - uses stdlib ast module
    - TSTaintTracker (TypeScript) - uses tree-sitter
    - GoTaintTracker (Go) - uses tree-sitter
    """

    @abstractmethod
    def analyze(self, *args: Any, **kwargs: Any) -> TaintAnalysisResult:
        """
        Run full taint analysis. Signature varies by language implementation.

        Python: analyze() -> TaintAnalysisResult  (uses self.func_node)
        TS/Go: analyze(function_node) -> TaintAnalysisResult
        """
        ...

    def _bfs_reachability(
        self,
        flow_graph: Dict[str, List[Tuple[str, int]]],
        tainted_values: Dict[str, TaintedValue],
        sink_calls: List[Tuple[str, str, int]],
        sanitized_vars: Dict[str, Tuple[SanitizationType, int, Optional[int]]],
        var_used_checker: Any = None,
    ) -> List[SinkReach]:
        """
        Shared BFS algorithm to check if tainted values reach dangerous sinks.

        Args:
            flow_graph: Adjacency list {var: [(target, line), ...]}
            tainted_values: Map of variable name to TaintedValue
            sink_calls: List of (func_name, sink_type_value, line)
            sanitized_vars: Map of variable to (san_type, line, scope_end)
            var_used_checker: Callable(var_name, func_name, line) -> bool

        Returns:
            List of SinkReach objects
        """
        results: List[SinkReach] = []

        for var_name, tainted in tainted_values.items():
            if tainted.source == TaintSource.HARDCODED:
                continue

            visited: Set[str] = set()
            queue: List[Tuple[str, List[str], int]] = [
                (var_name, [var_name], tainted.line)
            ]

            while queue:
                current, path, current_line = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                for sink_func, sink_type_name, sink_line in sink_calls:
                    sink_type = SinkType(sink_type_name)
                    used = True
                    if var_used_checker is not None:
                        used = var_used_checker(current, sink_func, sink_line)
                    if used:
                        is_sanitized = self._is_sanitized_at_line(
                            var_name, sink_line, sanitized_vars
                        )
                        confidence = self._calculate_confidence(
                            tainted.source, len(path), is_sanitized
                        )
                        results.append(
                            SinkReach(
                                tainted_var=var_name,
                                sink_function=sink_func,
                                sink_type=sink_type,
                                line=sink_line,
                                is_sanitized=is_sanitized,
                                flow_path=path.copy(),
                                source=tainted.source,
                                confidence=confidence,
                            )
                        )

                if current in flow_graph:
                    for next_var, edge_line in flow_graph[current]:
                        if next_var not in visited:
                            queue.append((next_var, path + [next_var], edge_line))

        return results

    @staticmethod
    def _is_sanitized_at_line(
        var_name: str,
        line: int,
        sanitized_vars: Dict[str, Tuple[SanitizationType, int, Optional[int]]],
    ) -> bool:
        """Check if variable is sanitized at a given line."""
        if var_name not in sanitized_vars:
            return False

        san_type, san_line, scope_end = sanitized_vars[var_name]

        if san_line > line:
            return False

        if scope_end is not None and line > scope_end:
            return False

        return True

    @staticmethod
    def _calculate_confidence(
        source: TaintSource, path_length: int, is_sanitized: bool
    ) -> float:
        """Calculate confidence score for the finding."""
        base_confidence = {
            TaintSource.FUNCTION_PARAM: 0.90,
            TaintSource.USER_INPUT: 0.95,
            TaintSource.ENV_VAR: 0.70,
            TaintSource.NETWORK: 0.85,
            TaintSource.FILE_READ: 0.75,
            TaintSource.LLM_OUTPUT: 0.90,
            TaintSource.DERIVED: 0.85,
            TaintSource.UNKNOWN: 0.50,
            TaintSource.HARDCODED: 0.10,
        }.get(source, 0.50)

        path_penalty = max(0, (path_length - 1) * 0.05)
        confidence = base_confidence - path_penalty

        if is_sanitized:
            confidence *= 0.20

        return max(0.10, min(0.99, confidence))
