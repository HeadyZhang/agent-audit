"""Memory operation context analyzer for AGENT-018 false positive suppression.

v0.11.0: Correct approach - use method whitelist gate, not variable name patterns.
Only known Agent memory methods (add_message, add_texts, etc.) should trigger AGENT-018.
Python's set.add(), list.append() are NOT in the whitelist.
"""

import ast
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

import yaml

logger = logging.getLogger(__name__)


class OperationType(str, Enum):
    """Type of memory operation."""
    READ = "read"
    WRITE = "write"
    CLEAR = "clear"
    UNKNOWN = "unknown"


class DataSource(str, Enum):
    """Source of data being written to memory."""
    USER_INPUT = "user_input"
    LLM_OUTPUT = "llm_output"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


@dataclass
class MemoryOpContext:
    """
    Context analysis result for a memory operation.

    Used to determine severity and confidence for AGENT-018 findings.
    """
    operation_type: OperationType = OperationType.UNKNOWN
    data_source: DataSource = DataSource.UNKNOWN
    has_sanitization: bool = False
    framework_detected: Optional[str] = None
    is_framework_standard: bool = False
    confidence: float = 0.5
    analysis_notes: List[str] = field(default_factory=list)


class MemoryContextAnalyzer:
    """
    Analyzes memory operations for context-aware security assessment.

    Provides three levels of analysis:
    1. Framework allowlist matching
    2. Data source tracking (user input vs LLM output vs internal)
    3. Sanitization detection
    """

    # User input source patterns
    USER_INPUT_SOURCES: Set[str] = {
        'input', 'raw_input',  # Built-in
        'request.json', 'request.args', 'request.form', 'request.data',  # Flask/Django
        'sys.argv', 'argparse',  # CLI
        'getenv', 'os.environ',  # Environment (potentially user-controlled)
        'stdin', 'sys.stdin',  # Standard input
        'websocket.recv', 'socket.recv',  # Network input
    }

    # LLM output patterns (function names that typically return LLM responses)
    LLM_OUTPUT_PATTERNS: Set[str] = {
        'invoke', 'ainvoke', 'generate', 'agenerate',
        'chat', 'complete', 'completion', 'acomplete',
        'call', 'acall', 'run', 'arun',
        'create', 'chat_completion', 'chat.completions.create',
        'send_message', 'ask', 'query',
    }

    # Write operation patterns
    WRITE_OPERATIONS: Set[str] = {
        'append', 'add', 'save', 'store', 'put', 'set', 'update',
        'insert', 'upsert', 'persist', 'write', 'push',
        'add_message', 'add_messages', 'save_context', 'add_memory',
        'add_documents', 'add_texts',
    }

    # Read operation patterns
    READ_OPERATIONS: Set[str] = {
        'get', 'load', 'read', 'fetch', 'retrieve', 'query', 'search',
        'load_memory_variables', 'get_messages', 'get_memory',
    }

    # Clear operation patterns
    CLEAR_OPERATIONS: Set[str] = {
        'clear', 'reset', 'delete', 'remove', 'truncate', 'purge',
    }

    # Sanitization function patterns
    SANITIZATION_PATTERNS: Set[str] = {
        'sanitize', 'validate', 'clean', 'escape', 'filter',
        'isinstance', 'type', 'hasattr',
        're.match', 're.search', 're.fullmatch', 're.sub',
        'strip', 'replace',
        'html.escape', 'quote', 'urlencode',
        'json.loads',  # Schema validation via parsing
    }

    def __init__(self, allowlist_path: Optional[Path] = None):
        """
        Initialize the context analyzer.

        Args:
            allowlist_path: Path to framework allowlist YAML file.
                          If None, uses default location.
        """
        self.allowlist: Dict[str, Any] = {}
        self._load_allowlist(allowlist_path)

    def _load_allowlist(self, allowlist_path: Optional[Path] = None) -> None:
        """Load framework allowlist from YAML file."""
        if allowlist_path is None:
            # Default location relative to rules directory
            default_path = Path(__file__).parent.parent.parent.parent.parent / \
                          "rules" / "allowlists" / "framework_memory.yaml"
            if default_path.exists():
                allowlist_path = default_path

        if allowlist_path and allowlist_path.exists():
            try:
                with open(allowlist_path, 'r', encoding='utf-8') as f:
                    self.allowlist = yaml.safe_load(f) or {}
                logger.debug(f"Loaded memory allowlist from {allowlist_path}")
            except Exception as e:
                logger.warning(f"Failed to load allowlist: {e}")
                self.allowlist = {}

    def analyze(
        self,
        node: ast.AST,
        source_code: str,
        file_imports: List[str],
    ) -> MemoryOpContext:
        """
        Analyze a memory operation AST node.

        v0.11.0: This is called AFTER the method whitelist gate.
        Only known Agent memory methods reach this point.

        Args:
            node: AST node representing the memory operation
            source_code: Full source code of the file
            file_imports: List of imports in the file

        Returns:
            MemoryOpContext with analysis results
        """
        ctx = MemoryOpContext()

        # Step 1: Detect framework
        ctx.framework_detected = self._detect_framework(file_imports)

        # Step 2: Check allowlist
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                ctx.is_framework_standard = self._check_allowlist(
                    func_name, file_imports, ctx.framework_detected
                )
                if ctx.is_framework_standard:
                    ctx.analysis_notes.append(
                        f"Matched framework allowlist: {ctx.framework_detected}"
                    )

        # Step 3: Determine operation type
        ctx.operation_type = self._determine_operation_type(node)

        # Step 4: Track data source (for write operations)
        if ctx.operation_type == OperationType.WRITE:
            ctx.data_source = self._trace_data_source(node, source_code)

        # Step 5: Check for sanitization
        ctx.has_sanitization = self._check_sanitization(node, source_code)

        # Step 6: Calculate confidence
        ctx.confidence = self._calculate_confidence(ctx)

        return ctx

    def _detect_framework(self, imports: List[str]) -> Optional[str]:
        """Detect which agent framework is being used based on imports."""
        import_str = ' '.join(imports).lower()

        if 'langchain' in import_str:
            return 'langchain'
        elif 'crewai' in import_str:
            return 'crewai'
        elif 'autogen' in import_str:
            return 'autogen'
        elif 'google.adk' in import_str or 'google.generativeai' in import_str:
            return 'google_adk'
        elif 'agentscope' in import_str:
            return 'agentscope'
        elif 'llama_index' in import_str:
            return 'llama_index'
        elif 'semantic_kernel' in import_str:
            return 'semantic_kernel'
        elif 'haystack' in import_str:
            return 'haystack'

        return None

    def _check_allowlist(
        self,
        func_name: str,
        imports: List[str],
        framework: Optional[str]
    ) -> bool:
        """Check if function matches framework allowlist."""
        if not self.allowlist:
            return False

        # Extract simple function/method name
        simple_name = func_name.split('.')[-1]

        # Check each framework in allowlist
        for fw_name, fw_config in self.allowlist.items():
            if not isinstance(fw_config, dict):
                continue

            # Check module imports
            modules = fw_config.get('modules', [])
            for module in modules:
                if any(module in imp for imp in imports):
                    # Module match - check if function is from this module
                    classes = fw_config.get('classes', [])
                    methods = fw_config.get('methods', [])

                    # Check class match
                    for cls in classes:
                        if cls in func_name or cls == simple_name:
                            return True

                    # Check method match
                    for method in methods:
                        method_simple = method.split('.')[-1]
                        if method_simple == simple_name:
                            return True

        return False

    def _determine_operation_type(self, node: ast.AST) -> OperationType:
        """Determine if this is a read, write, or clear operation."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                simple_name = func_name.split('.')[-1].lower()

                if any(op in simple_name for op in self.WRITE_OPERATIONS):
                    return OperationType.WRITE
                elif any(op in simple_name for op in self.READ_OPERATIONS):
                    return OperationType.READ
                elif any(op in simple_name for op in self.CLEAR_OPERATIONS):
                    return OperationType.CLEAR

        elif isinstance(node, ast.Assign):
            # Direct assignment to memory-like variable
            return OperationType.WRITE

        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            # dict/list subscript assignment
            return OperationType.WRITE

        return OperationType.UNKNOWN

    def _trace_data_source(self, node: ast.AST, source_code: str) -> DataSource:
        """
        Trace the source of data being written to memory.

        Uses a simplified 3-level backward trace through the AST.
        """
        if not isinstance(node, ast.Call):
            return DataSource.UNKNOWN

        # Check arguments for data source
        for arg in node.args:
            source = self._check_arg_source(arg)
            if source != DataSource.UNKNOWN:
                return source

        for kw in node.keywords:
            if kw.arg in ('content', 'text', 'message', 'data', 'value', 'input'):
                source = self._check_arg_source(kw.value)
                if source != DataSource.UNKNOWN:
                    return source

        return DataSource.UNKNOWN

    def _check_arg_source(self, node: ast.expr) -> DataSource:
        """Check the source of an argument expression."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                # Check for user input functions
                if any(src in func_name for src in self.USER_INPUT_SOURCES):
                    return DataSource.USER_INPUT

                # Check for LLM output patterns
                simple_name = func_name.split('.')[-1]
                if simple_name in self.LLM_OUTPUT_PATTERNS:
                    return DataSource.LLM_OUTPUT

                # Recursive check on nested calls
                for arg in node.args:
                    source = self._check_arg_source(arg)
                    if source != DataSource.UNKNOWN:
                        return source

        elif isinstance(node, ast.Name):
            # Check variable name patterns
            name_lower = node.id.lower()
            if any(pattern in name_lower for pattern in [
                'user', 'input', 'request', 'query', 'prompt'
            ]):
                return DataSource.USER_INPUT
            if any(pattern in name_lower for pattern in [
                'response', 'output', 'result', 'completion', 'answer'
            ]):
                return DataSource.LLM_OUTPUT

        elif isinstance(node, ast.Subscript):
            # Check base for patterns like request['data']
            if isinstance(node.value, ast.Name):
                if node.value.id.lower() in ('request', 'form', 'args', 'params'):
                    return DataSource.USER_INPUT

        elif isinstance(node, ast.Attribute):
            # Check for patterns like request.json
            attr_chain = self._get_attr_chain(node)
            attr_str = '.'.join(attr_chain)
            if any(src in attr_str for src in self.USER_INPUT_SOURCES):
                return DataSource.USER_INPUT

        elif isinstance(node, ast.Constant):
            # Literal value = internal
            return DataSource.INTERNAL

        return DataSource.UNKNOWN

    def _check_sanitization(self, node: ast.AST, source_code: str) -> bool:
        """
        Check if the operation includes sanitization.

        Looks for sanitization function calls in the same statement
        or in the preceding lines.
        """
        if not isinstance(node, ast.Call):
            return False

        # Check if any argument is wrapped in a sanitization call
        for arg in node.args:
            if self._is_sanitized_arg(arg):
                return True

        for kw in node.keywords:
            if self._is_sanitized_arg(kw.value):
                return True

        # Check for sanitization patterns in the source line
        if hasattr(node, 'lineno'):
            lines = source_code.splitlines()
            if 0 < node.lineno <= len(lines):
                line = lines[node.lineno - 1].lower()
                if any(san in line for san in [
                    'sanitize', 'validate', 'clean', 'escape', 'filter'
                ]):
                    return True

        return False

    def _is_sanitized_arg(self, node: ast.expr) -> bool:
        """Check if an argument is wrapped in a sanitization call."""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                simple_name = func_name.split('.')[-1].lower()
                return any(
                    san in simple_name
                    for san in self.SANITIZATION_PATTERNS
                )
        return False

    def _calculate_confidence(self, ctx: MemoryOpContext) -> float:
        """
        Calculate confidence score based on context analysis.

        Higher confidence = more likely to be a real vulnerability.
        """
        if ctx.is_framework_standard:
            return 0.15  # Low confidence for standard framework operations

        if ctx.operation_type == OperationType.READ:
            return 0.20  # Read operations are less risky

        if ctx.operation_type == OperationType.CLEAR:
            return 0.25  # Clear operations are also less risky

        # Write operations - calculate based on data source and sanitization
        if ctx.data_source == DataSource.USER_INPUT:
            if ctx.has_sanitization:
                return 0.35  # User input but sanitized
            else:
                return 0.95  # User input without sanitization - high risk

        elif ctx.data_source == DataSource.LLM_OUTPUT:
            if ctx.has_sanitization:
                return 0.40
            else:
                return 0.80  # LLM output can be manipulated via injection

        elif ctx.data_source == DataSource.INTERNAL:
            return 0.30  # Internal data is lower risk

        else:  # UNKNOWN
            if ctx.has_sanitization:
                return 0.35
            else:
                return 0.50  # Unknown source - medium confidence

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the full name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = self._get_attr_chain(node.func)
            return '.'.join(parts)
        return None

    def _get_attr_chain(self, node: ast.Attribute) -> List[str]:
        """Get the chain of attributes for an Attribute node."""
        parts: List[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return parts
