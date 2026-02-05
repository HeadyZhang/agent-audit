"""
Tree-sitter based parser for multi-language code analysis.

Provides unified interface for parsing Python, TypeScript, and JavaScript
with semantic extraction of assignments, function calls, and string literals.

Falls back to regex-based parsing if tree-sitter is not available.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Sequence, Tuple

logger = logging.getLogger(__name__)


class TreeSitterError(Exception):
    """Error raised when tree-sitter parsing fails."""
    pass


class ValueType(Enum):
    """Classification of assignment value types."""
    LITERAL_STRING = "literal_string"
    FUNCTION_CALL = "function_call"
    VARIABLE_REF = "variable_ref"
    ENV_READ = "env_read"
    TYPE_DEFINITION = "type_definition"
    NONE_NULL = "none_null"
    NUMERIC = "numeric"
    BOOLEAN = "boolean"
    LIST = "list"
    DICT = "dict"
    OTHER = "other"


@dataclass
class Assignment:
    """Represents a variable assignment in source code."""
    name: str
    value: str
    value_type: ValueType
    line: int
    column: int
    end_line: int
    end_column: int
    raw_text: str  # Original source text


@dataclass
class FunctionCall:
    """Represents a function call in source code."""
    name: str  # Full qualified name (e.g., os.getenv, subprocess.run)
    args: List[str]  # Positional arguments as strings
    kwargs: Dict[str, str]  # Keyword arguments
    line: int
    column: int
    end_line: int
    end_column: int
    raw_text: str


@dataclass
class StringLiteral:
    """Represents a string literal in source code."""
    value: str  # The string content (without quotes)
    raw_value: str  # Original with quotes
    is_fstring: bool
    is_multiline: bool
    line: int
    column: int
    end_line: int
    end_column: int


# Try to import tree-sitter; gracefully degrade if not available
_TREE_SITTER_AVAILABLE = False
_tree_sitter_python: Any = None
_tree_sitter_javascript: Any = None
_tree_sitter_typescript: Any = None

try:
    import tree_sitter
    _TREE_SITTER_AVAILABLE = True
    logger.debug("tree-sitter core library available")

    try:
        import tree_sitter_python as _ts_python_mod
        _tree_sitter_python = _ts_python_mod
        logger.debug("tree-sitter-python available")
    except ImportError:
        logger.debug("tree-sitter-python not installed")

    try:
        import tree_sitter_javascript as _ts_js_mod
        _tree_sitter_javascript = _ts_js_mod
        logger.debug("tree-sitter-javascript available")
    except ImportError:
        logger.debug("tree-sitter-javascript not installed")

    try:
        import tree_sitter_typescript as _ts_ts_mod
        _tree_sitter_typescript = _ts_ts_mod
        logger.debug("tree-sitter-typescript available")
    except ImportError:
        logger.debug("tree-sitter-typescript not installed")

except ImportError:
    logger.debug("tree-sitter not installed, using regex fallback")


class TreeSitterParser:
    """
    Multi-language parser using tree-sitter with regex fallback.

    Provides semantic extraction of:
    - Variable assignments with value type classification
    - Function calls with argument extraction
    - String literals with f-string detection
    """

    # Language file extensions
    LANGUAGE_EXTENSIONS: Dict[str, str] = {
        '.py': 'python',
        '.pyw': 'python',
        '.js': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
    }

    # Environment variable read patterns
    ENV_READ_PATTERNS = [
        r'os\.environ\s*\[',
        r'os\.environ\.get\s*\(',
        r'os\.getenv\s*\(',
        r'getenv\s*\(',
        r'process\.env\.',
        r'Deno\.env\.get\s*\(',
    ]

    def __init__(self, source: str, language: Optional[str] = None, file_path: Optional[str] = None):
        """
        Initialize parser with source code.

        Args:
            source: Source code to parse
            language: Language name ('python', 'javascript', 'typescript')
                     If None, will be inferred from file_path
            file_path: Optional file path for language detection
        """
        self.source = source
        self.file_path = file_path
        self._tree = None
        self._use_tree_sitter = False

        # Detect language
        if language is None and file_path:
            ext = Path(file_path).suffix.lower()
            language = self.LANGUAGE_EXTENSIONS.get(ext, 'python')
        self.language = language or 'python'

        # Try to initialize tree-sitter
        self._init_tree_sitter()

    def _init_tree_sitter(self) -> None:
        """Initialize tree-sitter parser if available."""
        if not _TREE_SITTER_AVAILABLE:
            return

        try:
            parser_module = None
            if self.language == 'python' and _tree_sitter_python:
                parser_module = _tree_sitter_python
            elif self.language == 'javascript' and _tree_sitter_javascript:
                parser_module = _tree_sitter_javascript
            elif self.language == 'typescript' and _tree_sitter_typescript:
                parser_module = _tree_sitter_typescript

            if parser_module is None:
                return

            # tree-sitter-python 0.23+ uses LANGUAGE attribute
            if hasattr(parser_module, 'LANGUAGE'):
                lang = parser_module.LANGUAGE
            elif hasattr(parser_module, 'language'):
                lang = parser_module.language()
            else:
                return

            parser = tree_sitter.Parser(lang)
            self._tree = parser.parse(self.source.encode('utf-8'))
            self._use_tree_sitter = True
            logger.debug(f"Using tree-sitter for {self.language}")

        except Exception as e:
            logger.debug(f"tree-sitter init failed: {e}, using regex fallback")
            self._use_tree_sitter = False

    @property
    def is_tree_sitter_available(self) -> bool:
        """Check if tree-sitter parsing is active."""
        return self._use_tree_sitter

    def find_assignments(self) -> List[Assignment]:
        """
        Find all variable assignments in source code.

        Returns:
            List of Assignment objects with value type classification
        """
        if self._use_tree_sitter:
            return self._find_assignments_tree_sitter()
        return self._find_assignments_regex()

    def find_function_calls(self) -> List[FunctionCall]:
        """
        Find all function calls in source code.

        Returns:
            List of FunctionCall objects
        """
        if self._use_tree_sitter:
            return self._find_function_calls_tree_sitter()
        return self._find_function_calls_regex()

    def find_string_literals(self) -> List[StringLiteral]:
        """
        Find all string literals in source code.

        Returns:
            List of StringLiteral objects with f-string detection
        """
        if self._use_tree_sitter:
            return self._find_string_literals_tree_sitter()
        return self._find_string_literals_regex()

    # =========================================================================
    # Tree-sitter implementations
    # =========================================================================

    def _find_assignments_tree_sitter(self) -> List[Assignment]:
        """Find assignments using tree-sitter."""
        assignments: List[Assignment] = []
        if not self._tree:
            return assignments

        root = self._tree.root_node

        # Query patterns vary by language
        if self.language == 'python':
            self._walk_python_assignments(root, assignments)
        else:
            self._walk_js_assignments(root, assignments)

        return assignments

    def _walk_python_assignments(self, node: Any, assignments: List[Assignment]) -> None:
        """Walk Python AST for assignments."""
        if node.type == 'assignment':
            # Get left side (variable name)
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')

            if left and right:
                name = self._node_text(left)
                value = self._node_text(right)
                value_type = self._classify_value_type(right)

                assignments.append(Assignment(
                    name=name,
                    value=value,
                    value_type=value_type,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    raw_text=self._node_text(node),
                ))

        # Recurse to children
        for child in node.children:
            self._walk_python_assignments(child, assignments)

    def _walk_js_assignments(self, node: Any, assignments: List[Assignment]) -> None:
        """Walk JS/TS AST for assignments."""
        if node.type in ('variable_declarator', 'assignment_expression'):
            # Get name and value
            name_node = node.child_by_field_name('name') or node.child_by_field_name('left')
            value_node = node.child_by_field_name('value') or node.child_by_field_name('right')

            if name_node and value_node:
                name = self._node_text(name_node)
                value = self._node_text(value_node)
                value_type = self._classify_value_type(value_node)

                assignments.append(Assignment(
                    name=name,
                    value=value,
                    value_type=value_type,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    raw_text=self._node_text(node),
                ))

        for child in node.children:
            self._walk_js_assignments(child, assignments)

    def _classify_value_type(self, node: Any) -> ValueType:
        """Classify the type of an assignment value node."""
        node_type = node.type
        text = self._node_text(node)

        # Check for None/null
        if node_type in ('none', 'null'):
            return ValueType.NONE_NULL

        # Check for string literals
        if node_type in ('string', 'concatenated_string'):
            return ValueType.LITERAL_STRING

        # Check for f-strings
        if node_type == 'formatted_string':
            return ValueType.LITERAL_STRING

        # Check for template strings (JS)
        if node_type == 'template_string':
            return ValueType.LITERAL_STRING

        # Check for numbers
        if node_type in ('integer', 'float', 'number'):
            return ValueType.NUMERIC

        # Check for booleans
        if node_type in ('true', 'false') or text.lower() in ('true', 'false'):
            return ValueType.BOOLEAN

        # Check for function calls
        if node_type in ('call', 'call_expression'):
            # Check if it's an env read
            if self._is_env_read(text):
                return ValueType.ENV_READ
            return ValueType.FUNCTION_CALL

        # Check for identifiers (variable references)
        if node_type in ('identifier', 'name'):
            return ValueType.VARIABLE_REF

        # Check for lists/arrays
        if node_type in ('list', 'array', 'list_comprehension'):
            return ValueType.LIST

        # Check for dicts/objects
        if node_type in ('dictionary', 'object', 'dict_comprehension'):
            return ValueType.DICT

        # Check for type annotations
        if node_type in ('type', 'subscript', 'generic_type'):
            return ValueType.TYPE_DEFINITION

        # Check for member expressions that look like env reads
        if node_type in ('attribute', 'member_expression', 'subscript'):
            if self._is_env_read(text):
                return ValueType.ENV_READ

        return ValueType.OTHER

    def _is_env_read(self, text: str) -> bool:
        """Check if text represents an environment variable read."""
        for pattern in self.ENV_READ_PATTERNS:
            if re.search(pattern, text):
                return True
        return False

    def _find_function_calls_tree_sitter(self) -> List[FunctionCall]:
        """Find function calls using tree-sitter."""
        calls: List[FunctionCall] = []
        if not self._tree:
            return calls

        root = self._tree.root_node

        if self.language == 'python':
            self._walk_python_calls(root, calls)
        else:
            self._walk_js_calls(root, calls)

        return calls

    def _walk_python_calls(self, node: Any, calls: List[FunctionCall]) -> None:
        """Walk Python AST for function calls."""
        if node.type == 'call':
            func_node = node.child_by_field_name('function')
            args_node = node.child_by_field_name('arguments')

            if func_node:
                name = self._node_text(func_node)
                args: List[str] = []
                kwargs: Dict[str, str] = {}

                if args_node:
                    for arg in args_node.children:
                        if arg.type == 'argument_list':
                            continue
                        if arg.type == 'keyword_argument':
                            key_node = arg.child_by_field_name('name')
                            val_node = arg.child_by_field_name('value')
                            if key_node and val_node:
                                kwargs[self._node_text(key_node)] = self._node_text(val_node)
                        elif arg.type not in ('(', ')', ','):
                            args.append(self._node_text(arg))

                calls.append(FunctionCall(
                    name=name,
                    args=args,
                    kwargs=kwargs,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    raw_text=self._node_text(node),
                ))

        for child in node.children:
            self._walk_python_calls(child, calls)

    def _walk_js_calls(self, node: Any, calls: List[FunctionCall]) -> None:
        """Walk JS/TS AST for function calls."""
        if node.type == 'call_expression':
            func_node = node.child_by_field_name('function')
            args_node = node.child_by_field_name('arguments')

            if func_node:
                name = self._node_text(func_node)
                args: List[str] = []
                kwargs: Dict[str, str] = {}  # JS doesn't have kwargs, but we keep interface consistent

                if args_node:
                    for arg in args_node.children:
                        if arg.type not in ('(', ')', ',', 'arguments'):
                            args.append(self._node_text(arg))

                calls.append(FunctionCall(
                    name=name,
                    args=args,
                    kwargs=kwargs,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_column=node.end_point[1],
                    raw_text=self._node_text(node),
                ))

        for child in node.children:
            self._walk_js_calls(child, calls)

    def _find_string_literals_tree_sitter(self) -> List[StringLiteral]:
        """Find string literals using tree-sitter."""
        literals: List[StringLiteral] = []
        if not self._tree:
            return literals

        root = self._tree.root_node

        if self.language == 'python':
            self._walk_python_strings(root, literals)
        else:
            self._walk_js_strings(root, literals)

        return literals

    def _walk_python_strings(self, node: Any, literals: List[StringLiteral]) -> None:
        """Walk Python AST for string literals."""
        if node.type == 'string':
            raw = self._node_text(node)
            value = self._extract_string_value(raw)
            is_multiline = raw.startswith('"""') or raw.startswith("'''")

            literals.append(StringLiteral(
                value=value,
                raw_value=raw,
                is_fstring=False,
                is_multiline=is_multiline,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
            ))
        elif node.type == 'formatted_string':
            raw = self._node_text(node)
            value = self._extract_string_value(raw)

            literals.append(StringLiteral(
                value=value,
                raw_value=raw,
                is_fstring=True,
                is_multiline='"""' in raw or "'''" in raw,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
            ))

        for child in node.children:
            self._walk_python_strings(child, literals)

    def _walk_js_strings(self, node: Any, literals: List[StringLiteral]) -> None:
        """Walk JS/TS AST for string literals."""
        if node.type == 'string':
            raw = self._node_text(node)
            value = self._extract_string_value(raw)

            literals.append(StringLiteral(
                value=value,
                raw_value=raw,
                is_fstring=False,
                is_multiline=False,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
            ))
        elif node.type == 'template_string':
            raw = self._node_text(node)
            value = raw.strip('`')
            has_interpolation = '${' in raw

            literals.append(StringLiteral(
                value=value,
                raw_value=raw,
                is_fstring=has_interpolation,
                is_multiline='\n' in raw,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1],
            ))

        for child in node.children:
            self._walk_js_strings(child, literals)

    def _node_text(self, node: Any) -> str:
        """Extract text content of a tree-sitter node."""
        return self.source[node.start_byte:node.end_byte]

    def _extract_string_value(self, raw: str) -> str:
        """Extract string value without quotes."""
        # Handle triple quotes
        if raw.startswith('"""') or raw.startswith("'''"):
            return raw[3:-3]
        if raw.startswith('f"""') or raw.startswith("f'''"):
            return raw[4:-3]

        # Handle single/double quotes with prefixes
        prefixes = ('f', 'r', 'b', 'fr', 'rf', 'br', 'rb')
        for prefix in prefixes:
            if raw.lower().startswith(prefix + '"'):
                return raw[len(prefix)+1:-1]
            if raw.lower().startswith(prefix + "'"):
                return raw[len(prefix)+1:-1]

        # Simple quotes
        if raw.startswith('"') or raw.startswith("'"):
            return raw[1:-1]
        if raw.startswith('`'):
            return raw[1:-1]

        return raw

    # =========================================================================
    # Regex fallback implementations
    # =========================================================================

    def _find_assignments_regex(self) -> List[Assignment]:
        """Find assignments using regex (fallback)."""
        assignments: List[Assignment] = []
        lines = self.source.split('\n')

        # Python assignment pattern
        py_pattern = re.compile(
            r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)(?:#.*)?$'
        )

        # JS/TS patterns
        js_const_pattern = re.compile(
            r'^(\s*)(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+?)(?://.*)?;?$'
        )

        for i, line in enumerate(lines):
            line_num = i + 1

            if self.language == 'python':
                match = py_pattern.match(line)
            else:
                match = js_const_pattern.match(line)

            if match:
                indent = match.group(1)
                name = match.group(2)
                value = match.group(3).strip().rstrip(';')
                value_type = self._classify_value_regex(value)

                assignments.append(Assignment(
                    name=name,
                    value=value,
                    value_type=value_type,
                    line=line_num,
                    column=len(indent),
                    end_line=line_num,
                    end_column=len(line),
                    raw_text=line.strip(),
                ))

        return assignments

    def _classify_value_regex(self, value: str) -> ValueType:
        """Classify value type using regex patterns."""
        value = value.strip()

        # None/null
        if value in ('None', 'null', 'undefined'):
            return ValueType.NONE_NULL

        # Boolean
        if value.lower() in ('true', 'false'):
            return ValueType.BOOLEAN

        # Numeric
        if re.match(r'^-?\d+\.?\d*$', value):
            return ValueType.NUMERIC

        # String literals
        if value.startswith(('"""', "'''", '"', "'", 'f"', "f'", 'r"', "r'")):
            return ValueType.LITERAL_STRING
        if value.startswith('`'):  # JS template
            return ValueType.LITERAL_STRING

        # List/Array
        if value.startswith('['):
            return ValueType.LIST

        # Dict/Object
        if value.startswith('{'):
            return ValueType.DICT

        # Env reads
        if self._is_env_read(value):
            return ValueType.ENV_READ

        # Function call
        if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', value):
            return ValueType.FUNCTION_CALL

        # Variable reference (identifier)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', value):
            return ValueType.VARIABLE_REF

        return ValueType.OTHER

    def _find_function_calls_regex(self) -> List[FunctionCall]:
        """Find function calls using regex (fallback)."""
        calls: List[FunctionCall] = []
        lines = self.source.split('\n')

        # Pattern to find function calls
        call_pattern = re.compile(
            r'([a-zA-Z_][a-zA-Z0-9_.]*)\s*\(([^)]*)\)'
        )

        for i, line in enumerate(lines):
            line_num = i + 1

            for match in call_pattern.finditer(line):
                name = match.group(1)
                args_str = match.group(2)

                args, kwargs = self._parse_args_regex(args_str)

                calls.append(FunctionCall(
                    name=name,
                    args=args,
                    kwargs=kwargs,
                    line=line_num,
                    column=match.start(),
                    end_line=line_num,
                    end_column=match.end(),
                    raw_text=match.group(0),
                ))

        return calls

    def _parse_args_regex(self, args_str: str) -> Tuple[List[str], Dict[str, str]]:
        """Parse function arguments from string."""
        args: List[str] = []
        kwargs: Dict[str, str] = {}

        if not args_str.strip():
            return args, kwargs

        # Simple split by comma (doesn't handle nested calls well)
        parts = args_str.split(',')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Check for keyword argument
            if '=' in part and not part.startswith(('==', '!=')):
                # Find first = that's not == or !=
                eq_idx = -1
                for j, c in enumerate(part):
                    if c == '=' and j > 0 and part[j-1] not in ('=', '!', '<', '>'):
                        if j + 1 < len(part) and part[j+1] != '=':
                            eq_idx = j
                            break
                        elif j + 1 >= len(part):
                            eq_idx = j
                            break

                if eq_idx > 0:
                    key = part[:eq_idx].strip()
                    val = part[eq_idx+1:].strip()
                    if key.isidentifier():
                        kwargs[key] = val
                        continue

            args.append(part)

        return args, kwargs

    def _find_string_literals_regex(self) -> List[StringLiteral]:
        """Find string literals using regex (fallback)."""
        literals: List[StringLiteral] = []
        lines = self.source.split('\n')

        # Patterns for different string types
        patterns = [
            # Triple-quoted strings
            (re.compile(r'(f?r?)(""")(.*?)(""")'), True),
            (re.compile(r"(f?r?)(''')(.*?)(''')"), True),
            # Double-quoted strings
            (re.compile(r'''(f?r?)(")([^"\\]*(?:\\.[^"\\]*)*)(")'''), False),
            # Single-quoted strings
            (re.compile(r"(f?r?)(')([^'\\]*(?:\\.[^'\\]*)*)(')" ), False),
            # JS template literals
            (re.compile(r'(`)(.*?)(`)', re.DOTALL), False),
        ]

        for i, line in enumerate(lines):
            line_num = i + 1

            for pattern, is_multiline in patterns:
                for match in pattern.finditer(line):
                    groups = match.groups()
                    if len(groups) == 4:
                        prefix, open_q, content, close_q = groups
                        raw_value = prefix + open_q + content + close_q
                        is_fstring = 'f' in prefix.lower() if prefix else False
                    else:
                        open_q, content, close_q = groups
                        raw_value = open_q + content + close_q
                        is_fstring = '${' in content if open_q == '`' else False

                    literals.append(StringLiteral(
                        value=content,
                        raw_value=raw_value,
                        is_fstring=is_fstring,
                        is_multiline=is_multiline,
                        line=line_num,
                        column=match.start(),
                        end_line=line_num,
                        end_column=match.end(),
                    ))

        return literals


# Convenience functions
def parse_python(source: str, file_path: Optional[str] = None) -> TreeSitterParser:
    """Create a Python parser instance."""
    return TreeSitterParser(source, language='python', file_path=file_path)


def parse_javascript(source: str, file_path: Optional[str] = None) -> TreeSitterParser:
    """Create a JavaScript parser instance."""
    return TreeSitterParser(source, language='javascript', file_path=file_path)


def parse_typescript(source: str, file_path: Optional[str] = None) -> TreeSitterParser:
    """Create a TypeScript parser instance."""
    return TreeSitterParser(source, language='typescript', file_path=file_path)
