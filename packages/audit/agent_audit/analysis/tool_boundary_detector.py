"""
Tool Boundary Detection for AGENT-034.

v0.11.0: Core principle - Only flag issues WITHIN Agent Tool entry points.
No blacklists - just tight entry point identification.

v0.12.0: Expanded detection for OpenAI function calling pattern.
- Functions passed to tools=[...] parameter are Tool entry points
- @function_schema, @openai_function decorators are Tool entry points

This is the GATE for AGENT-034:
- If is_tool_entry_point() returns False, skip ALL further checks
- No need for SAFE_BUILTIN_CALLS blacklist

Key insight: asyncio.run() in a regular function doesn't need AGENT-034.
Only asyncio.run() called with untrusted input inside a @tool function needs checking.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional, Set


# Agent Tool entry point decorators
TOOL_DECORATORS: Set[str] = {
    # LangChain
    'tool',
    # LlamaIndex
    'function_tool',
    # Semantic Kernel
    'kernel_function',
    # CrewAI (uses @tool from langchain)
    # OpenAI Agents SDK
    'function',
}

# v0.12.0: Function Calling decorators (OpenAI/Anthropic patterns)
FUNCTION_CALLING_DECORATORS: Set[str] = {
    'function_schema',
    'openai_function',
    'tool_function',
    'function_def',
    'tool_def',
}

# Methods that indicate Tool class implementation
TOOL_CLASS_METHODS: Set[str] = {
    '_run',      # BaseTool._run()
    '_arun',     # BaseTool._arun()
    'run',       # Direct run method
    'arun',      # Async run
    'invoke',    # RunnableLambda.invoke()
    'ainvoke',   # Async invoke
}

# Base classes that indicate Tool implementation
TOOL_BASE_CLASSES: Set[str] = {
    'BaseTool',
    'Tool',
    'StructuredTool',
    'FunctionTool',
    'QueryEngineTool',
    'RunnableLambda',
    'RunnableSequence',
}

# v0.12.0: Function Calling API patterns (OpenAI/Anthropic)
FUNCTION_CALLING_API_PATTERNS: Set[str] = {
    'chat.completions.create',
    'ChatCompletion.create',
    'completions.create',
    'messages.create',  # Anthropic
}


@dataclass
class ToolBoundaryResult:
    """Result of tool boundary analysis."""
    is_tool_entry: bool
    reason: str
    confidence: float
    tool_type: Optional[str] = None  # 'decorator', 'class_method', 'name_heuristic', 'openai_function'


@dataclass
class FileToolContext:
    """v0.12.0: File-level Tool context for OpenAI function calling detection."""
    has_openai_import: bool = False
    has_anthropic_import: bool = False
    has_function_calling_api: bool = False
    registered_tool_functions: Set[str] = field(default_factory=set)


def analyze_file_tool_context(
    tree: ast.AST,
    imports: Set[str],
) -> FileToolContext:
    """
    v0.12.0: Analyze file for OpenAI/Anthropic function calling patterns.

    Detects:
    - OpenAI/Anthropic imports
    - Function calling API calls (chat.completions.create, etc.)
    - Functions registered in tools=[...] parameter

    Args:
        tree: Parsed AST of the file
        imports: Set of import names from the file

    Returns:
        FileToolContext with detected patterns
    """
    ctx = FileToolContext()

    # Check OpenAI/Anthropic imports
    imports_str = ' '.join(imports).lower()
    ctx.has_openai_import = 'openai' in imports_str
    ctx.has_anthropic_import = 'anthropic' in imports_str

    # Walk AST to find function calling API calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if call_name and _is_function_calling_api(call_name):
                ctx.has_function_calling_api = True
                _extract_registered_tools(node, ctx)

    return ctx


def _is_function_calling_api(call_name: str) -> bool:
    """Check if call is a function calling API."""
    return any(pattern in call_name for pattern in FUNCTION_CALLING_API_PATTERNS)


def _extract_registered_tools(call_node: ast.Call, ctx: FileToolContext) -> None:
    """Extract tool function names from API call's tools/functions parameter."""
    for keyword in call_node.keywords:
        if keyword.arg in ('tools', 'functions'):
            _extract_tool_names_from_arg(keyword.value, ctx)


def _extract_tool_names_from_arg(node: ast.expr, ctx: FileToolContext) -> None:
    """Extract tool function names from argument value."""
    if isinstance(node, ast.List):
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                # tools=[func1, func2]
                ctx.registered_tool_functions.add(elt.id)
            elif isinstance(elt, ast.Dict):
                # tools=[{"name": "func1", ...}]
                _extract_from_dict(elt, ctx)
            elif isinstance(elt, ast.Call):
                # tools=[some_wrapper(func1)]
                for arg in elt.args:
                    if isinstance(arg, ast.Name):
                        ctx.registered_tool_functions.add(arg.id)


def _extract_from_dict(node: ast.Dict, ctx: FileToolContext) -> None:
    """Extract function name from dict definition."""
    for key, val in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == 'name':
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                ctx.registered_tool_functions.add(val.value)


def is_tool_entry_point(
    node: ast.FunctionDef,
    parent_class: Optional[str] = None,
    parent_bases: Optional[Set[str]] = None,
    file_context: Optional[FileToolContext] = None,
) -> ToolBoundaryResult:
    """
    Check if a function is an Agent Tool entry point.

    v0.12.0: Added file_context parameter for OpenAI function calling detection.

    This is the ONLY gate for AGENT-034. If this returns False,
    skip ALL further AGENT-034 checks. No blacklists needed.

    Args:
        node: AST FunctionDef node
        parent_class: Name of the containing class (if any)
        parent_bases: Set of base class names for parent class
        file_context: v0.12.0 - File-level tool context for function calling detection

    Returns:
        ToolBoundaryResult indicating if this is a Tool entry point
    """
    # Check 1: Has @tool decorator
    for decorator in node.decorator_list:
        dec_name = _get_decorator_name(decorator)
        if dec_name in TOOL_DECORATORS:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"@{dec_name} decorator",
                confidence=0.95,
                tool_type='decorator'
            )
        # v0.12.0: Check function calling decorators
        if dec_name in FUNCTION_CALLING_DECORATORS:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"@{dec_name} function calling decorator",
                confidence=0.90,
                tool_type='function_calling_decorator'
            )

    # Check 2: Is _run()/_arun() method in a Tool class
    if parent_class and parent_bases:
        if node.name in TOOL_CLASS_METHODS:
            if parent_bases & TOOL_BASE_CLASSES:
                return ToolBoundaryResult(
                    is_tool_entry=True,
                    reason=f"{parent_class}.{node.name}() in Tool class",
                    confidence=0.90,
                    tool_type='class_method'
                )

    # Check 3: Function name contains 'tool' (weak heuristic)
    # Only use if it also has str parameters - very weak signal
    if 'tool' in node.name.lower():
        has_str_param = _has_str_params(node)
        if has_str_param:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"Name heuristic: {node.name}",
                confidence=0.60,
                tool_type='name_heuristic'
            )

    # Check 4: v0.12.0 - OpenAI function calling pattern
    if file_context and file_context.has_function_calling_api:
        if node.name in file_context.registered_tool_functions:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"OpenAI function calling: {node.name}",
                confidence=0.85,
                tool_type='openai_function'
            )

    # NOT a Tool entry point - SKIP all AGENT-034 checks
    return ToolBoundaryResult(
        is_tool_entry=False,
        reason="Not a Tool entry point",
        confidence=0.0,
        tool_type=None
    )


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Extract full call name from Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current: ast.expr = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return '.'.join(parts)
    return None


def _get_decorator_name(node: ast.expr) -> str:
    """Extract decorator name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    elif isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _has_str_params(node: ast.FunctionDef) -> bool:
    """Check if function has str/Any type parameters."""
    for arg in node.args.args:
        if arg.arg in ('self', 'cls'):
            continue
        # Unannotated = Any
        if arg.annotation is None:
            return True
        # Check for str/Any annotation
        if isinstance(arg.annotation, ast.Name):
            if arg.annotation.id in ('str', 'Any'):
                return True
        # Check for Optional[str]
        if isinstance(arg.annotation, ast.Subscript):
            if isinstance(arg.annotation.value, ast.Name):
                if arg.annotation.value.id == 'Optional':
                    if isinstance(arg.annotation.slice, ast.Name):
                        if arg.annotation.slice.id == 'str':
                            return True
    return False


def _get_annotation_type(node: Optional[ast.expr]) -> str:
    """Get type annotation as string."""
    if node is None:
        return 'Any'
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return str(node.value)
    return 'Any'
