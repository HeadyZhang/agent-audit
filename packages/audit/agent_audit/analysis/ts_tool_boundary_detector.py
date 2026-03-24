"""
TypeScript/JavaScript Tool Boundary Detector.

Identifies AI agent tool entry points in TypeScript/JavaScript code:
- MCP SDK tool definitions: server.tool("name", schema, handler)
- Vercel AI SDK tools: tool({ description, parameters, execute })
- OpenAI function calling: functions/tools array definitions
- LangChain.js tools: class extending StructuredTool/DynamicTool
- Express/Fastify route handlers: app.post("/api/...", handler)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class TSToolFramework(Enum):
    """TypeScript tool framework classification."""

    MCP = "mcp"
    VERCEL_AI = "vercel-ai"
    OPENAI = "openai"
    LANGCHAIN_JS = "langchain-js"
    EXPRESS = "express"
    FASTIFY = "fastify"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TSToolBoundary:
    """Detected tool boundary in TypeScript code."""

    framework: TSToolFramework
    tool_name: str
    line: int
    confidence: float
    scope_start: int
    scope_end: int


@dataclass(frozen=True)
class _PatternEntry:
    """Internal: compiled pattern with metadata."""

    pattern: re.Pattern[str]
    framework: TSToolFramework
    base_confidence: float
    pattern_name: str


# Compiled pattern entries for TS tool detection
_TOOL_PATTERNS: List[_PatternEntry] = [
    # MCP SDK: server.tool("name", schema, handler)
    _PatternEntry(
        pattern=re.compile(r'\.tool\s*\(\s*["\'](\w+)["\']'),
        framework=TSToolFramework.MCP,
        base_confidence=0.90,
        pattern_name="mcp_tool",
    ),
    # Vercel AI SDK: tool({ description: "...", parameters: z.object(...), execute: ... })
    _PatternEntry(
        pattern=re.compile(
            r'\btool\s*\(\s*\{[^}]*description\s*:', re.DOTALL
        ),
        framework=TSToolFramework.VERCEL_AI,
        base_confidence=0.85,
        pattern_name="vercel_tool",
    ),
    # OpenAI function calling: tools: [{ type: "function", function: { name: "..." } }]
    _PatternEntry(
        pattern=re.compile(
            r'(?:functions|tools)\s*:\s*\[\s*\{[^}]*'
            r'(?:type\s*:\s*["\']function["\']|name\s*:\s*["\'](\w+)["\'])'
        ),
        framework=TSToolFramework.OPENAI,
        base_confidence=0.85,
        pattern_name="openai_function",
    ),
    # LangChain.js: class XTool extends StructuredTool
    _PatternEntry(
        pattern=re.compile(
            r'class\s+(\w+)\s+extends\s+'
            r'(?:StructuredTool|DynamicTool|Tool)\b'
        ),
        framework=TSToolFramework.LANGCHAIN_JS,
        base_confidence=0.90,
        pattern_name="langchain_tool",
    ),
    # Express handler: app.post("/api/...", handler)
    _PatternEntry(
        pattern=re.compile(
            r'(?:app|router)\.'
            r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        ),
        framework=TSToolFramework.EXPRESS,
        base_confidence=0.70,
        pattern_name="express_handler",
    ),
    # Fastify handler: fastify.post("/api/...", handler)
    _PatternEntry(
        pattern=re.compile(
            r'(?:fastify|server)\.'
            r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        ),
        framework=TSToolFramework.FASTIFY,
        base_confidence=0.70,
        pattern_name="fastify_handler",
    ),
]

# Context confidence boost keywords (when found near tool definitions)
_TOOL_CONTEXT_KEYWORDS = re.compile(
    r'\b(?:tool|agent|function_?call|ai_?sdk|mcp|handler|endpoint)\b',
    re.IGNORECASE,
)

_CONTEXT_BOOST = 0.05
_MAX_CONFIDENCE = 1.0
_CONTEXT_WINDOW = 5
_DEFAULT_SCOPE_ESTIMATE = 50
_MAX_SCOPE_SEARCH = 200

# Multiline patterns that need full-content scanning (not line-by-line).
# Each entry: (pattern, framework, base_confidence, pattern_name)
_MULTILINE_PATTERNS: List[_PatternEntry] = [
    # Vercel AI SDK: tool({ ...description: ... }) spanning multiple lines
    _PatternEntry(
        pattern=re.compile(
            r'\btool\s*\(\s*\{[^}]*description\s*:', re.DOTALL
        ),
        framework=TSToolFramework.VERCEL_AI,
        base_confidence=0.85,
        pattern_name="vercel_tool",
    ),
]


def detect_ts_tool_boundaries(content: str) -> List[TSToolBoundary]:
    """
    Detect tool boundaries in TypeScript/JavaScript content.

    Scans each line for known framework patterns and performs a
    separate multiline pass for patterns that span multiple lines.

    Args:
        content: Full file content as string.

    Returns:
        List of detected TSToolBoundary instances, ordered by line number.
    """
    boundaries: List[TSToolBoundary] = []
    lines = content.splitlines()

    # Pass 1: line-by-line patterns
    for line_idx, line in enumerate(lines):
        line_num = line_idx + 1
        for entry in _TOOL_PATTERNS:
            match = entry.pattern.search(line)
            if match is None:
                continue

            tool_name = _extract_tool_name(match, entry.pattern_name)
            confidence = _adjust_confidence(
                entry.base_confidence, lines, line_idx
            )
            scope_end = _estimate_scope_end(lines, line_idx)

            boundaries.append(
                TSToolBoundary(
                    framework=entry.framework,
                    tool_name=tool_name,
                    line=line_num,
                    confidence=confidence,
                    scope_start=line_num,
                    scope_end=scope_end,
                )
            )

    # Pass 2: multiline patterns (scan full content)
    matched_lines = {b.line for b in boundaries}
    for entry in _MULTILINE_PATTERNS:
        for match in entry.pattern.finditer(content):
            # Determine line number from match position
            line_num = content[:match.start()].count("\n") + 1
            if line_num in matched_lines:
                continue  # Already detected by line-by-line pass

            line_idx = line_num - 1
            tool_name = _extract_tool_name(match, entry.pattern_name)
            confidence = _adjust_confidence(
                entry.base_confidence, lines, line_idx
            )
            scope_end = _estimate_scope_end(lines, line_idx)

            boundaries.append(
                TSToolBoundary(
                    framework=entry.framework,
                    tool_name=tool_name,
                    line=line_num,
                    confidence=confidence,
                    scope_start=line_num,
                    scope_end=scope_end,
                )
            )
            matched_lines.add(line_num)

    # Return sorted by line number for deterministic order
    return sorted(boundaries, key=lambda b: b.line)


def is_within_tool_boundary(
    line: int,
    boundaries: List[TSToolBoundary],
) -> Optional[TSToolBoundary]:
    """
    Check if a line number is within any detected tool boundary.

    Args:
        line: 1-indexed line number to check.
        boundaries: Previously detected boundaries from detect_ts_tool_boundaries.

    Returns:
        The enclosing TSToolBoundary, or None if line is outside all boundaries.
    """
    for boundary in boundaries:
        if boundary.scope_start <= line <= boundary.scope_end:
            return boundary
    return None


def get_tool_confidence_boost(boundary: TSToolBoundary) -> float:
    """
    Get confidence boost for findings within a tool boundary.

    Findings inside agent tool handlers are more security-critical,
    so they receive a confidence boost.

    Args:
        boundary: The enclosing tool boundary.

    Returns:
        Float boost value to add to finding confidence.
    """
    boost_map = {
        TSToolFramework.MCP: 0.10,
        TSToolFramework.VERCEL_AI: 0.08,
        TSToolFramework.OPENAI: 0.08,
        TSToolFramework.LANGCHAIN_JS: 0.10,
        TSToolFramework.EXPRESS: 0.05,
        TSToolFramework.FASTIFY: 0.05,
        TSToolFramework.UNKNOWN: 0.0,
    }
    return boost_map.get(boundary.framework, 0.0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_tool_name(
    match: re.Match[str],
    pattern_name: str,
) -> str:
    """Extract tool name from a regex match, falling back to pattern label."""
    if match.lastindex is None:
        return f"<{pattern_name}>"

    for group_idx in range(1, match.lastindex + 1):
        try:
            group_value = match.group(group_idx)
        except IndexError:
            continue
        if group_value and not group_value.startswith("/"):
            return group_value

    return f"<{pattern_name}>"


def _adjust_confidence(
    base_confidence: float,
    lines: List[str],
    line_idx: int,
) -> float:
    """Boost confidence if tool-related keywords appear nearby."""
    context_start = max(0, line_idx - _CONTEXT_WINDOW)
    context_end = min(len(lines), line_idx + _CONTEXT_WINDOW + 1)
    context = "\n".join(lines[context_start:context_end])

    if _TOOL_CONTEXT_KEYWORDS.search(context):
        return min(_MAX_CONFIDENCE, base_confidence + _CONTEXT_BOOST)
    return base_confidence


def _estimate_scope_end(lines: List[str], start_idx: int) -> int:
    """
    Estimate where a function/handler scope ends by tracking braces.

    Counts braces per line and considers the scope closed only when
    the cumulative balance returns to zero at a line boundary (not
    mid-line, which avoids false closes on patterns like ``{}, () => {``).

    Returns a 1-indexed line number.
    """
    brace_count = 0
    started = False
    max_idx = min(start_idx + _MAX_SCOPE_SEARCH, len(lines))

    for i in range(start_idx, max_idx):
        for ch in lines[i]:
            if ch == "{":
                brace_count += 1
                started = True
            elif ch == "}":
                brace_count -= 1

        # Only check balance at line boundaries
        if started and brace_count <= 0:
            return i + 1  # 1-indexed

    # Fallback: estimate scope at ~50 lines
    return min(start_idx + _DEFAULT_SCOPE_ESTIMATE + 1, len(lines))
