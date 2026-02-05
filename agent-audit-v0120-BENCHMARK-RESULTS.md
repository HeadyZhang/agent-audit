# Agent-Audit v0.12.0 Semantic Layer Refinement Results

**Date**: 2026-02-05
**Version**: v0.12.0
**Status**: ✅ ALL BENCHMARKS PASSED

---

## Executive Summary

v0.12.0 implements two refinements to the v0.11.0 semantic layer:

| Feature | Problem Solved | Result |
|---------|---------------|--------|
| Import-aware ambiguous methods | `list.insert()` was triggering AGENT-018 FP | **✅ FIXED** |
| OpenAI function calling detection | Functions in `tools=[...]` were not detected | **✅ FIXED** |

### Benchmark Results

| Benchmark | Scenario | Expected | Actual | Status |
|-----------|----------|----------|--------|--------|
| 1 | `list.insert()` without llama_index | 0 AGENT-018 | 0 | ✅ PASS |
| 2 | LlamaIndex `index.insert()` | AGENT-018 | 4 findings | ✅ PASS |
| 3 | OpenAI `chat.completions.create()` | AGENT-034 | 3 findings | ✅ PASS |
| 4 | Anthropic `messages.create()` | AGENT-034 | 2 findings | ✅ PASS |
| 5 | Original `@tool` decorator | AGENT-034 | 3 findings | ✅ PASS |
| 6 | SWE-agent pattern (regular funcs) | 0 AGENT-034 | 0 | ✅ PASS |
| 7 | Generative Agents (`set.add`) | 0 AGENT-018 | 0 | ✅ PASS |

---

## Phase 1: Insert Ambiguity Fix

### Problem

v0.11.0 whitelist included `insert` mapped to `llama_index`, but:
- Python's `list.insert()` would trigger false positives
- No way to distinguish `list.insert()` from `index.insert()`

### Solution

Split methods into UNAMBIGUOUS and AMBIGUOUS:
- **UNAMBIGUOUS**: Always trigger (e.g., `add_message`, `add_documents`)
- **AMBIGUOUS**: Only trigger with matching import (e.g., `insert` + `llama_index`)

### Test Results

| Scenario | Import | Expected | Actual | Status |
|----------|--------|----------|--------|--------|
| `list.insert(0, item)` | `os, sys` | No trigger | No trigger | ✓ PASS |
| `index.insert(doc)` | `llama_index` | AGENT-018 | AGENT-018 | ✓ PASS |
| `data.upsert(item)` | `pandas` | No trigger | No trigger | ✓ PASS |
| `client.upsert(vec)` | `pinecone` | AGENT-018 | AGENT-018 | ✓ PASS |

---

## Phase 2: OpenAI Function Calling Detection

### Problem

v0.11.0 only detected Tool entry points via:
- `@tool` decorator
- `BaseTool._run()` method

Projects like Generative Agents that use OpenAI's function calling API directly were not detected.

### Solution

Added `FileToolContext` analysis that:
1. Detects `chat.completions.create()` API calls
2. Extracts functions from `tools=[func1, func2]` parameter
3. Marks those functions as Tool entry points

### Test Results

| Scenario | Registration | Expected | Actual | Status |
|----------|--------------|----------|--------|--------|
| `@tool def shell(cmd): subprocess.run(cmd)` | Decorator | AGENT-034 | AGENT-034 | ✓ PASS |
| `def exec(code): eval(code)` + `tools=[exec]` | Function calling | AGENT-034 | AGENT-034 | ✓ PASS |
| `def helper(): eval(x)` (no registration) | None | No trigger | No trigger | ✓ PASS |
| `@function_schema def func(x): ...` | Decorator | AGENT-034 | AGENT-034 | ✓ PASS |

---

## Implementation Details

### Files Modified

1. **`memory_method_detector.py`**
   - Split `AGENT_MEMORY_WRITE_METHODS` into:
     - `UNAMBIGUOUS_MEMORY_METHODS`: 17 methods
     - `AMBIGUOUS_MEMORY_METHODS`: 2 methods (`insert`, `upsert`)
   - Added `file_imports` parameter to `is_agent_memory_method()`

2. **`tool_boundary_detector.py`**
   - Added `FileToolContext` dataclass
   - Added `analyze_file_tool_context()` function
   - Added `FUNCTION_CALLING_API_PATTERNS` and `FUNCTION_CALLING_DECORATORS`
   - Updated `is_tool_entry_point()` to accept `file_context` parameter

3. **`python_scanner.py`**
   - Added `_tree` parameter to `PythonASTVisitor.__init__()`
   - Added `_file_tool_context` field and `_get_file_tool_context()` method
   - Updated `_check_memory_poisoning()` to pass `file_imports`
   - Updated `_check_tool_no_input_validation()` to pass `file_context`
   - **CRITICAL FIX**: Moved AGENT-034 check outside `if is_tool:` block

### Test Coverage

| Test File | Tests Added | Total |
|-----------|-------------|-------|
| `test_memory_method_detector.py` | +28 | 64 |
| `test_tool_boundary_detector.py` | +13 | 27 |

**Full suite**: 1039 tests passing

---

## Verification Commands

```bash
# Run all tests
cd packages/audit
poetry run pytest ../../tests/ -v

# Test ambiguous methods
poetry run pytest ../../tests/test_analysis/test_memory_method_detector.py -v -k "ambiguous"

# Test OpenAI function calling
poetry run pytest ../../tests/test_analysis/test_tool_boundary_detector.py -v -k "OpenAI"

# Scan test scenarios
poetry run agent-audit scan /path/to/test_scenarios.py --format json
```

---

## Backward Compatibility

Both changes are fully backward compatible:
- `is_agent_memory_method()` accepts `file_imports=None` (defaults to conservative behavior)
- `is_tool_entry_point()` accepts `file_context=None` (existing code works unchanged)
- `AGENT_MEMORY_WRITE_METHODS` dict preserved for API compatibility

---

## Known Limitations

1. **Ambiguous method detection requires imports**: If a file uses `llama_index` without importing it directly (e.g., passed as parameter), detection may miss it.

2. **Function calling detection is heuristic-based**: Complex patterns like `tools=get_tools()` where `get_tools()` returns a list won't be detected.

---

## Changelog

### v0.12.0 (2026-02-05)

#### Added
- Import-aware detection for ambiguous methods (`insert`, `upsert`)
- OpenAI function calling detection (`tools=[func1, func2]`)
- `FileToolContext` dataclass for file-level analysis
- `analyze_file_tool_context()` function
- `FUNCTION_CALLING_DECORATORS` for `@function_schema`, `@openai_function`, etc.
- 41 new unit tests

#### Fixed
- `list.insert()` false positive (was triggering AGENT-018)
- AGENT-034 not checking OpenAI function calling patterns
- AGENT-034 check was inside `if is_tool:` block (now uses own gate)

#### Changed
- `is_agent_memory_method()` now accepts `file_imports` parameter
- `is_tool_entry_point()` now accepts `file_context` parameter
- Split `AGENT_MEMORY_WRITE_METHODS` into unambiguous/ambiguous categories
