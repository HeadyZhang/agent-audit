# Agent-Audit v0.11.0 Correct Semantic Layer Implementation

**Date**: 2026-02-05
**Version**: v0.10.0 → v0.11.0
**Focus**: Fix incorrect v0.10.0 blacklist approach with correct whitelist/gate approach

---

## Executive Summary

**v0.10.0 was wrong.** It used blacklists (SAFE_BUILTIN_CALLS) and variable name patterns (BUILTIN_VARIABLE_PATTERNS) to exclude false positives.

**v0.11.0 is correct.** It tightens trigger conditions using gates:
- AGENT-034: Only trigger inside Tool entry points (@tool decorator, BaseTool._run)
- AGENT-018: Only trigger for known Agent memory methods (add_message, add_texts, etc.)

### Core Principle

**Tighten trigger conditions, don't loosen exclusion conditions.**

---

## v0.10.0 vs v0.11.0 Comparison

| Aspect | v0.10.0 (Wrong) | v0.11.0 (Correct) |
|--------|-----------------|-------------------|
| **AGENT-034 Gate** | 60+ SAFE_BUILTIN_CALLS blacklist | Tool entry point detection |
| **AGENT-018 Gate** | Variable name regex patterns | Method whitelist |
| **Maintainability** | Need to keep adding to blacklist | Only maintain known Agent methods |
| **Accuracy** | Can miss new stdlib, can mismatch | Precise method identification |

---

## Implementation Details

### Task 1: Delete v0.10.0 Wrong Code

**Deleted**:
- `agent_audit/analysis/agent_boundary_detector.py` (60+ SAFE_BUILTIN_CALLS)
- `tests/test_analysis/test_agent_boundary_detector.py` (wrong tests)
- `_is_dangerous_op_actually_safe_builtin()` from dangerous_operation_analyzer.py
- `_is_python_builtin_collection_call()` from memory_context.py
- `_file_context_cache` and related code

---

### Task 2: Create tool_boundary_detector.py

**File**: `agent_audit/analysis/tool_boundary_detector.py`

```python
def is_tool_entry_point(
    node: ast.FunctionDef,
    parent_class: Optional[str] = None,
    parent_bases: Optional[Set[str]] = None,
) -> ToolBoundaryResult:
    """
    Check if a function is an Agent Tool entry point.

    This is the ONLY gate for AGENT-034.
    If False, skip ALL further checks. No blacklist needed.
    """
    # Check 1: @tool decorator
    for decorator in node.decorator_list:
        if _get_decorator_name(decorator) in TOOL_DECORATORS:
            return ToolBoundaryResult(is_tool_entry=True, ...)

    # Check 2: _run/_arun in Tool class
    if parent_class and parent_bases:
        if node.name in TOOL_CLASS_METHODS:
            if parent_bases & TOOL_BASE_CLASSES:
                return ToolBoundaryResult(is_tool_entry=True, ...)

    # NOT a Tool entry point
    return ToolBoundaryResult(is_tool_entry=False, ...)
```

**Key Constants**:
```python
TOOL_DECORATORS = {'tool', 'function_tool', 'kernel_function'}
TOOL_CLASS_METHODS = {'_run', '_arun', 'run', 'arun', 'invoke', 'ainvoke'}
TOOL_BASE_CLASSES = {'BaseTool', 'Tool', 'StructuredTool', ...}
```

---

### Task 3: Create memory_method_detector.py

**File**: `agent_audit/analysis/memory_method_detector.py`

```python
# WHITELIST of known Agent memory methods
AGENT_MEMORY_WRITE_METHODS = {
    'add_message': 'langchain',
    'add_messages': 'langchain',
    'add_user_message': 'langchain',
    'add_ai_message': 'langchain',
    'save_context': 'langchain',
    'add_texts': 'vector_store',
    'add_documents': 'vector_store',
    'upsert': 'vector_store',
    'insert': 'llama_index',
    'add_to_memory': 'crewai',
    'write_documents': 'haystack',
    ...
}

def is_agent_memory_method(method_name: str) -> Tuple[bool, str]:
    """
    WHITELIST check - not in list = not checked.
    Python's set.add(), list.append() are NOT in this list.
    """
    if method_name in AGENT_MEMORY_WRITE_METHODS:
        return (True, AGENT_MEMORY_WRITE_METHODS[method_name])
    return (False, "")
```

---

### Task 4: Modify python_scanner.py

**_check_tool_no_input_validation (AGENT-034)**:
```python
def _check_tool_no_input_validation(self, node):
    # === v0.11.0: GATE - Is this a Tool entry point? ===
    boundary = is_tool_entry_point(node, ...)
    if not boundary.is_tool_entry:
        return None  # NOT a Tool - skip ALL checks

    # ... rest of checks only run inside Tool ...
```

**_check_memory_poisoning (AGENT-018)**:
```python
def _check_memory_poisoning(self, node):
    method_name = func_name.split('.')[-1]

    # === v0.11.0: GATE - Only check known Agent memory methods ===
    is_memory, framework = is_agent_memory_method(method_name)
    if not is_memory:
        return None  # Not Agent memory - skip

    # ... rest of checks only run for Agent memory ...
```

**Updated MEMORY_WRITE_FUNCTIONS** (removed generic methods):
```python
# Removed: 'put', 'set', 'store' (cause false positives)
# Added: specific Agent memory methods
MEMORY_WRITE_FUNCTIONS = {
    'add_documents', 'add_texts', 'upsert', 'insert',
    'persist', 'save_context', 'add_message', 'add_memory',
    'add_messages', 'add_user_message', 'add_ai_message',
    'add_to_memory', 'write_documents', 'insert_nodes',
    'store_memory', 'persist_memory', 'save_memory', 'update_memory',
}
```

---

## Test Results

```
1012 passed, 1 skipped in 2.43s
```

**Test Growth**: 948 (v0.9.0) → 1012 (v0.11.0) = +64 new tests

**New Test Files**:
- `tests/test_analysis/test_tool_boundary_detector.py` (14 tests)
- `tests/test_analysis/test_memory_method_detector.py` (50 tests)

---

## Files Modified/Created

**Created**:
1. `agent_audit/analysis/tool_boundary_detector.py` - Tool entry point gate
2. `agent_audit/analysis/memory_method_detector.py` - Memory method whitelist
3. `tests/test_analysis/test_tool_boundary_detector.py` - Tool boundary tests
4. `tests/test_analysis/test_memory_method_detector.py` - Memory method tests

**Modified**:
5. `agent_audit/analysis/dangerous_operation_analyzer.py` - Removed blacklist code
6. `agent_audit/analyzers/memory_context.py` - Removed variable name patterns
7. `agent_audit/scanners/python_scanner.py` - Added new gates
8. `agent_audit/version.py` - Version 0.11.0
9. `pyproject.toml` - Version 0.11.0

**Deleted**:
10. `agent_audit/analysis/agent_boundary_detector.py` - Wrong v0.10.0 code
11. `tests/test_analysis/test_agent_boundary_detector.py` - Wrong tests

---

## Verification Scenarios

### Scenario 1: asyncio.run() in regular function

```python
# This should NOT trigger AGENT-034
def main():
    asyncio.run(async_main())
```

**v0.10.0**: Needed to check SAFE_BUILTIN_CALLS blacklist
**v0.11.0**: `is_tool_entry_point(main)` → False → Skip entirely

### Scenario 2: set.add() in any context

```python
# This should NOT trigger AGENT-018
seen = set()
seen.add(item)
```

**v0.10.0**: Needed BUILTIN_VARIABLE_PATTERNS to match 'seen'
**v0.11.0**: `is_agent_memory_method('add')` → False → Skip entirely

### Scenario 3: @tool with subprocess (should trigger)

```python
@tool
def shell_tool(command: str) -> str:
    return subprocess.run(command, shell=True)
```

**v0.11.0**: `is_tool_entry_point()` → True → Check for dangerous ops → Found → AGENT-034

### Scenario 4: memory.add_message() (should trigger)

```python
from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()
memory.add_message(user_input)
```

**v0.11.0**: `is_agent_memory_method('add_message')` → True → AGENT-018

---

## Conclusion

v0.11.0 implements the **correct** semantic layer approach:

| Rule | Wrong Approach (v0.10.0) | Correct Approach (v0.11.0) |
|------|--------------------------|----------------------------|
| AGENT-034 | Blacklist exclusion | Tool entry point gate |
| AGENT-018 | Variable name regex | Method whitelist gate |

**Key insight**: Don't try to identify what to exclude (infinite). Instead, identify what to check (finite).
