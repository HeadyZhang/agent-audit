# Agent-Audit v0.11.0 正确的语义层实施 Prompt

> **重要**: v0.10.0 采用了错误的黑名单方向，本 prompt 纠正这个错误。

---

## 任务背景

v0.10.0 实现了 AGENT-034/018 的假阳性过滤，但采用了**错误的方案**：

| 规则 | v0.10.0 错误方案 | 问题 |
|------|-----------------|------|
| AGENT-034 | 60+ `SAFE_BUILTIN_CALLS` 黑名单 | 治标不治本，新标准库会漏 |
| AGENT-018 | `BUILTIN_VARIABLE_PATTERNS` 变量名正则 | 猜测式检测，不可靠 |

**正确方向**：收紧触发条件，而不是放松排除条件。

---

## 核心纠正

### AGENT-034: 从"检测后排除"改为"入口前拦截"

**❌ v0.10.0 错误逻辑**:
```
检测到 subprocess.run → 在黑名单吗? → 是则跳过
```

**✅ v0.11.0 正确逻辑**:
```
是 Tool 入口吗? → 否则直接跳过（不需要任何黑名单）
```

### AGENT-018: 从"变量名猜测"改为"方法白名单"

**❌ v0.10.0 错误逻辑**:
```
检测到 .add() → 变量名匹配 seen/visited/_set 吗? → 是则跳过
```

**✅ v0.11.0 正确逻辑**:
```
方法在 AGENT_MEMORY_METHODS 白名单吗? → 否则直接跳过
```

---

## 实施任务

### Task 1: 清理 v0.10.0 错误代码

**删除** `packages/audit/agent_audit/analysis/agent_boundary_detector.py` 中的：

```python
# 删除这些 - 黑名单方案
SAFE_BUILTIN_CALLS: Set[str] = {...}  # 60+ 项
BUILTIN_VARIABLE_PATTERNS = [...]  # 变量名正则

def is_safe_builtin(func_name: str) -> ...:  # 删除
def is_python_collection(receiver_name: str, ...) -> ...:  # 删除
```

**删除** `dangerous_operation_analyzer.py` 中的：
```python
def _is_dangerous_op_actually_safe_builtin(...):  # 删除整个函数
```

### Task 2: 创建 Tool 入口检测器

**新建或重写** `packages/audit/agent_audit/analysis/tool_boundary_detector.py`:

```python
"""
Tool Boundary Detection for AGENT-034.

Core principle: Only flag issues WITHIN Agent Tool entry points.
No blacklists - just tight entry point identification.
"""

import ast
from dataclasses import dataclass
from typing import Optional, Set

TOOL_DECORATORS: Set[str] = {
    'tool',           # LangChain @tool
    'function_tool',  # LlamaIndex
    'kernel_function', # Semantic Kernel
}

TOOL_CLASS_METHODS: Set[str] = {
    '_run', '_arun', 'run', 'arun', 'invoke', 'ainvoke',
}

TOOL_BASE_CLASSES: Set[str] = {
    'BaseTool', 'Tool', 'StructuredTool', 'FunctionTool',
    'QueryEngineTool', 'RunnableLambda',
}


@dataclass
class ToolBoundaryResult:
    is_tool_entry: bool
    reason: str
    confidence: float = 1.0


def is_tool_entry_point(
    node: ast.FunctionDef,
    parent_class: Optional[str] = None,
    parent_bases: Optional[Set[str]] = None,
) -> ToolBoundaryResult:
    """
    Check if function is an Agent Tool entry point.
    
    This is the ONLY gate for AGENT-034.
    If False, skip ALL further checks. No blacklists needed.
    """
    # Check 1: @tool decorator
    for dec in node.decorator_list:
        name = _get_decorator_name(dec)
        if name in TOOL_DECORATORS:
            return ToolBoundaryResult(True, f"@{name} decorator", 0.95)
    
    # Check 2: _run/_arun in Tool class
    if parent_class and parent_bases:
        if node.name in TOOL_CLASS_METHODS:
            if parent_bases & TOOL_BASE_CLASSES:
                return ToolBoundaryResult(True, f"{parent_class}.{node.name}()", 0.90)
    
    # Check 3: Weak heuristic - function name contains 'tool'
    # Only use if no stronger signals, and with lower confidence
    if 'tool' in node.name.lower() and _has_str_params(node):
        return ToolBoundaryResult(True, f"Name heuristic: {node.name}", 0.60)
    
    # NOT a Tool entry point
    return ToolBoundaryResult(False, "Not a Tool entry point", 0.0)


def _get_decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _has_str_params(node: ast.FunctionDef) -> bool:
    for arg in node.args.args:
        if arg.arg in ('self', 'cls'):
            continue
        # Check for str/Any annotation
        if arg.annotation is None:
            return True  # Unannotated = Any
        if isinstance(arg.annotation, ast.Name):
            if arg.annotation.id in ('str', 'Any'):
                return True
    return False
```

### Task 3: 创建 Agent 内存方法白名单

**新建或重写** `packages/audit/agent_audit/analysis/memory_method_detector.py`:

```python
"""
Agent Memory Method Detection for AGENT-018.

Core principle: WHITELIST of known Agent memory write methods.
No variable name guessing - only specific method identification.
"""

from typing import Dict, Tuple, Optional, Set

# WHITELIST of Agent Memory Write Methods
# Only these methods should trigger AGENT-018
AGENT_MEMORY_WRITE_METHODS: Dict[str, str] = {
    # LangChain Memory
    'add_message': 'langchain',
    'add_user_message': 'langchain',
    'add_ai_message': 'langchain',
    'add_messages': 'langchain',
    'save_context': 'langchain',
    
    # Vector Stores
    'add_texts': 'vector_store',
    'add_documents': 'vector_store',
    'aadd_texts': 'vector_store',
    'aadd_documents': 'vector_store',
    'upsert': 'vector_store',
    
    # LlamaIndex
    'insert': 'llama_index',
    'insert_nodes': 'llama_index',
    
    # CrewAI
    'add_to_memory': 'crewai',
    
    # Haystack
    'write_documents': 'haystack',
    
    # Generic (always Agent memory, never Python builtin)
    'add_memory': 'generic',
    'store_memory': 'generic',
    'persist_memory': 'generic',
    'save_memory': 'generic',
    'update_memory': 'generic',
}


def is_agent_memory_method(method_name: str) -> Tuple[bool, str]:
    """
    Check if method is a known Agent memory write operation.
    
    This uses a WHITELIST - not in list = not checked.
    Python's set.add(), list.append() are NOT in this list.
    """
    if method_name in AGENT_MEMORY_WRITE_METHODS:
        framework = AGENT_MEMORY_WRITE_METHODS[method_name]
        return (True, f"{method_name} ({framework})")
    
    return (False, "")
```

### Task 4: 修改 python_scanner.py

**修改 `_check_tool_no_input_validation`**:

```python
from agent_audit.analysis.tool_boundary_detector import is_tool_entry_point

def _check_tool_no_input_validation(
    self, node: ast.FunctionDef
) -> Optional[Dict[str, Any]]:
    """AGENT-034: Only check within Tool entry points."""
    
    # === GATE: Tool Entry Point Check ===
    boundary = is_tool_entry_point(
        node,
        parent_class=self._current_class,
        parent_bases=self._current_class_bases,
    )
    
    if not boundary.is_tool_entry:
        return None  # NOT a Tool → skip ALL checks
    
    # --- From here, we're inside a Tool ---
    
    # Get str params
    str_params = self._get_str_params(node)
    if not str_params:
        return None
    
    # Check validation
    if self._has_input_validation(node, str_params):
        return None
    
    # Check dangerous sinks
    dangerous = self._find_dangerous_sink(node, str_params)
    if not dangerous:
        return None
    
    return {
        'type': 'tool_no_input_validation',
        'function': node.name,
        'tool_boundary': boundary.reason,
        'unvalidated_params': list(str_params),
        'dangerous_sink': dangerous,
        'line': node.lineno,
        'confidence': boundary.confidence,
        'owasp_id': 'ASI-02',
    }
```

**修改 `_check_memory_poisoning`**:

```python
from agent_audit.analysis.memory_method_detector import is_agent_memory_method

def _check_memory_poisoning(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    """AGENT-018: Only check known Agent memory methods."""
    
    func_name = self._get_call_name(node)
    if not func_name:
        return None
    
    method_name = func_name.split('.')[-1]
    
    # === GATE: Agent Memory Method Check ===
    is_memory, framework = is_agent_memory_method(method_name)
    
    if not is_memory:
        return None  # Not Agent memory method → skip
    
    # --- From here, we know it's an Agent memory write ---
    
    # ... existing context analysis ...
    
    return {
        'type': 'unsanitized_memory_write',
        'function': func_name,
        'method': method_name,
        'framework': framework,
        'line': node.lineno,
        # ... rest ...
    }
```

### Task 5: 更新测试

**删除**基于黑名单/正则的测试：
- `test_safe_builtin_asyncio_run` - 不再需要
- `test_python_collection_detection` - 不再需要
- `test_visited_add_is_builtin` - 不再需要

**添加**新测试：

```python
# test_tool_boundary_detector.py

def test_tool_decorator_is_entry():
    """@tool decorator identifies entry point."""
    source = '''
@tool
def my_tool(query: str) -> str:
    return query
'''
    node = ast.parse(source).body[0]
    result = is_tool_entry_point(node)
    assert result.is_tool_entry is True
    assert '@tool' in result.reason


def test_regular_function_not_entry():
    """Regular function is NOT entry point."""
    source = '''
def process_data(data: str) -> str:
    return asyncio.run(async_process(data))
'''
    node = ast.parse(source).body[0]
    result = is_tool_entry_point(node)
    assert result.is_tool_entry is False


def test_add_message_is_memory_method():
    """add_message is Agent memory method."""
    is_mem, _ = is_agent_memory_method('add_message')
    assert is_mem is True


def test_set_add_not_memory_method():
    """set.add() is NOT Agent memory method."""
    is_mem, _ = is_agent_memory_method('add')
    assert is_mem is False


def test_list_append_not_memory_method():
    """list.append() is NOT Agent memory method."""
    is_mem, _ = is_agent_memory_method('append')
    assert is_mem is False
```

### Task 6: 验证

```bash
# 运行测试
poetry run pytest tests/ -v

# 关键验证点:
# 1. asyncio.run() 不触发 AGENT-034 (因为不在 @tool 内，不是因为在黑名单)
# 2. set().add() 不触发 AGENT-018 (因为 'add' 不在方法白名单)
# 3. memory.add_message() 仍然触发 AGENT-018 (因为在白名单)
```

---

## 正确性检验

实施后，用这些场景检验是否正确：

### 场景 1: asyncio.run 不应触发

```python
# 这个文件没有 @tool，所以不应触发 AGENT-034
import asyncio

async def main():
    result = await process()
    return result

if __name__ == "__main__":
    asyncio.run(main())  # 不触发 - 因为不是 Tool 入口
```

**验证逻辑**: `is_tool_entry_point(main)` 返回 False → 跳过

### 场景 2: set.add 不应触发

```python
# Generative Agents 场景
from langchain.agents import Agent

def track_agents(agents):
    seen = set()
    for agent in agents:
        seen.add(agent.id)  # 不触发 - 'add' 不在白名单
```

**验证逻辑**: `is_agent_memory_method('add')` 返回 False → 跳过

### 场景 3: Tool + subprocess 应触发

```python
@tool
def shell_executor(command: str) -> str:
    """Execute shell command."""
    result = subprocess.run(command, shell=True)  # 触发!
    return result.stdout
```

**验证逻辑**: 
1. `is_tool_entry_point` → True (@tool)
2. 有 str 参数 → True
3. 有危险操作 → True  
4. 无验证 → True
5. → 触发 AGENT-034

### 场景 4: memory.add_message 应触发

```python
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory()
memory.add_message(user_input)  # 触发!
```

**验证逻辑**: `is_agent_memory_method('add_message')` 返回 True → 触发 AGENT-018

---

## 总结

| 改动 | v0.10.0 错误 | v0.11.0 正确 |
|-----|-------------|-------------|
| AGENT-034 Gate | 黑名单排除 | Tool 入口识别 |
| AGENT-018 Gate | 变量名正则 | 方法白名单 |
| 可维护性 | 差（需补黑名单） | 好（只维护方法列表） |
| 准确性 | 差（会漏/会误） | 高（精确匹配） |

**核心原则**: 收紧触发条件，而不是放松排除条件。
