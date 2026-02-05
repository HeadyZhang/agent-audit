# Agent-Audit v0.10.0 语义层实施 Prompt

> **使用方法**: 在新的 Claude Code 会话中，将此文件内容完整粘贴作为首条消息。

---

## 角色与目标

你是一个专注于代码安全扫描工具优化的高级 Python 工程师。你的任务是为 `agent-audit` 项目实施 **AGENT-034/018 语义层重构**，这是 v0.10.0 的核心优化。

**核心目标**: 通过添加 Agent 边界检测，大幅减少假阳性，同时保留所有真阳性。

## 问题数据

```
当前 v0.9.0 Benchmark:
├── SWE-agent: 54 findings (目标 ≤20)
│   └── AGENT-034: 33 个 FP (asyncio.run, re.compile 误报)
├── Generative Agents: 11 findings (目标 0)  
│   └── AGENT-018: 11 个 FP (全部是 Python set() 误报)
└── 这两个问题阻塞了 quality gate 通过
```

## 根因分析

| 规则 | 当前逻辑 | 问题 |
|------|---------|------|
| AGENT-034 | `@tool + str参数 + 含危险函数` | `asyncio.run()`, `re.compile()` 被误判为危险操作 |
| AGENT-018 | `method_name in MEMORY_WRITE_FUNCTIONS` | Python `set()`, `list.append()` 被误判为 Agent 内存操作 |

**根因**: 缺乏语义层检测——未区分 "Agent 上下文" vs "普通 Python 代码"。

## 解决方案设计

### 核心思路

在规则触发前添加 **Agent 边界检测**:

```
优化前: AST匹配语法模式 → 直接报告
优化后: AST匹配语法模式 → 检查是否在Agent上下文 → 是则报告
```

### Agent 上下文定义

1. **文件级**: 必须 import Agent 框架 (langchain, crewai, autogen 等)
2. **函数级**: AGENT-034 需要 @tool 装饰器
3. **调用级**: AGENT-018 需要是 Agent memory 对象，非 Python 内置

## 实施任务清单

请按以下顺序执行:

### Task 1: 创建 Agent 边界检测器

**文件**: `packages/audit/agent_audit/analysis/agent_boundary_detector.py`

创建新模块，实现:
- `AgentBoundaryDetector` 类
- `analyze_file()`: 检测文件是否有 Agent 框架 import
- `is_safe_builtin_call()`: 判断是否安全内置函数 (asyncio.run, re.compile 等)
- `is_python_builtin_collection()`: 判断是否 Python 内置集合 (set, list 等)
- `is_agent_memory_operation()`: 判断是否 Agent memory 操作

关键常量:
```python
SAFE_BUILTIN_CALLS = {
    'asyncio.run', 'asyncio.create_task', 'asyncio.gather',
    're.compile', 're.match', 're.search', 're.findall',
    'json.loads', 'json.dumps', 'list', 'dict', 'set', ...
}

AGENT_FRAMEWORK_IMPORTS = {
    'langchain': ['langchain', 'langchain_core', ...],
    'crewai': ['crewai'],
    'autogen': ['autogen', 'pyautogen'],
    ...
}

BUILTIN_VARIABLE_PATTERNS = [
    r'^_?(seen|visited|processed|checked)_?\w*$',  # 跟踪用集合
    r'^_?\w*(_set|_list|_dict)$',  # 明确命名为集合
]

AGENT_MEMORY_INDICATORS = [
    r'memory', r'store', r'vector', r'context', r'history', ...
]
```

### Task 2: 修改 dangerous_operation_analyzer.py

**文件**: `packages/audit/agent_audit/analysis/dangerous_operation_analyzer.py`

修改 `should_flag_tool_input()` 函数:
- 添加 `is_safe_builtin()` 检查
- 如果检测到的 "危险操作" 实际是安全内置 (asyncio.run 等)，返回 `(False, 0.0, "Safe builtin")`

### Task 3: 修改 python_scanner.py

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

3.1 在 `__init__` 添加:
```python
self._agent_detector = AgentBoundaryDetector()
self._has_agent_imports = False
```

3.2 在 `scan` 方法开头添加文件级检测:
```python
file_context = self._agent_detector.analyze_file(self.source)
self._has_agent_imports = file_context.has_agent_imports
```

3.3 修改 `_check_tool_no_input_validation` (AGENT-034):
- 开头添加: `if not self._has_agent_imports: return None`

3.4 修改 `_check_memory_poisoning` (AGENT-018):
- 开头添加: `if not self._has_agent_imports: return None`
- 在 method_name 检查后添加 Python 内置过滤:
```python
is_builtin, _ = self._agent_detector.is_python_builtin_collection(node, var_name)
if is_builtin:
    return None  # 跳过 Python 内置如 set(), list.append()
```

3.5 添加辅助方法 `_extract_receiver_name()` 提取方法调用的接收者变量名

### Task 4: 添加单元测试

**文件**: `packages/audit/tests/test_analysis/test_agent_boundary_detector.py`

测试用例:
- `test_file_with_langchain_import`: 有 langchain import → is_agent_context=True
- `test_file_without_agent_import`: 无 Agent import → is_agent_context=False
- `test_safe_builtin_asyncio_run`: asyncio.run → is_safe_builtin=True
- `test_safe_builtin_re_compile`: re.compile → is_safe_builtin=True
- `test_python_set_is_builtin`: set() → is_builtin=True
- `test_visited_add_is_builtin`: visited.add() → is_builtin=True
- `test_memory_add_is_agent_memory`: memory.add() → is_agent_memory=True

### Task 5: 验证

1. 运行单元测试: `poetry run pytest tests/test_analysis/test_agent_boundary_detector.py -v`
2. 运行完整测试: `poetry run pytest tests/ -v --tb=short`
3. 确保所有 948+ 测试通过

### Task 6: 更新版本

- `packages/audit/agent_audit/version.py`: `__version__ = "0.10.0"`
- `packages/audit/pyproject.toml`: `version = "0.10.0"`

## 关键约束

1. **不破坏现有功能** - 只添加前置过滤，不删除现有检测逻辑
2. **保留真阳性** - AGENT-044 (sudoers), AGENT-001 (command injection) 必须继续工作
3. **类型注解** - 所有新函数必须有完整类型注解
4. **代码风格** - 遵循项目 black/ruff 配置

## 验收标准

| 指标 | v0.9.0 | v0.10.0 目标 |
|------|--------|-------------|
| SWE-agent AGENT-034 | 33 | ≤6 |
| Generative Agents AGENT-018 | 11 | 0 |
| 测试通过率 | 100% | 100% |

## 开始

请先阅读以下现有代码了解上下文:
1. `packages/audit/agent_audit/scanners/python_scanner.py` - 主扫描器，找到 `_check_tool_no_input_validation` 和 `_check_memory_poisoning`
2. `packages/audit/agent_audit/analysis/dangerous_operation_analyzer.py` - AGENT-034 辅助分析器
3. `packages/audit/agent_audit/analyzers/memory_context.py` - AGENT-018 上下文分析器

读取完成后，按 Task 1-6 顺序实施。每个 Task 完成后运行相关测试验证。
