# Agent-Audit v0.12.0 语义层精细化 Prompt

> **前置**: v0.11.0 语义层基础已完成，方向正确。本次优化解决两个边界问题。

---

## 任务背景

v0.11.0 实现了正确的语义层：
- AGENT-034: Tool 入口 gate (不用黑名单)
- AGENT-018: 方法白名单 (不猜变量名)

但存在两个边界问题需要修复：

| 问题 | 影响 | 解决方案 |
|------|------|---------|
| `insert` 歧义 | `list.insert()` 会触发 FP | 增加 import 检查 |
| 无框架项目漏检 | OpenAI function calling 不触发 | 扩展 Tool 入口识别 |

---

## Phase 1: 修复 `insert` 歧义问题

### 问题

当前 `is_agent_memory_method('insert')` 返回 `(True, 'llama_index')`，不检查文件是否 import 了 llama_index。

导致 `my_list.insert(0, item)` 触发 AGENT-018 (FP)。

### 解决方案

对有歧义的方法，增加 import 检查。

### Step 1.1: 修改 memory_method_detector.py

**文件**: `packages/audit/agent_audit/analysis/memory_method_detector.py`

将方法分为两类：无歧义 + 有歧义

```python
"""
Agent Memory Method Detection for AGENT-018.

v0.12.0: 对有歧义的方法增加 import 检查。
"""

from __future__ import annotations
from typing import Dict, Tuple, Optional, Set

# 无歧义的方法 - 直接触发，不需要 import 检查
UNAMBIGUOUS_MEMORY_METHODS: Dict[str, str] = {
    # LangChain Memory
    'add_message': 'langchain',
    'add_user_message': 'langchain',
    'add_ai_message': 'langchain',
    'add_messages': 'langchain',
    'save_context': 'langchain',
    'add_memory': 'langchain',
    # Vector Stores
    'add_texts': 'vector_store',
    'add_documents': 'vector_store',
    'aadd_texts': 'vector_store',
    'aadd_documents': 'vector_store',
    # LlamaIndex (无歧义的)
    'insert_nodes': 'llama_index',
    # CrewAI
    'add_to_memory': 'crewai',
    # Haystack
    'write_documents': 'haystack',
    # Generic
    'store_memory': 'generic',
    'persist_memory': 'generic',
    'save_memory': 'generic',
    'update_memory': 'generic',
    'update_context': 'generic',
}

# 有歧义的方法 - 需要检查 import
# 格式: method_name -> (framework, required_import_keywords)
AMBIGUOUS_MEMORY_METHODS: Dict[str, Tuple[str, Set[str]]] = {
    'insert': ('llama_index', {'llama_index', 'llama-index', 'llamaindex'}),
    'upsert': ('vector_store', {'pinecone', 'chromadb', 'weaviate', 'qdrant', 'milvus', 'faiss'}),
}

# Python 内置方法 - 永远不触发
PYTHON_BUILTIN_METHODS: Set[str] = {
    'add', 'append', 'extend', 'update', 'put', 'push', 'set',
}


def is_agent_memory_method(
    method_name: str,
    file_imports: Optional[Set[str]] = None,
) -> Tuple[bool, str]:
    """
    检查方法是否为 Agent 内存操作。
    
    v0.12.0: 对有歧义的方法增加 import 检查。
    
    Args:
        method_name: 方法名
        file_imports: 文件的 import 列表
    
    Returns:
        (is_memory_method, framework)
    """
    # 快速排除 Python 内置
    if method_name in PYTHON_BUILTIN_METHODS:
        return (False, "")
    
    # 检查无歧义方法
    if method_name in UNAMBIGUOUS_MEMORY_METHODS:
        return (True, UNAMBIGUOUS_MEMORY_METHODS[method_name])
    
    # 检查有歧义方法
    if method_name in AMBIGUOUS_MEMORY_METHODS:
        framework, required_imports = AMBIGUOUS_MEMORY_METHODS[method_name]
        
        # 没有 import 信息时，保守处理：不触发（避免 FP）
        if file_imports is None:
            return (False, "")
        
        # 检查是否有匹配的 import
        imports_str = ' '.join(file_imports).lower().replace('-', '_')
        if any(req.replace('-', '_') in imports_str for req in required_imports):
            return (True, framework)
        
        # 没有对应 import，跳过
        return (False, "")
    
    return (False, "")


def is_definitely_not_memory(method_name: str) -> bool:
    """检查是否肯定是 Python 内置方法"""
    return method_name in PYTHON_BUILTIN_METHODS


def get_memory_method_info(method_name: str) -> Optional[str]:
    """获取方法的框架信息"""
    if method_name in UNAMBIGUOUS_MEMORY_METHODS:
        return UNAMBIGUOUS_MEMORY_METHODS[method_name]
    if method_name in AMBIGUOUS_MEMORY_METHODS:
        return AMBIGUOUS_MEMORY_METHODS[method_name][0]
    return None
```

### Step 1.2: 修改 python_scanner.py 调用

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

找到 `_check_memory_poisoning` 方法，修改 `is_agent_memory_method` 调用：

```python
def _check_memory_poisoning(self, node: ast.Call) -> Optional[Dict[str, Any]]:
    # ... 现有代码 ...
    
    method_name = func_name.split('.')[-1] if '.' in func_name else func_name
    
    # === v0.12.0: 传入 imports 用于歧义方法检查 ===
    is_memory, framework = is_agent_memory_method(
        method_name,
        file_imports=set(self.imports),  # 新增
    )
    if not is_memory:
        return None
    
    # ... 后续代码保持不变 ...
```

### Step 1.3: 添加测试

**文件**: `packages/audit/tests/test_analysis/test_memory_method_detector.py`

添加新测试：

```python
class TestAmbiguousMethodsWithImport:
    """测试有歧义方法的 import 检查"""
    
    def test_insert_without_llama_index_import(self):
        """list.insert() 不应触发（无 llama_index import）"""
        is_mem, _ = is_agent_memory_method('insert', file_imports={'os', 'sys'})
        assert is_mem is False
    
    def test_insert_with_llama_index_import(self):
        """index.insert() 应触发（有 llama_index import）"""
        is_mem, fw = is_agent_memory_method('insert', file_imports={'llama_index'})
        assert is_mem is True
        assert fw == 'llama_index'
    
    def test_insert_with_llama_index_submodule(self):
        """从子模块 import 也应触发"""
        is_mem, _ = is_agent_memory_method(
            'insert', 
            file_imports={'llama_index.core', 'llama_index.embeddings'}
        )
        assert is_mem is True
    
    def test_insert_without_imports(self):
        """无 import 信息时保守处理（不触发）"""
        is_mem, _ = is_agent_memory_method('insert', file_imports=None)
        assert is_mem is False
    
    def test_upsert_with_pinecone(self):
        """pinecone.upsert() 应触发"""
        is_mem, fw = is_agent_memory_method('upsert', file_imports={'pinecone'})
        assert is_mem is True
        assert fw == 'vector_store'
    
    def test_upsert_without_vector_db(self):
        """无向量数据库 import 时不触发"""
        is_mem, _ = is_agent_memory_method('upsert', file_imports={'pandas', 'numpy'})
        assert is_mem is False
```

---

## Phase 2: 扩展 OpenAI Function Calling 识别

### 问题

当前 `is_tool_entry_point()` 只识别 @tool 装饰器和 Tool 基类。

像 Generative Agents 这样直接用 OpenAI API 的项目，Tool 函数不会被识别。

### 解决方案

识别 OpenAI function calling 模式：函数被传给 `tools=[...]` 参数。

### Step 2.1: 扩展 tool_boundary_detector.py

**文件**: `packages/audit/agent_audit/analysis/tool_boundary_detector.py`

添加 OpenAI function calling 识别：

```python
"""
Tool Boundary Detection for AGENT-034.

v0.12.0: 新增 OpenAI function calling 识别。
"""

from __future__ import annotations
import ast
from dataclasses import dataclass, field
from typing import Optional, Set, List

# ... 保留原有 TOOL_DECORATORS, TOOL_CLASS_METHODS, TOOL_BASE_CLASSES ...

# v0.12.0: Function Calling API 调用模式
FUNCTION_CALLING_API_PATTERNS: Set[str] = {
    'chat.completions.create',
    'ChatCompletion.create',
    'completions.create',
    'messages.create',  # Anthropic
}

# v0.12.0: Function Calling 装饰器
FUNCTION_CALLING_DECORATORS: Set[str] = {
    'function_schema',
    'openai_function',
    'tool_function',
    'function_def',
    'tool_def',
}


@dataclass
class FileToolContext:
    """文件级 Tool 上下文 (v0.12.0)"""
    has_openai_import: bool = False
    has_anthropic_import: bool = False
    has_function_calling_api: bool = False
    registered_tool_functions: Set[str] = field(default_factory=set)


@dataclass
class ToolBoundaryResult:
    """Tool 边界检测结果"""
    is_tool_entry: bool
    reason: str
    confidence: float
    tool_type: Optional[str] = None


def analyze_file_tool_context(
    tree: ast.AST,
    imports: Set[str],
) -> FileToolContext:
    """
    分析文件的 Tool 上下文 (v0.12.0)。
    
    识别 OpenAI/Anthropic function calling 模式。
    """
    ctx = FileToolContext()
    
    # 检查 OpenAI/Anthropic import
    imports_str = ' '.join(imports).lower()
    ctx.has_openai_import = 'openai' in imports_str
    ctx.has_anthropic_import = 'anthropic' in imports_str
    
    # 遍历 AST 查找 function calling API 调用
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if call_name and _is_function_calling_api(call_name):
                ctx.has_function_calling_api = True
                _extract_registered_tools(node, ctx)
    
    return ctx


def _is_function_calling_api(call_name: str) -> bool:
    """检查是否是 function calling API"""
    return any(pattern in call_name for pattern in FUNCTION_CALLING_API_PATTERNS)


def _extract_registered_tools(call_node: ast.Call, ctx: FileToolContext):
    """从 API 调用中提取注册的 tool 函数名"""
    for keyword in call_node.keywords:
        if keyword.arg in ('tools', 'functions'):
            _extract_tool_names_from_arg(keyword.value, ctx)


def _extract_tool_names_from_arg(node: ast.expr, ctx: FileToolContext):
    """从参数值中提取 tool 函数名"""
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


def _extract_from_dict(node: ast.Dict, ctx: FileToolContext):
    """从字典中提取函数名"""
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
    检查函数是否为 Tool 入口点。
    
    v0.12.0: 新增 OpenAI function calling 识别。
    """
    # Check 1: @tool 装饰器
    for decorator in node.decorator_list:
        dec_name = _get_decorator_name(decorator)
        if dec_name in TOOL_DECORATORS:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"@{dec_name} decorator",
                confidence=0.95,
                tool_type='decorator'
            )
        # v0.12.0: function calling 装饰器
        if dec_name in FUNCTION_CALLING_DECORATORS:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"@{dec_name} function calling decorator",
                confidence=0.90,
                tool_type='function_calling_decorator'
            )
    
    # Check 2: Tool 类方法
    if parent_class and parent_bases:
        if node.name in TOOL_CLASS_METHODS:
            if parent_bases & TOOL_BASE_CLASSES:
                return ToolBoundaryResult(
                    is_tool_entry=True,
                    reason=f"{parent_class}.{node.name}() in Tool class",
                    confidence=0.90,
                    tool_type='class_method'
                )
    
    # Check 3: 函数名 heuristic
    if 'tool' in node.name.lower():
        if _has_str_params(node):
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"Name heuristic: {node.name}",
                confidence=0.60,
                tool_type='name_heuristic'
            )
    
    # Check 4: OpenAI function calling 模式 (v0.12.0)
    if file_context and file_context.has_function_calling_api:
        if node.name in file_context.registered_tool_functions:
            return ToolBoundaryResult(
                is_tool_entry=True,
                reason=f"OpenAI function calling: {node.name}",
                confidence=0.85,
                tool_type='openai_function'
            )
    
    # NOT a Tool entry point
    return ToolBoundaryResult(
        is_tool_entry=False,
        reason="Not a Tool entry point",
        confidence=0.0,
        tool_type=None
    )


def _get_call_name(node: ast.Call) -> Optional[str]:
    """从 Call 节点提取函数名"""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return '.'.join(parts)
    return None


# ... 保留原有 _get_decorator_name, _has_str_params 等函数 ...
```

### Step 2.2: 修改 python_scanner.py

**文件**: `packages/audit/agent_audit/scanners/python_scanner.py`

1. 导入新函数：
```python
from agent_audit.analysis.tool_boundary_detector import (
    is_tool_entry_point,
    analyze_file_tool_context,
    FileToolContext,
)
```

2. 在 `PythonScanner.__init__` 添加：
```python
self._file_tool_context: Optional[FileToolContext] = None
```

3. 添加或修改 `visit_Module`：
```python
def visit_Module(self, node: ast.Module):
    """模块入口 - v0.12.0: 分析文件级 Tool 上下文"""
    self._file_tool_context = analyze_file_tool_context(
        node, 
        set(self.imports)
    )
    self.generic_visit(node)
```

4. 修改 `_check_tool_no_input_validation`：
```python
def _check_tool_no_input_validation(self, node: ast.FunctionDef):
    # === v0.12.0: 传入 file_context ===
    boundary = is_tool_entry_point(
        node,
        parent_class=self._current_class,
        parent_bases=getattr(self, '_current_class_bases', None),
        file_context=self._file_tool_context,  # 新增
    )
    
    if not boundary.is_tool_entry:
        return None
    
    # ... 后续代码保持不变 ...
```

### Step 2.3: 添加测试

**文件**: `packages/audit/tests/test_analysis/test_tool_boundary_detector.py`

添加 OpenAI function calling 测试：

```python
class TestOpenAIFunctionCalling:
    """测试 OpenAI function calling 识别"""
    
    def test_function_registered_in_tools(self):
        """函数被传给 tools 参数应识别为 Tool 入口"""
        source = '''
import openai

def get_weather(location: str) -> str:
    return f"Weather in {location}"

client.chat.completions.create(
    model="gpt-4",
    tools=[get_weather],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})
        
        assert ctx.has_openai_import is True
        assert ctx.has_function_calling_api is True
        assert 'get_weather' in ctx.registered_tool_functions
    
    def test_function_not_in_tools(self):
        """未注册的函数不应识别为 Tool 入口"""
        source = '''
import openai

def helper():
    pass

def get_weather(location: str) -> str:
    return f"Weather in {location}"

client.chat.completions.create(
    model="gpt-4",
    tools=[get_weather],
)
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})
        
        assert 'get_weather' in ctx.registered_tool_functions
        assert 'helper' not in ctx.registered_tool_functions
    
    def test_tool_entry_with_file_context(self):
        """is_tool_entry_point 应识别 OpenAI function"""
        ctx = FileToolContext(
            has_openai_import=True,
            has_function_calling_api=True,
            registered_tool_functions={'get_weather'},
        )
        
        source = '''
def get_weather(location: str) -> str:
    return subprocess.run(location, shell=True)
'''
        tree = ast.parse(source)
        func_node = tree.body[0]
        
        result = is_tool_entry_point(func_node, file_context=ctx)
        assert result.is_tool_entry is True
        assert result.tool_type == 'openai_function'
    
    def test_no_function_calling_api(self):
        """没有 function calling API 调用时不识别"""
        source = '''
import openai

def my_func(x: str):
    return x
'''
        tree = ast.parse(source)
        ctx = analyze_file_tool_context(tree, {'openai'})
        
        assert ctx.has_openai_import is True
        assert ctx.has_function_calling_api is False
```

---

## Phase 3: 验证

### 运行测试

```bash
cd packages/audit
poetry run pytest tests/test_analysis/test_memory_method_detector.py -v
poetry run pytest tests/test_analysis/test_tool_boundary_detector.py -v
poetry run pytest tests/ -v --tb=short
```

### 手动验证场景

**场景 1: list.insert() 不应触发**
```python
# 文件: test_list.py (无 llama_index import)
my_list = [1, 2, 3]
my_list.insert(0, 0)  # 不应触发 AGENT-018
```

**场景 2: index.insert() 应触发**
```python
# 文件: test_llama.py (有 llama_index import)
from llama_index import VectorStoreIndex
index = VectorStoreIndex()
index.insert(user_doc)  # 应触发 AGENT-018
```

**场景 3: OpenAI function + eval 应触发**
```python
# 文件: test_openai.py
import openai

def code_executor(code: str) -> str:
    return eval(code)  # 应触发 AGENT-034

client.chat.completions.create(tools=[code_executor])
```

### 更新版本

```bash
# version.py
__version__ = "0.12.0"

# pyproject.toml
version = "0.12.0"
```

---

## 关键约束

1. **Phase 1 和 Phase 2 相互独立** - 可以单独实施和测试
2. **保持向后兼容** - 不破坏现有检测能力
3. **保守处理歧义** - 无 import 信息时不触发（避免 FP）
4. **类型注解完整** - 所有新函数必须有类型注解

---

## 预期效果

| 场景 | v0.11.0 | v0.12.0 |
|------|---------|---------|
| `list.insert(0, item)` | 触发 FP | 不触发 ✓ |
| `index.insert(doc)` + llama_index | 触发 | 触发 ✓ |
| OpenAI function + eval | 不触发 | 触发 ✓ |
| @tool + subprocess | 触发 | 触发 ✓ |
