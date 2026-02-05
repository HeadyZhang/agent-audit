# agent-audit v0.5.0 改进版执行方案 & Claude Code Prompts

> **基于 Agent-Vuln-Bench Baseline + openclaw 实战数据 | 目标版本: v0.5.0**
> **日期: 2026-02-04**
> **前置状态: v0.4.1 已完成 (confidence/tier 字段, 3 FP 修复, Layer 1 F1=100%)**
> **核心目标: Recall 17.6% → 80%+; FP率 98% → <5%; 多语言 AST; 完整权限模型**

---

## 改进摘要：原方案 vs 改进方案

| 维度 | 原方案 (v050-plan) | 改进方案 (本文) | 改进原因 |
|------|-------------------|----------------|---------|
| 数据锚点 | 仅 openclaw 扫描数据 | + Agent-Vuln-Bench 7 样本定量 baseline | 有了精确的 Recall/Precision 数字 |
| v0.4.1 认知 | 未体现 | 明确标注已完成项,避免重复工作 | v0.4.1 已引入 confidence/tier |
| C1 范围 | tree-sitter + 置信度引擎 | + **JSON/YAML 扫描入口修复** (解决 Set B=0%) | KNOWN-003 暴露文件类型过滤 bug |
| C2 范围 | 仅 AGENT-004 语义化 | 拆分为 **C2a**(AGENT-004) + **C2b**(AGENT-034/026/037 扩展) | 3/4 benchmark gap 指向触发范围过窄 |
| C5 验收 | openclaw + Layer 1 回归 | + **Agent-Vuln-Bench 复测** (硬性 Recall≥60%) | benchmark 是唯一可量化验收标准 |
| Prompt 数量 | 6 个 (C1-C6) | **7 个** (C1, C2a, C2b, C3, C4, C5, C6) | C2 拆分降低单 Prompt 复杂度 |
| 每个 Prompt | 无数据锚点 | 每个标注"预期使 KNOWN/WILD-XXX 通过" | 可追溯改动到 benchmark 效果 |

---

## 第一部分：当前状态全景

### 1.1 v0.4.1 已完成项（不要重复实现）

| 已完成 | 位置 | 状态 |
|--------|------|------|
| Finding 模型 confidence: float = 1.0 | Finding/Result 类 | ✅ 已合并 |
| Finding 模型 tier: str = "BLOCK" | Finding/Result 类 | ✅ 已合并 |
| confidence_to_tier() 辅助函数 | analysis 或 utils | ✅ 已合并 |
| FP-1: AGENT-026 URL 白名单 → 0.20 | 规则逻辑 | ✅ 已修复 |
| FP-2: AGENT-034 ast.literal_eval → 0.10 | 规则逻辑 | ✅ 已修复 |
| FP-3: AGENT-034 参数化 SQL → 0.10 | 规则逻辑 | ✅ 已修复 |
| Layer 1 Benchmark: F1=100% (393 tests) | tests/ | ✅ 通过 |

### 1.2 Agent-Vuln-Bench Baseline（v0.4.1 当前能力）

```
┌───────────────────────┬────────┬─────────────┬──────────────────────────┐
│       指标            │ 当前值 │ v0.5.0 目标 │ 哪些 Prompt 解决         │
├───────────────────────┼────────┼─────────────┼──────────────────────────┤
│ Overall Recall        │ 17.6%  │ ≥80%        │ C2a + C2b 主力           │
│ Set A Recall (Inject) │ 33.3%  │ ≥90%        │ C2b (034/026 扩展)       │
│ Set B Recall (MCP)    │ 0.0%   │ ≥90%        │ C1 (JSON 扫描入口修复)   │
│ Set C Recall (Data)   │ 0.0%   │ ≥70%        │ C2a (004 格式扩充)       │
│ Taint Accuracy        │ 0.0%   │ ≥30%        │ C2b (taint 追踪初步)     │
│ Precision             │ 100%   │ ≥85%        │ C2a (confidence 引擎)    │
│ openclaw FP 率        │ 98%    │ <5%         │ C1 + C2a                 │
│ openclaw 安全面覆盖   │ 1/7    │ ≥5/7        │ C3 (权限规则)            │
└───────────────────────┴────────┴─────────────┴──────────────────────────┘
```

### 1.3 Benchmark 暴露的 4 个 Gap → Prompt 映射

| Gap | 样本 | 根因 | 解决 Prompt | 预期效果 |
|-----|------|------|-------------|---------|
| eval/exec 仅 @tool 内检测 | KNOWN-001, KNOWN-002, WILD-001 | AGENT-034 触发条件过窄 | **C2b** | Set A: 33%→100% |
| MCP JSON 被跳过 | KNOWN-003 | 扫描器文件类型过滤 | **C1** | Set B: 0%→100% |
| 凭证格式不完整 | KNOWN-004 | sk-proj- 等未覆盖 | **C2a** | Set C: 0%→100% |
| SSRF 仅 @tool 内检测 | WILD-002 | AGENT-026/037 触发条件过窄 | **C2b** | WILD 通过率提升 |

**根因洞察**: 4 个 gap 中有 3 个（eval/exec、SSRF、MCP）指向同一根因——规则只在 `@tool` 装饰器上下文触发。v0.5.0 的 confidence 引擎解决扩大范围 vs 控噪的矛盾：**在非 @tool 上下文也触发，但给较低 confidence**。

---

## 第二部分：改进架构方案

### 2.1 检测范围扩展策略（新增）

```
v0.4.1 (当前)                          v0.5.0 (改进)
┌─────────────────────┐                ┌──────────────────────────────┐
│ 规则触发区域:       │                │ 规则触发区域:                │
│ ┌───────────────┐   │                │ ┌───────────────────────┐    │
│ │ @tool 装饰器  │←── 100% 检测       │ │ Tier 1: @tool 上下文  │←── conf=0.95  │
│ │ 上下文内部    │   │                │ │ (保持原有高置信度)     │    │
│ └───────────────┘   │                │ ├───────────────────────┤    │
│                     │                │ │ Tier 2: Agent 入口     │←── conf=0.75  │
│ ❌ 其他上下文       │                │ │ (main, handler, route) │    │
│    完全不检测        │                │ ├───────────────────────┤    │
│                     │                │ │ Tier 3: 任意代码       │←── conf=0.55  │
│                     │                │ │ (eval/exec/spawn 等)   │    │
│                     │                │ └───────────────────────┘    │
└─────────────────────┘                └──────────────────────────────┘

关键设计: 范围扩大 3 倍，但通过 confidence 分层保持 Precision
```

### 2.2 JSON/YAML 扫描入口修复（新增）

```
v0.4.1 问题:
  file_discovery → filter_by_extension(.py, .json, .yaml) → scanners
                                                ↑
  问题: 独立 .json 文件传给了 config_scanner，但 MCP 规则 (029-033)
        只在 mcp_scanner 中检测。config_scanner 不识别 MCP 模式。
  
  另一个问题: mcp_scanner 可能只扫描特定文件名 (mcp.json, claude_desktop_config.json)

v0.5.0 修复:
  file_discovery → 文件路由:
    *.py           → python_scanner
    *.ts/*.js      → ts_scanner (新增)
    *.json/*.yaml  → config_scanner + mcp_scanner (并行)  ← 修复点
    *.md           → secret_scanner + privilege_scanner
    *.sh           → privilege_scanner + secret_scanner
  
  mcp_scanner 扩展: 不仅扫描 mcp.json，还扫描:
    - 任何包含 "mcpServers" 键的 JSON 文件
    - claude_desktop_config.json
    - .cursor/mcp.json
    - 任何 YAML 中包含 mcp 相关配置的文件
```

### 2.3 总体架构（保留原方案，增加标注）

```
v0.5.0 架构
┌───────────────────────────────────────────────┐
│  File Discovery v2                            │
│  .py .ts .js .json .yaml .md .sh              │
│  ★ 修复: JSON 路由到 mcp_scanner (C1)         │
└───────────────────────┬───────────────────────┘
                        │
┌───────────────────────▼───────────────────────┐
│  Multi-Language AST Engine                    │
│  ├ python_ast (existing)                      │
│  ├ tree_sitter_ts (NEW, C1)                   │
│  ├ tree_sitter_js (NEW, C1)                   │
│  ├ config_json (existing)                     │
│  ├ mcp_scanner (existing, ★路由修复 C1)       │
│  ├ secret_semantic (REDESIGNED, C2a)          │
│  ├ privilege_scanner (NEW, C3)                │
│  └ ★ expanded_rules (C2b):                    │
│      AGENT-034 eval/exec 扩展触发范围         │
│      AGENT-026/037 SSRF 扩展触发范围          │
└───────────────────────┬───────────────────────┘
                        │
┌───────────────────────▼───────────────────────┐
│  Confidence Analysis Engine                   │
│  ★ v0.4.1 已有 confidence_to_tier()          │
│  ★ C1 新增: entropy + placeholder + value     │
│  ├ context_aware_confidence (C2b):            │
│  │  @tool上下文=0.95, Agent入口=0.75, 其他=0.55│
│  └ file_type_multiplier (C2a)                 │
└───────────────────────┬───────────────────────┘
                        │
┌───────────────────────▼───────────────────────┐
│  Tiered Reporter (C4)                         │
│  BLOCK(≥0.90) | WARN(≥0.60) | INFO(≥0.30)   │
│  Confidence-weighted Risk Score               │
└───────────────────────────────────────────────┘
```

---

## 第三部分：改进 Prompt 执行计划

### 3.1 执行顺序和依赖

```
C1 (基础设施 + 入口修复)──────┬──→ C2b (034/026/037 扩展)──┐
                              │                             │
C2a (AGENT-004 语义化)────────┤                             ├→ C5 (验证)→ C6 (文档)
                              │                             │
C3 (权限规则 043-048)─────────┤──→ C4 (分层报告)───────────┘
                              │
                              └── 所有依赖 C1 的 tree-sitter 和 confidence 模块

执行顺序: C1 → C2a → C2b → C3 → C4 → C5 → C6 (严格顺序)
```

### 3.2 各 Prompt 的 Benchmark 锚点

| Prompt | 目标 | 预期使通过的样本 | Recall 增量 |
|--------|------|-----------------|-------------|
| C1 | tree-sitter + 入口修复 | **KNOWN-003** (MCP JSON) | Set B: 0%→100% (+1/7) |
| C2a | AGENT-004 语义化 | **KNOWN-004** (凭证格式) | Set C: 0%→100% (+1/7) |
| C2b | 034/026/037 扩展 | **KNOWN-001, KNOWN-002, KNOWN-005, WILD-001, WILD-002** | Set A: 33%→100% (+4/7) |
| C3 | 权限规则 | openclaw 安全面 (无 benchmark 样本) | 不影响 bench Recall |
| C4 | 报告层 | 不影响检测 | 不影响 Recall |
| C5 | 验证 | 全部复测 | 确认 ≥80% |

**预期最终 Recall: 7/7 = 100% (目标 ≥80%，有余量)**

---

## 第四部分：完整 Claude Code Prompts

---

### Prompt C1: tree-sitter 基础设施 + JSON 扫描入口修复 + 置信度分析模块

```markdown
# 角色
你是 agent-audit 的核心架构师。你正在为这个 AI Agent 安全扫描工具添加多语言 AST 支持
并修复 JSON 文件扫描入口问题。

# 背景
agent-audit 当前状态 (v0.4.1):
- 已有 39 条规则 (AGENT-001~042), Python AST 分析
- Finding 模型已有 confidence: float = 1.0 和 tier: str = "BLOCK" 字段
- 已有 confidence_to_tier() 辅助函数
- Layer 1 Benchmark: F1=100% (393 tests)

两个 P0 问题需要本 Prompt 解决:
1. **GAP-1**: TypeScript 项目无 AST 级检测，对 TS 退化为 grep (导致 98% 误报)
2. **Benchmark GAP**: Agent-Vuln-Bench KNOWN-003 (MCP 配置过度权限) 漏报，
   根因: 独立 .json 文件未正确路由到 mcp_scanner

# 任务 (按顺序执行)

## 第一步: 深入了解现有代码结构

```bash
# 1. 项目整体结构
find . -name "*.py" -path "*/agent_audit/*" | head -40
cat agent_audit/__init__.py

# 2. 扫描入口 — 理解文件发现和路由逻辑
grep -rn "def scan\|file_discovery\|glob\|walk\|Path.*rglob\|\.json\|\.yaml\|\.yml" \
    agent_audit/ --include="*.py" | head -30

# 3. MCP 扫描器 — 理解它如何被调用
grep -rn "mcp_scanner\|mcp.*scan\|mcpServers\|MCP" \
    agent_audit/ --include="*.py" -l
# 逐个读取这些文件

# 4. 现有 Python AST 扫描器接口
grep -rn "class.*Scanner\|def scan\|def analyze\|def check" \
    agent_audit/ --include="*.py" | head -20

# 5. Finding 数据模型（v0.4.1 已添加 confidence/tier）
grep -rn "class Finding\|class Result\|confidence\|tier\|dataclass" \
    agent_audit/ --include="*.py" | head -20

# 6. 现有 confidence_to_tier 实现
grep -rn "confidence_to_tier\|def.*tier\|BLOCK\|WARN\|INFO\|SUPPRESSED" \
    agent_audit/ --include="*.py" | head -20

# 7. AGENT-004 当前实现
grep -rn "AGENT.004\|hardcoded.*credential\|secret.*scan\|credential" \
    agent_audit/ --include="*.py" -l
```

**先完成所有读取，彻底理解现有架构后再开始编码。**

## 第二步: 修复 JSON/YAML 扫描入口路由

**Benchmark 锚点: 修复此 gap 预期使 KNOWN-003 (MCP 配置过度权限) 通过，
Set B Recall 0% → 100%**

查找文件发现/路由逻辑，确保:

1. `.json` 文件同时路由到 `config_scanner` 和 `mcp_scanner`
2. `mcp_scanner` 不仅识别 `mcp.json` / `claude_desktop_config.json`，
   还识别**任何包含 `mcpServers` 键**的 JSON 文件
3. `.yaml`/`.yml` 同理

```python
# 伪代码 — 适配到现有代码结构
def route_file(file_path: str, content: str) -> list[str]:
    """确定哪些 scanner 应该处理这个文件"""
    ext = Path(file_path).suffix.lower()
    scanners = []
    
    if ext == ".py":
        scanners.append("python_scanner")
    elif ext in (".ts", ".tsx", ".js", ".jsx"):
        scanners.append("ts_scanner")  # 新增
    elif ext in (".json", ".yaml", ".yml"):
        scanners.append("config_scanner")
        # 关键修复: JSON/YAML 也经过 mcp_scanner
        if looks_like_mcp_config(content):
            scanners.append("mcp_scanner")
        else:
            scanners.append("mcp_scanner")  # 保守起见都走一遍
    elif ext in (".md", ".rst", ".txt"):
        scanners.append("secret_scanner")
    elif ext in (".sh", ".bash"):
        scanners.append("privilege_scanner")
    
    # 所有文件都走 secret_scanner (用于 AGENT-004)
    if "secret_scanner" not in scanners:
        scanners.append("secret_scanner")
    
    return scanners

def looks_like_mcp_config(content: str) -> bool:
    """快速判断 JSON/YAML 是否包含 MCP 配置"""
    return any(kw in content for kw in [
        "mcpServers", "mcp_servers", "MCPServers",
        '"command"', '"args"', "tool_servers",
    ])
```

**验证**: 创建一个测试用 MCP JSON 文件并确认能被扫描到:
```python
# tests/test_mcp_routing.py
def test_standalone_mcp_json_scanned():
    """独立 MCP JSON 文件应被 mcp_scanner 处理"""
    mcp_json = '''{
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
            }
        }
    }'''
    # 写入临时文件并扫描
    findings = scan_file("mcp_config.json", mcp_json)
    # 应该触发 MCP 相关规则 (AGENT-029~033)
    assert any(f.rule_id.startswith("AGENT-0") for f in findings), \
        "KNOWN-003 fix: standalone MCP JSON must be scanned"
```

## 第三步: 安装 tree-sitter

```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript --break-system-packages
```

验证安装:
```python
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Parser
print("tree-sitter installed successfully")
```

如果安装失败，尝试:
```bash
pip install tree-sitter==0.22.3 --break-system-packages
pip install tree-sitter-languages --break-system-packages  # 备选
```

## 第四步: 创建 tree-sitter 解析器封装

创建 `agent_audit/parsers/treesitter_parser.py`:

```python
"""
统一的多语言 AST 解析器，基于 tree-sitter。

设计目标:
1. 对上层规则引擎暴露语言无关的查询接口
2. 支持 Python, TypeScript, JavaScript
3. 可扩展到更多语言

核心抽象:
- ValueType: 枚举 (LITERAL_STRING, FUNCTION_CALL, VARIABLE_REF, ENV_READ,
                    TYPE_DEFINITION, NONE_NULL, OTHER)
- Assignment: 赋值语句 {identifier, value_expr, value_type, line}
- FunctionCall: 函数调用 {callee, args, line}
- StringLiteral: 字符串字面量 {value, line}
"""
```

关键实现要求:

1. `parse(source: str, language: str) -> Tree`
   - language: "python" | "typescript" | "javascript"

2. `find_assignments(source, language) -> list[Assignment]`
   - **必须**区分 value_type:
     * `x = "hello"` → LITERAL_STRING
     * `x = getToken()` → FUNCTION_CALL
     * `x = other_var` → VARIABLE_REF
     * `x = process.env.KEY` / `os.environ["KEY"]` → ENV_READ
     * `password: z.string()` → TYPE_DEFINITION
     * `x = None` / `null` / `undefined` → NONE_NULL
   
   TypeScript 特有模式:
     * `const x = "value"` → VariableDeclaration → VariableDeclarator
     * `let x = funcCall()` → VariableDeclaration → CallExpression
     * `obj.property = "value"` → AssignmentExpression
     * `{ password: variable }` → Property(Identifier, Identifier) = VARIABLE_REF
     * `{ password: "literal" }` → Property(Identifier, StringLiteral) = LITERAL_STRING
     * `z.string().optional()` → CallExpression(MemberExpression) = TYPE_DEFINITION
     * `interface X { password: string }` → PropertySignature = TYPE_DEFINITION
     * `function isPasswordValid()` → FunctionDeclaration = 不是赋值

3. `find_string_literals(source, language) -> list[StringLiteral]`

4. `find_function_calls(source, language, pattern=None) -> list[FunctionCall]`
   - pattern 支持: "child_process.spawn", "exec*", "subprocess.*"

5. `get_node_context(node) -> str`
   - 返回: "function_declaration", "class_definition", "assignment",
     "type_annotation", "import", "comment"

## 第五步: 创建置信度分析模块

**注意**: v0.4.1 已有 confidence_to_tier()。本步骤创建的是**更底层的分析模块**。

创建 `agent_audit/analysis/entropy.py`:

```python
"""Shannon entropy 计算器"""
import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    """
    计算字符串的 Shannon entropy (bits per character)
    
    参考校准值:
    "password"              → 2.75  (低, 常见词)
    "YOUR_API_KEY_HERE"     → 3.47  (低, 占位符)
    "ghp_aBcDeFgH123456..." → 4.82  (高, 真实 token)
    "sk-proj-abc123xyz..."  → 5.04  (高, 真实 key)
    
    判定阈值:
    entropy < 3.5 且不匹配已知格式 → 大概率不是真实凭证
    entropy > 4.0 且长度 > 12      → 值得关注
    entropy > 4.5 且长度 > 16      → 高度可疑
    """
    if len(s) < 2:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
```

创建 `agent_audit/analysis/placeholder_detector.py`:

```python
"""占位符/示例值检测器"""
import re

PLACEHOLDER_PATTERNS = [
    r"YOUR_\w+_HERE",
    r"CHANGE.?ME",
    r"<your[_-]?\w+>",
    r"\[INSERT_\w+\]",
    r"TODO|FIXME|REPLACE|PLACEHOLDER",
    r"^xxx+$|^\*{3,}$|^\.{3,}$",
    r"^example|^dummy|^fake|^test[_-]|^sample",
    r"^sk-xxx|^ghp_xxx",
]

def is_placeholder(value: str) -> tuple[bool, float]:
    """
    返回 (is_placeholder, confidence_that_its_placeholder)
    confidence 高 = 更确定是占位符 = 更不可能是真实凭证
    
    示例:
    "YOUR_API_KEY_HERE"  → (True, 0.95)
    "change-me"          → (True, 0.85)
    "ghp_1234567890..."  → (False, 0.0)
    """
```

创建 `agent_audit/analysis/value_analyzer.py`:

```python
"""
赋值右值分析器 — AGENT-004 语义化的核心模块

输入: 一个候选 finding (identifier, value_expr, value_type, context)
输出: (should_report, confidence, reason)

设计: 与 C2a 配合使用，本 Prompt 只创建模块框架和工具函数，
C2a 负责完整的三阶段引擎集成。
"""

KNOWN_CREDENTIAL_FORMATS = [
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", 0.95),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", 0.95),
    (r"github_pat_[A-Za-z0-9_]{30,}", "GitHub Fine-grained PAT", 0.95),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API Key", 0.92),
    (r"sk-proj-[A-Za-z0-9-]{20,}", "OpenAI Project Key", 0.92),
    (r"sk-ant-[A-Za-z0-9-]{20,}", "Anthropic API Key", 0.92),
    (r"co-[A-Za-z0-9]{20,}", "Cohere API Key", 0.90),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", 0.95),
    (r"postgres(ql)?://\w+:[^@\s]+@", "PostgreSQL Connection String", 0.92),
    (r"mysql://\w+:[^@\s]+@", "MySQL Connection String", 0.92),
    (r"mongodb(\+srv)?://\w+:[^@\s]+@", "MongoDB Connection String", 0.92),
    (r"-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----", "Private Key", 0.95),
    (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.", "JWT Token", 0.85),
    (r"xox[bpars]-[A-Za-z0-9-]+", "Slack Token", 0.92),
    (r"Bearer\s+[A-Za-z0-9-_.]{20,}", "Bearer Token", 0.80),
]
# ★ 新增 sk-proj-, sk-ant-, co-* 等格式 — 解决 KNOWN-004 漏报
```

## 第六步: 测试

```python
# tests/test_treesitter_parser.py

def test_ts_assignment_literal():
    """TypeScript: const password = "real_secret_123" → LITERAL_STRING"""
    source = 'const password = "real_secret_123";'
    assignments = parser.find_assignments(source, "typescript")
    assert len(assignments) == 1
    assert assignments[0].value_type == ValueType.LITERAL_STRING

def test_ts_assignment_function_call():
    """TypeScript: const token = resolveToken(x) → FUNCTION_CALL"""
    source = "const token = resolveToken(account.token);"
    assignments = parser.find_assignments(source, "typescript")
    assert len(assignments) == 1
    assert assignments[0].value_type == ValueType.FUNCTION_CALL

def test_ts_assignment_env_read():
    """TypeScript: const secret = process.env.SECRET → ENV_READ"""
    source = "const secret = process.env.API_SECRET;"
    assignments = parser.find_assignments(source, "typescript")
    assert len(assignments) == 1
    assert assignments[0].value_type == ValueType.ENV_READ

def test_ts_schema_definition():
    """TypeScript: password: z.string().optional() → TYPE_DEFINITION"""
    source = 'const schema = z.object({ password: z.string().optional() });'
    assignments = parser.find_assignments(source, "typescript")
    pw = [a for a in assignments if a.identifier == "password"]
    assert len(pw) == 0 or pw[0].value_type == ValueType.TYPE_DEFINITION

def test_ts_function_name_not_assignment():
    """TypeScript: function isGatewayRestartAllowed() → 不是赋值"""
    source = "export function isGatewayRestartAllowed() { return true; }"
    assignments = parser.find_assignments(source, "typescript")
    pw = [a for a in assignments if "password" in a.identifier.lower()]
    assert len(pw) == 0

def test_ts_variable_ref():
    """TypeScript: { pass: password } → VARIABLE_REF"""
    source = "const config = { pass: password, user: username };"
    assignments = parser.find_assignments(source, "typescript")
    pass_a = [a for a in assignments if a.identifier == "pass"]
    if pass_a:
        assert pass_a[0].value_type == ValueType.VARIABLE_REF

def test_py_assignment_literal():
    """Python: API_KEY = "sk-1234..." → LITERAL_STRING"""
    source = 'API_KEY = "sk-1234abcdef"'
    assignments = parser.find_assignments(source, "python")
    assert len(assignments) == 1
    assert assignments[0].value_type == ValueType.LITERAL_STRING

def test_py_assignment_env():
    """Python: secret = os.environ["KEY"] → ENV_READ"""
    source = 'secret = os.environ["API_KEY"]'
    assignments = parser.find_assignments(source, "python")
    assert len(assignments) == 1
    assert assignments[0].value_type == ValueType.ENV_READ

# entropy 测试
def test_entropy_low():
    assert shannon_entropy("password") < 3.5

def test_entropy_high():
    assert shannon_entropy("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456") > 4.0

# placeholder 测试
def test_placeholder_detected():
    is_ph, conf = is_placeholder("YOUR_API_KEY_HERE")
    assert is_ph is True and conf > 0.8

def test_placeholder_real_token():
    is_ph, conf = is_placeholder("ghp_1234567890abcdef1234567890abcdef12")
    assert is_ph is False

# ★ JSON 路由测试 (Benchmark 锚点: KNOWN-003)
def test_mcp_json_routing():
    """独立 MCP JSON 文件必须被 mcp_scanner 处理"""
    content = '{"mcpServers": {"fs": {"command": "npx", "args": ["server-fs", "/"]}}}'
    # 验证路由逻辑包含 mcp_scanner
    scanners = route_file("project/mcp.json", content)
    assert "mcp_scanner" in scanners
```

## 约束

- 不修改任何现有文件的**公开接口**
- tree-sitter 解析器作为独立模块，现有 Python AST 扫描器继续工作
- ★ 不要重新实现 confidence_to_tier() — v0.4.1 已有
- ★ 不要修改 Finding 模型的 confidence/tier 字段定义 — v0.4.1 已有
- 所有新模块必须有类型注解 (typing)
- 如果 tree-sitter 安装遇到问题，记录具体错误并寻找替代方案

## 自验证清单

完成后请逐项确认:
□ tree-sitter 安装成功并能解析 Python/TypeScript/JavaScript
□ parser.find_assignments() 对三种语言正确分类 value_type
□ 8 个解析器测试全部通过
□ shannon_entropy 对 "password" 返回 < 3.5，对随机 token 返回 > 4.0
□ is_placeholder 正确识别 YOUR_*_HERE 等模式
□ ★ JSON 文件路由修复：包含 mcpServers 的 JSON 文件能被 mcp_scanner 处理
□ ★ 新增的 MCP 路由测试通过
□ 现有测试没有被破坏 (pytest tests/ 确认)
□ ★ 没有重复实现 v0.4.1 已有的 confidence_to_tier 和 Finding 字段
```

---

### Prompt C2a: AGENT-004 语义化重构 + 凭证格式扩充

```markdown
# 角色
你是 agent-audit 的安全工程师。你正在重构 AGENT-004 (Hardcoded Credentials) 规则，
从简单的关键词 grep 升级为三阶段语义分析引擎。

# 前置条件
Prompt C1 已完成。以下模块已就绪:
- `agent_audit/parsers/treesitter_parser.py` — 多语言 AST 解析器
- `agent_audit/analysis/entropy.py` — Shannon entropy 计算
- `agent_audit/analysis/placeholder_detector.py` — 占位符检测
- `agent_audit/analysis/value_analyzer.py` — 已知凭证格式 + 值分析框架
- JSON/YAML 扫描入口已修复

验证前置条件:
```bash
python -c "
from agent_audit.parsers.treesitter_parser import TreeSitterParser
from agent_audit.analysis.entropy import shannon_entropy
from agent_audit.analysis.placeholder_detector import is_placeholder
from agent_audit.analysis.value_analyzer import KNOWN_CREDENTIAL_FORMATS
print(f'C1 verified. {len(KNOWN_CREDENTIAL_FORMATS)} known formats loaded.')
"
```
如果任何导入失败，停止并报告。

# Benchmark 锚点
本 Prompt 修复: **KNOWN-004** (硬编码 API 密钥，sk-proj-/sk-ant- 格式)
预期效果: Set C Recall 0% → 100%
同时解决: openclaw 227 findings → ≤6 findings (98% FP → 0% FP in BLOCK+WARN)

# 背景: openclaw 误报数据

```
总 findings: 227 (全部 AGENT-004)
真阳性 (TP): 4 (postgres 连接串在 .md 文件中)
误报分布:
├── 变量名/类型声明碰撞 (~136, 60%) — value_type 非 LITERAL_STRING
├── 文档占位符 (~45, 20%) — YOUR_KEY_HERE 等
├── 环境变量读取 (~23, 10%) — process.env.X
├── 函数名碰撞 (~18, 8%) — isPasswordValid 等
└── 真正硬编码 (~4, 2%) — ✅
```

# 任务

## 第一步: 深度理解现有 AGENT-004

```bash
grep -rn "AGENT.004\|hardcoded.*credential\|HardcodedCredential\|secret_scan" \
    agent_audit/ --include="*.py" -l
# 逐个读取每个文件，理解:
# 1. 正则表达式
# 2. 匹配逻辑流程
# 3. 如何生成 Finding 对象
# 4. 已有的 FP 抑制逻辑（v0.4.1 可能已有一些）
```

## 第二步: 实现三阶段引擎

### Stage 1: 候选发现 (Candidate Discovery)

保留现有关键词扫描作为候选发现，但**不直接生成 findings**。
同时增加 Path B — 已知凭证格式的字符串字面量扫描。

```python
CREDENTIAL_KEYWORDS = [
    "password", "passwd", "pwd", "token", "secret", "api_key",
    "apikey", "api-key", "auth_token", "access_token", "private_key",
    "credential", "conn_str", "connection_string",
]
```

### Stage 2: 值分析 (Value Analysis)

对每个候选执行，使用 tree-sitter 解析器确定 value_type:

```python
def analyze_candidate(identifier, value_expr, value_type, context, file_path):
    """
    输入: 候选发现的各字段
    输出: (should_report: bool, confidence: float, reason: str)
    """
    # === 立即排除 (confidence = 0.0) ===
    if value_type == ValueType.FUNCTION_CALL:
        return (False, 0.0, "value is function call")
    if value_type == ValueType.VARIABLE_REF:
        return (False, 0.0, "value is variable reference")
    if value_type == ValueType.ENV_READ:
        return (False, 0.0, "value is environment variable read")
    if value_type == ValueType.TYPE_DEFINITION:
        return (False, 0.0, "value is type/schema definition")
    if value_type == ValueType.NONE_NULL:
        return (False, 0.0, "value is null/None/undefined")
    if context == "function_declaration":
        return (False, 0.0, "identifier is function name")
    if context == "import":
        return (False, 0.0, "identifier is in import path")

    # === 占位符检测 ===
    is_ph, ph_conf = is_placeholder(value_expr)
    if is_ph and ph_conf > 0.7:
        return (False, 0.15, f"placeholder detected: {ph_conf}")

    # 值等于标识符名 (password="password")
    if value_expr.lower().strip('"\'') == identifier.lower():
        return (False, 0.15, "value equals identifier name")

    # === 已知格式匹配 (★ 包含 sk-proj-, sk-ant-, co-*) ===
    for pattern, format_name, base_conf in KNOWN_CREDENTIAL_FORMATS:
        if re.search(pattern, value_expr):
            return (True, base_conf, f"matches known format: {format_name}")

    # === 高 Entropy 分析 ===
    if len(value_expr) > 8:
        ent = shannon_entropy(value_expr)
        if ent > 4.5 and len(value_expr) > 16:
            return (True, 0.75, f"high entropy: {ent:.2f}")
        if ent > 4.0 and len(value_expr) > 12:
            return (True, 0.55, f"moderate-high entropy: {ent:.2f}")

    # === 中等可疑 ===
    if value_type == ValueType.LITERAL_STRING and len(value_expr) >= 8:
        return (True, 0.40, "string literal assigned to secret-named identifier")

    # === 短字符串或低 entropy ===
    if len(value_expr) < 4:
        return (False, 0.10, "too short")
    
    return (False, 0.20, "low suspicion")
```

### Stage 3: 上下文调整 (Context Scoring)

```python
FILE_TYPE_MULTIPLIERS = {
    ".md": 0.85, ".rst": 0.85, ".txt": 0.85, ".adoc": 0.85,
}
TEST_PATH_PATTERNS = [
    r"/tests?/", r"/spec/", r"/fixtures?/", r"/__tests__/",
    r"/examples?/", r"/demos?/", r"/samples?/",
]
TEMPLATE_FILENAMES = [
    ".env.example", ".env.template", ".env.sample",
    "config.example.yaml", "config.sample.json",
]

def apply_context_adjustment(confidence, file_path):
    ext = Path(file_path).suffix.lower()
    if ext in FILE_TYPE_MULTIPLIERS:
        confidence *= FILE_TYPE_MULTIPLIERS[ext]
    for pattern in TEST_PATH_PATTERNS:
        if re.search(pattern, file_path):
            confidence *= 0.60
            break
    basename = Path(file_path).name.lower()
    if basename in TEMPLATE_FILENAMES:
        confidence *= 0.30
    return confidence
```

## 第三步: 集成到现有 AGENT-004

**重要: 包装而非替换现有代码。**

```python
# 新流程:
# keyword_match → candidate → value_analysis → context_adjust → tiered_finding
#
# 对 TS/JS 文件: 使用 tree-sitter 获取 value_type
# 对 Python 文件: 继续使用现有 Python AST (更精确)
# 对 .md/.sh/.yaml: 使用正则 + entropy 分析
```

## 第四步: 对 TS/JS 启用 AST 分析

```python
if file_ext in (".ts", ".tsx", ".js", ".jsx"):
    parser = TreeSitterParser()
    assignments = parser.find_assignments(content, language_from_ext(file_ext))
    # 对每个赋值执行 Stage 2 + Stage 3
elif file_ext == ".py":
    # 继续使用现有 Python AST
else:
    # .md, .sh, .yaml — 使用正则 + entropy
```

## 第五步: 测试

```python
# tests/test_agent004_semantic.py

class TestAGENT004Semantic:
    """AGENT-004 语义化重构测试"""

    # === 误报排除 (8个) ===

    def test_fp_function_call(self):
        """变量来自函数调用 → SUPPRESSED"""
        source = 'const token = resolveToken(account.token);'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    def test_fp_schema_definition(self):
        """Zod schema 定义 → SUPPRESSED"""
        source = 'const s = z.object({ password: z.string().optional() });'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    def test_fp_variable_passing(self):
        """对象字面量传递变量 → SUPPRESSED"""
        source = 'const cfg = { pass: password, user: username };'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    def test_fp_env_read(self):
        """环境变量读取 → SUPPRESSED"""
        source = 'const secret = process.env.API_SECRET;'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    def test_fp_function_name(self):
        """函数名碰撞 → SUPPRESSED"""
        source = 'export function isGatewayRestartAllowed() { return true; }'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    def test_fp_placeholder(self):
        """文档占位符 → SUPPRESSED 或最多 INFO"""
        source = 'apiKey: "YOUR_API_KEY_HERE"'
        findings = scan_source(source, "example.md")
        if findings:
            assert all(f.confidence < 0.30 for f in findings)

    def test_fp_value_equals_name(self):
        """值等于标识符名 → SUPPRESSED"""
        source = 'password = "password"'
        findings = scan_source(source, "test.py")
        if findings:
            assert all(f.confidence < 0.30 for f in findings)

    def test_fp_null_assignment(self):
        """赋值为 null → SUPPRESSED"""
        source = 'let token: string | null = null;'
        findings = scan_source(source, "test.ts")
        assert len(findings) == 0

    # === 真正漏洞检出 (6个) ===

    def test_tp_postgres_connection_string(self):
        """Postgres 连接串含密码 → HIGH+"""
        source = 'POSTGRES_URL=postgres://admin:real_pass_123@localhost:5432/db'
        findings = scan_source(source, "config.md")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.60

    def test_tp_openai_key(self):
        """硬编码 OpenAI Key → CRITICAL"""
        source = 'API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"'
        findings = scan_source(source, "config.py")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85

    def test_tp_anthropic_key(self):
        """★ 硬编码 Anthropic Key → CRITICAL (Benchmark 锚点: KNOWN-004)"""
        source = 'ANTHROPIC_KEY = "sk-ant-api03-1234567890abcdefghijklmnop"'
        findings = scan_source(source, "config.py")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85

    def test_tp_github_token(self):
        """硬编码 GitHub Token → CRITICAL"""
        source = 'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        findings = scan_source(source, "deploy.py")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85

    def test_tp_aws_key(self):
        """硬编码 AWS Access Key → CRITICAL"""
        source = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_source(source, "aws.py")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85

    def test_tp_high_entropy_secret(self):
        """高 entropy 字符串赋值给 secret → HIGH"""
        source = 'secret = "aB3xQ9mK7pL2nR5tY8wE4jF6hG1iD0"'
        findings = scan_source(source, "app.py")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.50
```

## 约束

- **不破坏其他规则 (AGENT-001~003, AGENT-005~042)**
- **向后兼容**: Finding 模型的 confidence/tier 已有默认值 (v0.4.1)
- **对 Python 文件**: 可继续用现有 Python AST，tree-sitter 是 TS/JS 补充
- **性能**: 解析器延迟加载 (lazy init)
- ★ **凭证格式必须包含 sk-proj-, sk-ant-, co-* ** (解决 KNOWN-004)

## 自验证

```bash
# 1. 新测试
pytest tests/test_agent004_semantic.py -v

# 2. 现有测试不破坏
pytest tests/ -v --tb=short

# 3. 语义检查
python -c "
# 这行不应该产生 finding (FP)
results = scan_for_credentials('test.ts', 'const token = resolveToken(account.token);')
print(f'FP test: {len(results)} findings (should be 0)')

# 这行应该产生 finding (TP) — ★ KNOWN-004 锚点
results = scan_for_credentials('test.py', 'API_KEY = \"sk-ant-api03-1234567890abcdef\"')
print(f'TP test (sk-ant-): {len(results)} findings (should be >= 1)')

# 这行应该产生 finding (TP)
results = scan_for_credentials('test.py', 'API_KEY = \"sk-proj-1234567890abcdef\"')
print(f'TP test (sk-proj-): {len(results)} findings (should be >= 1)')
"
```
```

---

### Prompt C2b: AGENT-034/026/037 检测范围扩展

```markdown
# 角色
你是 agent-audit 的安全工程师。你正在扩展三条核心规则的检测范围，
解决 Agent-Vuln-Bench 暴露的"规则只在 @tool 上下文触发"问题。

# 前置条件
Prompt C1 和 C2a 已完成。

验证:
```bash
python -c "
from agent_audit.parsers.treesitter_parser import TreeSitterParser
from agent_audit.analysis.entropy import shannon_entropy
print('C1+C2a prerequisites verified.')
"
# 同时验证现有测试通过
pytest tests/ -v --tb=line -q
```

# Benchmark 锚点
本 Prompt 修复:
- **KNOWN-001** (CVE-2023-29374, LangChain eval 注入) → AGENT-034 扩展
- **KNOWN-002** (CVE-2023-36258, PythonREPLTool exec) → AGENT-034 扩展
- **KNOWN-005** (Auto-GPT shell 执行) → AGENT-034/036 扩展
- **WILD-001** (Calculator tool eval) → AGENT-034 扩展
- **WILD-002** (Web fetcher SSRF) → AGENT-026/037 扩展

预期效果: Set A Recall 33.3% → 100%, Overall Recall 17.6% → ~86%+

# 根因分析

v0.4.1 的 AGENT-034 (unsafe_tool_construction)、AGENT-026 (tool_input_unsanitized)、
AGENT-037 (network_request_ssrf) 三条规则只在 `@tool` 装饰器上下文内触发。

但真实漏洞不局限于 @tool 装饰器:
- KNOWN-001: LangChain 的 `LLMMathChain` 内部调用 eval()，没有 @tool
- KNOWN-002: `PythonREPLTool.run()` 内部调用 exec()，不是标准 @tool 模式
- WILD-001: 自定义 Calculator 类的 calculate() 方法中 eval()，不是 @tool
- WILD-002: 自定义 fetch_url() 函数中 requests.get()，不是 @tool

**解决方案**: 使用 confidence 分层扩展检测范围:

```
@tool 上下文     → confidence = 0.90 (BLOCK)     ← 保持原有高置信度
Agent 入口上下文 → confidence = 0.75 (WARN)      ← 新增
任意代码上下文   → confidence = 0.55 (INFO/WARN)  ← 新增
```

# 任务

## 第一步: 理解现有三条规则

```bash
# 找到 AGENT-034, AGENT-026, AGENT-037 的实现
grep -rn "AGENT.034\|unsafe_tool\|AGENT.026\|unsanitized\|AGENT.037\|ssrf" \
    agent_audit/ --include="*.py" -l
# 逐个读取，理解:
# 1. 如何检测 @tool 装饰器
# 2. 如何检测 eval/exec/subprocess
# 3. 如何生成 Finding
# 4. 触发条件的具体代码
```

## 第二步: 定义上下文 confidence 分层

```python
# 新增: 上下文 confidence 映射
CONTEXT_CONFIDENCE = {
    "tool_decorator": 0.90,      # @tool, @langchain.tool, create_tool()
    "agent_framework": 0.85,     # AgentExecutor, BaseTool, ToolNode
    "handler_function": 0.75,    # def handle_*, async def process_*
    "main_entry": 0.70,          # if __name__ == "__main__", app.run()
    "class_method": 0.60,        # 类方法中的危险调用
    "standalone_function": 0.55, # 独立函数中的危险调用
    "module_level": 0.50,        # 模块顶层代码
}

def get_context_confidence(node_context: str, file_path: str) -> float:
    """
    根据代码上下文确定 confidence 基准值
    
    设计: 在 Agent 相关上下文中检测到的危险调用更可能是真正的漏洞，
    而在工具函数或通用代码中的相同调用可能是合法用途。
    """
```

## 第三步: 扩展 AGENT-034 (eval/exec 检测)

```python
# 当前: 只检测 @tool 装饰器内的 eval()/exec()
# 目标: 在所有上下文中检测，用 confidence 区分

# 需要检测的危险调用:
EVAL_EXEC_PATTERNS = {
    "python": [
        "eval", "exec", "compile",
        "os.system", "os.popen",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "__import__",
    ],
    "typescript": [
        "eval", "Function",
        "vm.runInNewContext", "vm.runInContext", "vm.runInThisContext",
        "child_process.exec", "child_process.execSync",
        "child_process.spawn", "child_process.spawnSync",
    ],
}

# 安全例外 (降低 confidence):
SAFE_EVAL_PATTERNS = [
    # ast.literal_eval — v0.4.1 已处理 (conf=0.10)
    "ast.literal_eval",
    # json.loads — 安全的反序列化
    "json.loads", "JSON.parse",
    # 参数化查询 — v0.4.1 已处理 (conf=0.10)
]

def check_eval_exec(source, file_path, language):
    """
    扩展后的 AGENT-034 检测逻辑
    
    ★ 关键变化: 不再要求 @tool 上下文
    ★ 新增: 对 TypeScript 的 eval/Function/vm.* 检测
    ★ confidence 根据上下文分层
    """
    findings = []
    
    if language in ("typescript", "javascript"):
        parser = TreeSitterParser()
        calls = parser.find_function_calls(source, language)
        for call in calls:
            if call.callee in EVAL_EXEC_PATTERNS.get(language, []):
                # 检查是否有安全例外
                if call.callee in SAFE_EVAL_PATTERNS:
                    continue
                
                # 获取上下文 confidence
                ctx = get_context_confidence(call.context, file_path)
                
                # 检查参数是否包含用户输入
                if has_user_input_arg(call):
                    ctx = min(ctx + 0.10, 0.95)
                
                findings.append(Finding(
                    rule_id="AGENT-034",
                    confidence=ctx,
                    tier=confidence_to_tier(ctx),
                    ...
                ))
    
    elif language == "python":
        # 扩展现有 Python AST 检测:
        # 1. 保留 @tool 上下文的高 confidence
        # 2. 新增: 非 @tool 上下文也检测，但 confidence 较低
        ...
    
    return findings
```

## 第四步: 扩展 AGENT-026 (tool_input_unsanitized) 和 AGENT-037 (SSRF)

```python
# AGENT-026: 扩展到非 @tool 上下文
# 原来: 只检测 @tool 函数中参数未校验直接使用
# 新增: 在 handler/route 函数中也检测参数未校验

# AGENT-037: 扩展到非 @tool 上下文
SSRF_PATTERNS = {
    "python": [
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "urllib.request.urlopen", "urllib.request.Request",
        "httpx.get", "httpx.post", "httpx.AsyncClient",
        "aiohttp.ClientSession",
    ],
    "typescript": [
        "fetch", "axios.get", "axios.post",
        "http.request", "https.request",
        "got", "node-fetch",
    ],
}

def check_ssrf(source, file_path, language):
    """
    扩展后的 AGENT-037 检测逻辑
    
    ★ 关键变化: 不再要求 @tool 上下文
    ★ 新增: TypeScript fetch/axios 检测
    
    confidence 逻辑:
    - URL 参数来自函数参数且未校验 → conf = context_base + 0.10
    - URL 参数是硬编码 → conf = 0.20 (SUPPRESSED，不是 SSRF)
    - URL 参数来自配置但有校验 → conf = 0.30 (INFO)
    """
```

## 第五步: 为 TypeScript 实现对等规则

对以下现有 Python 规则创建 TypeScript 等价检测:

| 规则 | Python 模式 | TypeScript 等价 | 优先级 |
|------|------------|----------------|--------|
| AGENT-034 | eval()/exec() | eval()/Function()/vm.* | ★ P0 |
| AGENT-035 | open()/os.path | fs.readFile/writeFile/path.join | P1 |
| AGENT-036 | subprocess.* | child_process.*/execSync/spawn | ★ P0 |
| AGENT-037 | requests.get() | fetch()/axios/http.request | ★ P0 |
| AGENT-039 | print()/logging | console.log()/logger.* | P2 |

至少实现 P0 标记的三条。

## 第六步: 测试

```python
# tests/test_expanded_rules.py

class TestExpandedRules:
    """规则扩展检测范围测试"""

    # === AGENT-034 扩展 ===
    
    def test_034_eval_in_tool_decorator(self):
        """★ 保持: @tool 内 eval → 高 confidence"""
        source = '''
from langchain.tools import tool

@tool
def calculator(expression: str) -> str:
    return str(eval(expression))
'''
        findings = scan_source(source, "calc.py")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1
        assert f034[0].confidence >= 0.85

    def test_034_eval_outside_tool(self):
        """★ 新增: 非 @tool eval → 中等 confidence (Benchmark: WILD-001)"""
        source = '''
class Calculator:
    def calculate(self, expression: str) -> float:
        return eval(expression)
'''
        findings = scan_source(source, "calculator.py")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1
        assert f034[0].confidence >= 0.50

    def test_034_exec_in_repl_tool(self):
        """★ Benchmark 锚点: KNOWN-002 (PythonREPLTool exec)"""
        source = '''
class PythonREPLTool:
    def run(self, command: str) -> str:
        exec(command)
        return "executed"
'''
        findings = scan_source(source, "repl.py")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1
        assert f034[0].confidence >= 0.55

    def test_034_langchain_eval_chain(self):
        """★ Benchmark 锚点: KNOWN-001 (LLMMathChain eval)"""
        source = '''
from langchain.chains import LLMMathChain
result = eval(llm_output)
'''
        findings = scan_source(source, "math_chain.py")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1

    def test_034_subprocess_in_autogpt(self):
        """★ Benchmark 锚点: KNOWN-005 (Auto-GPT shell)"""
        source = '''
import subprocess
def execute_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()
'''
        findings = scan_source(source, "commands.py")
        f034_or_036 = [f for f in findings if f.rule_id in ("AGENT-034", "AGENT-036")]
        assert len(f034_or_036) >= 1
        assert any(f.confidence >= 0.55 for f in f034_or_036)

    def test_034_safe_literal_eval(self):
        """保持: ast.literal_eval → SUPPRESSED (v0.4.1 已修复)"""
        source = '''
import ast
result = ast.literal_eval(user_input)
'''
        findings = scan_source(source, "safe.py")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        if f034:
            assert all(f.confidence < 0.30 for f in f034)

    # === AGENT-034 TypeScript ===
    
    def test_034_ts_eval(self):
        """★ TypeScript eval 检测"""
        source = 'function calc(expr: string) { return eval(expr); }'
        findings = scan_source(source, "calc.ts")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1

    def test_034_ts_function_constructor(self):
        """TypeScript new Function() 检测"""
        source = 'const fn = new Function("x", "return x * 2");'
        findings = scan_source(source, "dynamic.ts")
        f034 = [f for f in findings if f.rule_id == "AGENT-034"]
        assert len(f034) >= 1

    # === AGENT-037 扩展 ===
    
    def test_037_ssrf_outside_tool(self):
        """★ Benchmark 锚点: WILD-002 (非 @tool SSRF)"""
        source = '''
import requests
def fetch_url(url: str) -> str:
    response = requests.get(url)
    return response.text
'''
        findings = scan_source(source, "fetcher.py")
        f037 = [f for f in findings if f.rule_id == "AGENT-037"]
        assert len(f037) >= 1
        assert f037[0].confidence >= 0.50

    def test_037_ssrf_hardcoded_url(self):
        """硬编码 URL 不是 SSRF → 低 confidence"""
        source = '''
import requests
def get_status():
    return requests.get("https://api.example.com/health").status_code
'''
        findings = scan_source(source, "health.py")
        f037 = [f for f in findings if f.rule_id == "AGENT-037"]
        if f037:
            assert all(f.confidence < 0.40 for f in f037)

    # === AGENT-036 TypeScript ===
    
    def test_036_ts_child_process(self):
        """TypeScript child_process 检测"""
        source = '''
import { exec } from "child_process";
function run(cmd: string) { exec(cmd); }
'''
        findings = scan_source(source, "runner.ts")
        f036 = [f for f in findings if f.rule_id in ("AGENT-034", "AGENT-036")]
        assert len(f036) >= 1
```

## 约束

- **保持 @tool 上下文的高 confidence** — 不降低已有检测精度
- **不破坏 Layer 1 Benchmark** — 393 测试必须继续通过
- **confidence 分层是核心** — 扩大范围必须配合 confidence 降低，避免大量 FP 进入 WARN
- ★ **每条扩展的规则都要有对应的 benchmark 样本锚点**
- 对 build/deploy 脚本中的 subprocess 调用应降低 confidence (×0.5)

## 自验证

```bash
# 1. 新测试
pytest tests/test_expanded_rules.py -v

# 2. Layer 1 回归
pytest tests/ -v --tb=short -q

# 3. 关键 benchmark 锚点语义检查
python -c "
# KNOWN-001: eval outside @tool should be detected
source1 = 'result = eval(llm_output)'
r1 = scan_source(source1, 'chain.py')
print(f'KNOWN-001 (eval): {len(r1)} findings (need >= 1)')

# WILD-002: requests.get outside @tool should be detected
source2 = '''
import requests
def fetch(url): return requests.get(url).text
'''
r2 = scan_source(source2, 'fetcher.py')
print(f'WILD-002 (SSRF): {len(r2)} findings (need >= 1)')

# 安全代码不应被标记
source3 = 'result = ast.literal_eval(data)'
r3 = scan_source(source3, 'safe.py')
print(f'Safe eval: {len([f for f in r3 if f.confidence >= 0.60])} WARN+ (should be 0)')
"
```
```

---

### Prompt C3: 权限/特权检测规则 (AGENT-043~048)

```markdown
# 角色
你是 agent-audit 的安全规则开发者。你正在添加权限/特权检测规则。

# 前置条件
C1, C2a, C2b 已完成。tree-sitter 和 confidence 引擎就绪。

验证:
```bash
python -c "
from agent_audit.parsers.treesitter_parser import TreeSitterParser
print('Prerequisites verified.')
"
pytest tests/ -v --tb=line -q  # 确认无回归
```

# Benchmark 锚点
本 Prompt 主要解决 **openclaw 安全面覆盖** (1/7 → ≥5/7)。
Agent-Vuln-Bench 当前无对应样本，但这些规则覆盖 OWASP ASI-02/03/04/05/07/08/09。

# 任务

## 第一步: 理解现有规则注册方式

```bash
grep -rn "AGENT-025\|AGENT-034\|AGENT-036" agent_audit/ --include="*.py" -l
# 读取一个典型规则的完整实现
# 理解: 规则如何注册、如何被扫描器调用、如何产出 Finding
```

## 第二步: 创建 privilege_scanner.py

创建 `agent_audit/scanners/privilege_scanner.py`:

这个扫描器跨语言工作 (.ts/.js/.py/.sh/.md)，结合文件名、内容、AST 做综合判断。

## 第三步: 实现 6 条核心规则

### AGENT-043: daemon_privilege_escalation
- ASI: ASI-03 | 严重级别: HIGH
- 检测: 文件名含 daemon/service + 内容有 launchctl/systemctl/pm2 → 0.85
        仅 systemctl enable/start 在 shell 中 → 0.80
        仅文件名含 daemon 无实质内容 → 0.40 (INFO)
- 消息: "Agent runs as system daemon/service, gaining persistent elevated privileges"

### AGENT-044: sudoers_nopasswd_config
- ASI: ASI-03 | 严重级别: CRITICAL (.sh) / HIGH (.md)
- 检测: NOPASSWD + sudoers/visudo → 0.90
        文档中作为配置指引 → 0.75
        ALL=(ALL) ALL 模式 → 0.85
- 消息: "Configures or guides NOPASSWD sudoers entry"

### AGENT-045: browser_automation_unsandboxed
- ASI: ASI-02 | 严重级别: HIGH
- 检测 (需 tree-sitter TS AST):
  导入 chrome-remote-interface/playwright/puppeteer + page.evaluate → 0.85
  ws://devtools endpoint → 0.80
  --no-sandbox 标志 → 额外 +0.10
  仅截图等只读操作 → 0.50
- 消息: "Browser automation without sandbox"

### AGENT-046: system_credential_store_access
- ASI: ASI-05 | 严重级别: HIGH
- 检测: security find-generic-password / Keychain API → 0.85
        gnome-keyring / pass show → 0.80
        rbw get / 1password-cli → 0.75
- **关键区分**: 这不是 AGENT-004 (硬编码凭证)！
  readKeychainPassword() 是"程序访问系统凭证存储"，不是"代码里写死了密码"。
- 消息: "Agent accesses system credential store"

### AGENT-047: subprocess_execution_unsandboxed
- ASI: ASI-02/08 | 严重级别: HIGH (agent 代码) / MEDIUM (build 脚本)
- 检测: child_process.exec/spawn + 参数非硬编码 → 0.80
        subprocess.run + shell=True → 0.85
        降权: 在 scripts/build/ 目录 → ×0.50
        降权: 参数完全硬编码 → ×0.60
- 消息: "Agent executes subprocess without sandbox isolation"

### AGENT-048: extension_no_permission_boundary
- ASI: ASI-04/07 | 严重级别: HIGH
- 检测: 存在 extensions/ 或 plugins/ 目录 + 扩展代码直接 import core 模块 → 0.80
        扩展加载机制无权限声明 → 0.75
- 消息: "Extension/plugin system lacks permission boundaries"

## 第四步: 注册到扫描器主流程

确保 privilege_scanner:
1. 在文件发现阶段就知道要扫描 .ts/.js/.py/.sh/.md
2. 在现有扫描器之后运行
3. 输出带 confidence/tier 的 Finding

## 第五步: 测试

```python
# tests/test_privilege_rules.py

class TestPrivilegeRules:

    def test_043_daemon_launchctl(self):
        source = '''
        import { execSync } from "child_process";
        execSync("launchctl bootstrap system /Library/LaunchDaemons/com.app.plist");
        '''
        findings = scan_privilege(source, "gateway-daemon.ts")
        assert any(f.rule_id == "AGENT-043" for f in findings)

    def test_043_systemctl(self):
        source = "systemctl enable myapp.service && systemctl start myapp.service"
        findings = scan_privilege(source, "install.sh")
        assert any(f.rule_id == "AGENT-043" for f in findings)

    def test_044_sudoers_nopasswd(self):
        source = 'echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/app'
        findings = scan_privilege(source, "setup.sh")
        assert any(f.rule_id == "AGENT-044" and f.confidence >= 0.85 for f in findings)

    def test_045_cdp_browser(self):
        source = '''
        import CDP from "chrome-remote-interface";
        const { Runtime } = await CDP({ port: 9222 });
        await Runtime.evaluate({ expression: "document.title" });
        '''
        findings = scan_privilege(source, "browser.ts")
        assert any(f.rule_id == "AGENT-045" for f in findings)

    def test_046_keychain_access(self):
        source = '''
        const result = execSync('security find-generic-password -s "myapp" -w');
        '''
        findings = scan_privilege(source, "auth.ts")
        assert any(f.rule_id == "AGENT-046" for f in findings)
        # ★ 确保不被误报为 AGENT-004
        assert not any(f.rule_id == "AGENT-004" for f in findings)

    def test_047_subprocess_unsandboxed(self):
        source = '''
        import { spawn } from "child_process";
        const proc = spawn(command, args, { shell: true });
        '''
        findings = scan_privilege(source, "runner.ts")
        assert any(f.rule_id == "AGENT-047" for f in findings)

    def test_047_build_script_lowered(self):
        """构建脚本中的子进程 → 降权"""
        source = 'subprocess.run(["npm", "install"], check=True)'
        findings = scan_privilege(source, "scripts/build.py")
        if findings:
            assert all(f.confidence < 0.60 for f in findings)
```

## 约束

- 每条规则必须有 ASI 映射
- 每条规则输出 confidence 分数
- 不修改任何现有规则行为
- 优雅处理解析失败 (try/except 不中断扫描)
- 同一代码段被多条规则命中是正常的

## 自验证

```bash
pytest tests/test_privilege_rules.py -v
pytest tests/ -v --tb=short -q  # 回归检查
# 规则计数: 应 ≥ 45 (39 existing + 6 new)
grep -rn 'AGENT-0' agent_audit/ --include='*.py' | grep -oP 'AGENT-\d+' | sort -u | wc -l
```
```

---

### Prompt C4: 分层报告 + 置信度加权 Risk Score

```markdown
# 角色
你是 agent-audit 的产品工程师。你正在重构报告层。

# 前置条件
C1-C3 已完成。Findings 已携带 confidence 和 tier 字段。

# 任务

## 第一步: 理解现有报告逻辑

```bash
grep -rn "class.*Report\|def.*report\|risk.*score\|format_finding\|print_finding" \
    agent_audit/ --include="*.py" -l
```

## 第二步: 实现分层输出

默认显示 BLOCK + WARN，隐藏 INFO + SUPPRESSED。

终端输出格式:
```
╭──────────────────────────────────────────────────────────────╮
│ Agent Audit Security Report                                  │
│ Scanned: /path/to/project                                    │
│ Files analyzed: 847                                          │
│ Risk Score: 6.3/10 (MEDIUM-HIGH)                             │
╰──────────────────────────────────────────────────────────────╯

🔴 BLOCK — Tier 1 (Confidence ≥ 90%) — 0 findings

🟠 WARN — Tier 2 (Confidence ≥ 60%) — 4 findings

  AGENT-004: Hardcoded Credentials [confidence: 0.78]
    Location: SKILL.md:200
    Code: postgres://user:pass@localhost:5432/prose
    Reason: matches known format: PostgreSQL Connection String

  ...

ℹ️  INFO — Tier 3 (hidden, use --verbose to show) — 12 findings

📊 Summary:
  BLOCK: 0 | WARN: 4 | INFO: 12 | SUPPRESSED: 211
```

## 第三步: 置信度加权 Risk Score

```python
import math

def calculate_risk_score(findings: list) -> float:
    SEVERITY_WEIGHT = {
        "CRITICAL": 3.0, "HIGH": 1.5, "MEDIUM": 0.5, "LOW": 0.2,
    }
    raw = sum(
        f.confidence * SEVERITY_WEIGHT.get(f.severity, 0.5)
        for f in findings
        if getattr(f, 'tier', 'WARN') in ('BLOCK', 'WARN')
    )
    if raw <= 0:
        return 0.0
    return round(min(10.0, 2.5 * math.log2(1 + raw)), 1)
```

## 第四步: 添加 CLI 选项

- `--verbose`: 显示 BLOCK + WARN + INFO
- `--min-tier BLOCK|WARN|INFO|SUPPRESSED`: 自定义过滤
- `--no-color`: CI/CD 环境

## 第五步: JSON 输出升级

添加 confidence, tier, reason 字段。保留旧字段 (deprecated) 向后兼容。

## 自验证

```bash
pytest tests/test_reporter.py -v
pytest tests/ -v --tb=short -q
```
```

---

### Prompt C5: 三级验证 (openclaw + Layer 1 + Agent-Vuln-Bench)

```markdown
# 角色
你是 agent-audit 的 QA 工程师。对 v0.5.0 所有改动进行端到端验证。

# 前置条件
C1-C4 全部完成。

# 任务

## 第一级: Agent-Vuln-Bench 复测 (★ 硬性标准)

```bash
# 运行 Agent-Vuln-Bench 评估
cd tests/benchmark/agent-vuln-bench
python harness/run_eval.py --adapter agent_audit
python metrics/compute_metrics.py
```

### 硬性验收标准:

| 指标 | v0.4.1 Baseline | v0.5.0 最低要求 | v0.5.0 目标 |
|------|----------------|----------------|-------------|
| Overall Recall | 17.6% | **≥60%** | ≥80% |
| Set A Recall | 33.3% | **≥67%** | ≥90% |
| Set B Recall | 0.0% | **≥50%** | ≥90% |
| Set C Recall | 0.0% | **≥50%** | ≥70% |
| Precision | 100% | **≥75%** | ≥85% |

### 逐样本检查:

```python
# 逐个验证 benchmark 样本
EXPECTED_RESULTS = {
    "KNOWN-001": {"rule": "AGENT-034", "fixed_by": "C2b", "must_detect": True},
    "KNOWN-002": {"rule": "AGENT-034", "fixed_by": "C2b", "must_detect": True},
    "KNOWN-003": {"rule": "AGENT-029~033", "fixed_by": "C1", "must_detect": True},
    "KNOWN-004": {"rule": "AGENT-004", "fixed_by": "C2a", "must_detect": True},
    "KNOWN-005": {"rule": "AGENT-034/036", "fixed_by": "C2b", "must_detect": True},
    "WILD-001":  {"rule": "AGENT-034", "fixed_by": "C2b", "must_detect": True},
    "WILD-002":  {"rule": "AGENT-037", "fixed_by": "C2b", "must_detect": True},
}

for sample_id, expected in EXPECTED_RESULTS.items():
    # 运行扫描
    results = scan_sample(sample_id)
    detected = any(f.rule_id == expected["rule"] for f in results)
    print(f"{sample_id}: {'✅' if detected else '❌'} (fixed by {expected['fixed_by']})")
```

**如果 Overall Recall < 60%，这是 BLOCKER，必须在此 Prompt 内修复。**

## 第二级: openclaw 端到端验证

```bash
git clone --depth 1 https://github.com/openclaw/openclaw.git /tmp/openclaw
python -m agent_audit scan /tmp/openclaw --output json > /tmp/openclaw-results.json
python -m agent_audit scan /tmp/openclaw > /tmp/openclaw-results.txt
```

### 验收标准:

| 指标 | 阈值 | 验证方法 |
|------|------|---------|
| BLOCK+WARN findings | ≤15 | jq '.summary.by_tier' |
| BLOCK+WARN FP 率 | <20% | 人工审查每个 WARN+ finding |
| postgres 连接串检出 | ≥3 | grep AGENT-004 + postgres |
| 权限规则命中 | ≥2 | grep AGENT-04[3-8] |
| readKeychainPassword 不报 AGENT-004 | 0 | grep keychain + AGENT-004 |
| Risk Score | 3.0-8.0 | 不是 0 也不是 10 |

## 第三级: Layer 1 Benchmark 回归

```bash
pytest tests/ -v --tb=short
# Layer 1: 393 测试全部通过
```

## 第四级: 性能检查

```bash
time python -m agent_audit scan /tmp/openclaw      # <60s
time python -m agent_audit scan tests/benchmark/T1  # <5s
```

## 修复流程

如果验收标准未达标:
1. 定位问题根因
2. 修复并重新验证
3. 确保修复不破坏其他测试
4. **不要修改验收标准本身**

## 输出

写入 `docs/v050-validation-report.md`:

```markdown
# v0.5.0 Validation Report

## Agent-Vuln-Bench Results
- Overall Recall: X% (baseline: 17.6%, target: ≥60%) ✅/❌
- Set A Recall: X% ✅/❌
- Set B Recall: X% ✅/❌
- Set C Recall: X% ✅/❌
- Precision: X% ✅/❌
- Per-sample results: (表格)

## openclaw Results
- BLOCK+WARN findings: X (target ≤15) ✅/❌
- FP rate: X% ✅/❌
- Privilege rules: X ✅/❌
- Risk Score: X/10 ✅/❌

## Layer 1 Regression
- Tests passed: X/393 ✅/❌

## Performance
- openclaw scan: Xs ✅/❌
```
```

---

### Prompt C6: 文档更新 + 发布准备

```markdown
# 角色
你是 agent-audit 的技术文档维护者。

# 前置条件
C1-C5 全部完成并验证通过。

# 任务

## 1. 更新 README.md

添加 v0.5.0 变更亮点:
- 多语言 AST (tree-sitter): TypeScript/JavaScript 支持
- AGENT-004 语义化: 三阶段引擎, 98% FP → 0% FP
- 规则扩展: AGENT-034/026/037 扩展触发范围
- 新增权限规则: AGENT-043~048
- 置信度分层: BLOCK/WARN/INFO/SUPPRESSED
- Agent-Vuln-Bench: Recall 17.6% → X%

## 2. 更新 CHANGELOG.md

```markdown
## [0.5.0] - 2026-02-XX

### 🚀 Major Changes

#### Multi-Language AST Support
- tree-sitter based parsing for TypeScript, JavaScript
- Unified AST query interface

#### AGENT-004 Semantic Overhaul
- 3-stage analysis: candidate → value analysis → context scoring
- Shannon entropy + placeholder detection
- openclaw: 227 findings → X findings (98% FP → 0% FP)

#### Detection Range Expansion
- AGENT-034: eval/exec detection beyond @tool context
- AGENT-026/037: SSRF detection beyond @tool context
- Context-aware confidence scoring

#### New Privilege Detection Rules (AGENT-043~048)
- Daemon privilege, sudoers, browser automation, credential store,
  subprocess sandbox, extension permissions

#### Confidence-Based Tiered Reporting
- BLOCK (≥0.90), WARN (≥0.60), INFO (≥0.30), SUPPRESSED
- --verbose, --min-tier options

#### Agent-Vuln-Bench Results
- Recall: 17.6% → X%
- Set A/B/C coverage improvements
```

## 3. 更新 pyproject.toml / setup.py

新增依赖:
```
tree-sitter >= 0.22.0
tree-sitter-python >= 0.23.0
tree-sitter-javascript >= 0.23.0
tree-sitter-typescript >= 0.23.0
```

版本号: 0.5.0

## 4. 最终验证

```bash
pytest tests/ -v
pip install -e . --break-system-packages
agent-audit --version  # 0.5.0
agent-audit scan /tmp/openclaw
```
```

---

## 第五部分：Prompt 依赖关系与执行检查

```
C1 ──────────────────────────┐
(tree-sitter + 入口修复)     │
  ★ 解决: KNOWN-003 (Set B)  │
                              ├──→ C2b ──────────────────┐
C2a ─────────────────────────┤    (034/026/037 扩展)     │
(AGENT-004 语义化)            │    ★ 解决: KNOWN-001/002   │
  ★ 解决: KNOWN-004 (Set C)  │      KNOWN-005, WILD-1/2  │
                              │                            │
C3 ──────────────────────────┤                            ├→ C5 → C6
(权限规则 043-048)            │                            │
  ★ 解决: openclaw 安全面    │──→ C4 ───────────────────┘
                              │    (分层报告)
                              │
                              └── 每个 Prompt 开头有前置检查

执行顺序: C1 → C2a → C2b → C3 → C4 → C5 → C6 (严格)
```

### 各 Prompt 预期工作量

| Prompt | 预期时间 | 文件变动 | 新增测试 |
|--------|---------|---------|---------|
| C1 | 60min | 4-5 新文件 + 1-2 修改 | 12+ tests |
| C2a | 50min | 1-2 重构 + 1-2 新文件 | 14+ tests |
| C2b | 50min | 2-3 修改 + 1 新文件 | 12+ tests |
| C3 | 45min | 2-3 新文件 | 8+ tests |
| C4 | 30min | 1-2 重构 | 5+ tests |
| C5 | 45min | 0 (验证) | 验证脚本 |
| C6 | 20min | 3-4 文档 | 最终回归 |

总计: ~300min (5h)，7 个 Claude Code Prompt

---

## 附录 A: 原方案 vs 改进方案关键差异对照

| 编号 | 原方案 | 改进方案 | 原因 |
|------|--------|---------|------|
| Δ1 | C1 不含 JSON 入口修复 | C1 增加 JSON/YAML 路由修复 | KNOWN-003 Set B=0% |
| Δ2 | C2 只重构 AGENT-004 | 拆为 C2a(004) + C2b(034/026/037) | 3/4 gap 指向触发范围 |
| Δ3 | 凭证格式无 sk-ant-/co- | 明确列出 sk-ant-, co-* 等新格式 | KNOWN-004 漏报 |
| Δ4 | C5 只有 openclaw + Layer 1 | C5 增加 Agent-Vuln-Bench 硬性验收 | 唯一定量标准 |
| Δ5 | 无 benchmark 数据锚点 | 每个 Prompt 标注预期通过的样本 | 可追溯改动效果 |
| Δ6 | 6 个 Prompt | 7 个 Prompt | C2 拆分降低复杂度 |
| Δ7 | 未考虑 v0.4.1 已有 | 明确标注不重复实现 | 避免浪费和冲突 |
| Δ8 | 上下文 confidence 仅文件级 | 新增代码上下文 confidence 分层 | @tool=0.95, 普通=0.55 |

## 附录 B: 预期 Agent-Vuln-Bench 结果矩阵

| 样本 | v0.4.1 | C1 后 | C2a 后 | C2b 后 | v0.5.0 最终 |
|------|--------|-------|--------|--------|------------|
| KNOWN-001 (eval) | ❌ | ❌ | ❌ | ✅ | ✅ |
| KNOWN-002 (exec) | ❌ | ❌ | ❌ | ✅ | ✅ |
| KNOWN-003 (MCP) | ❌ | ✅ | ✅ | ✅ | ✅ |
| KNOWN-004 (cred) | ❌ | ❌ | ✅ | ✅ | ✅ |
| KNOWN-005 (shell) | ✅ | ✅ | ✅ | ✅ | ✅ |
| WILD-001 (eval) | ❌ | ❌ | ❌ | ✅ | ✅ |
| WILD-002 (SSRF) | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Recall** | **17.6%** | **29%** | **43%** | **100%** | **100%** |
