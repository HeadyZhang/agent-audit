# Agent Audit 安全分析技术规格说明

> **版本**: v0.14.1  
> **文档类型**: 安全专业角度技术说明  
> **适用对象**: 安全工程师、渗透测试人员、DevSecOps、合规审计

---

## 1. 执行摘要

Agent Audit 是一款面向 **AI Agent 应用** 的静态安全分析工具，基于 **OWASP Agentic Top 10 for 2026** 威胁模型，对 Python 代码、MCP 配置、硬编码凭证及权限边界进行多维度检测。

### 1.1 核心能力

| 维度 | 方法 | 覆盖威胁类别 |
|------|------|--------------|
| **代码静态分析** | Python AST + 模式匹配 + 数据流分析 | 注入、RCE、SSRF、信任边界 |
| **凭证检测** | 正则 + 语义分析 + 熵值 + 上下文调整 | 硬编码密钥、API Token、连接串 |
| **配置审计** | MCP/JSON/YAML 解析 + 策略校验 | 供应链、权限过宽、认证缺失 |
| **污点分析** | 函数内数据流图 + Sink 可达性 | Tool 输入未验证流向危险操作 |
| **运行时探测** | MCP 协议客户端（inspect 命令） | 工具暴露面、权限边界 |

---

## 2. 检测方法与威胁映射

### 2.1 检测方法论概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Agent Audit 检测流水线                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   [文件输入]                                                                  │
│        │                                                                     │
│        ├──► PythonScanner (AST)  ──► 危险模式 / Tool 元数据 / 框架模式          │
│        │         │                                                          │
│        │         ├──► 污点分析 (TaintTracker) ──► AGENT-034 精确判定           │
│        │         └──► 危险操作分析 (DangerousOperationAnalyzer)               │
│        │                                                                     │
│        ├──► SecretScanner (Regex) ──► 候选凭证                                 │
│        │         │                                                          │
│        │         └──► 语义分析 (SemanticAnalyzer) ──► 三层过滤 + 置信度         │
│        │                                                                     │
│        ├──► MCPConfigScanner ──► 服务器配置 / 环境变量 / 路径权限               │
│        │                                                                     │
│        └──► PrivilegeScanner ──► 提权模式 / 沙箱缺失 / 凭证存储访问             │
│                                                                             │
│   [RuleEngine] ──► 模式→规则映射 / 去重 / 置信度分级                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 按威胁类别的检测方法

#### ASI-01: Agent Goal Hijack（目标劫持）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-010** | AST 模式：`SystemMessage`、`ChatPromptTemplate.from_messages` 等函数的 f-string/format 参数；字符串拼接到 `system_prompt`、`instructions` | 用户输入未经 sanitize 直接拼接进系统提示，导致提示注入 |
| **AGENT-011** | 配置检测：Agent 构造缺少 `input_validator`、`allowed_tools`、`max_iterations` 等边界控制 | Agent 缺少目标边界与输入守卫 |
| **AGENT-027** | LangChain 专用：`SystemMessage(content=f"...")` 等可注入形式 | LangChain 系统提示可被用户输入污染 |

**技术要点**：通过 AST 识别「用户可控变量 → 系统提示」的数据流，而非简单关键词匹配。

---

#### ASI-02: Tool Misuse & Exploitation（工具滥用）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-001** | AST：`subprocess.run(..., shell=True)` 且参数含用户输入；`eval/exec` 直接执行用户/LLM 输出 | 命令注入、任意代码执行 |
| **AGENT-026** | AST + 污点：`@tool` 函数参数流向 `subprocess`、`requests`、`cursor.execute` 等 Sink，且无 sanitize | Tool 输入未净化即传入危险操作 |
| **AGENT-034** | 污点分析 + 危险操作分析：Tool 入口点的 str 参数是否流向 exec/subprocess/SQL，是否具备验证 | Tool 无输入验证导致 RCE/注入 |
| **AGENT-035** | AST：Tool 内调用 `eval`、`exec`、`subprocess` 且无沙箱证据 | 非沙箱化代码执行 |
| **AGENT-036** | AST：Tool 输出直接用于后续决策/执行，无校验 | Tool 输出被盲目信任 |
| **AGENT-041** | AST：SQL 语句通过 f-string、`format`、`%`、`+` 拼接用户输入 | SQL 注入 |
| **AGENT-029** | MCP 配置：`args` 含 `/`、`/home`、`$HOME` 等根路径 | MCP 文件系统权限过宽 |
| **AGENT-032** | MCP 配置：stdio 传输且无 sandbox 相关配置 | MCP 未隔离执行 |
| **AGENT-037** | AST：Agent 使用 `run_tool`、`delete_file` 等有副作用 Tool，但无 `human_in_the_loop`、`require_approval` | 关键操作缺少人工审批 |
| **AGENT-047** | PrivilegeScanner：subprocess 调用无 Docker/sandbox/seccomp 等隔离证据 | 子进程未沙箱化 |

**技术要点**：

- **污点分析 (TaintTracker)**：函数内构建数据流图，识别 Source（函数参数、`os.getenv`、`request.json()` 等）→ Sink（`subprocess.run`、`eval`、`cursor.execute` 等）的可达路径；检测 sanitization 节点（`validate`、`isinstance`、allowlist 等）。
- **危险操作分析 (DangerousOperationAnalyzer)**：仅在「确认是 Tool 入口点」时触发；检查参数是否流入 `DANGEROUS_FUNCTIONS`；通过 `SAFE_TOOL_PATTERNS`（如 `get_*`、`fetch_*`、`search_*`）降低误报。

---

#### ASI-03: Identity & Privilege Abuse（身份与权限滥用）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-002** | 统计：工具数量 > 15 或高风险工具组合（file_read + network_outbound 等） | Agent 权限过宽 |
| **AGENT-013** | AST：Agent/Tool/LLM 附近 `api_key=`、`secret_key=` 等硬编码赋值 | Agent 使用长期凭证 |
| **AGENT-014** | AST：`trust_all_tools`、`auto_approve`、`--dangerously-skip-permissions` 等 | 自动批准、绕过权限 |
| **AGENT-042** | MCP 配置：`mcpServers` 数量过多 | MCP 服务器过多 |
| **AGENT-043** | PrivilegeScanner：`daemon=True`、后台 agent 且无健康检查/监控 | Daemon 提权风险 |
| **AGENT-044** | PrivilegeScanner：`NOPASSWD` in sudoers 配置 | Sudoers 无密码提权 |
| **AGENT-046** | PrivilegeScanner：访问系统凭证存储（keychain、credential manager） | 系统凭证存储访问 |

---

#### ASI-04: Supply Chain Vulnerabilities（供应链）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-005** | MCP 配置：`command`/`url` 不在 `TRUSTED_SOURCES` | 未验证 MCP 服务器来源 |
| **AGENT-015** | MCP 配置：`npx -y some-unknown-package`、`npx @latest`、`github.com`、`file://`、`http://` | 不可信 MCP 源、未固定版本 |
| **AGENT-016** | AST：`WebBaseLoader`、`DirectoryLoader` 等 RAG 加载器链到 `add_documents`，无 `validate_source` 等 | RAG 数据源未验证 |
| **AGENT-030** | MCP 配置：服务器来源未经验证 | 未验证 MCP 服务器源 |
| **AGENT-048** | PrivilegeScanner：扩展/插件权限边界过宽 | 插件权限边界问题 |
| **AGENT-049** | AST：`pickle.load`、`torch.load`、`joblib.load` 等反序列化 | 不安全反序列化 |

---

#### ASI-05: Unexpected Code Execution（意外代码执行）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-017** | AST：Tool/Agent 内 `eval`、`exec`、`subprocess` 且无 sandbox/docker 证据 | 非沙箱化代码执行 |
| **AGENT-034** | 污点 + 危险操作分析（见 ASI-02） | Tool 参数流向 exec/subprocess |
| **AGENT-049** | 见 ASI-04 | 反序列化 RCE |

**扩展检测 (v0.5.0+)**：`eval_exec_expanded`、`subprocess_expanded` 在非 @tool 上下文中也检测，置信度分层（tool 内最高，普通函数较低）。

---

#### ASI-06: Memory & Context Poisoning（记忆与上下文投毒）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-018** | AST：`add_documents`、`add_texts`、`upsert` 等写入函数的参数来自 `user_input`、`query` 等，且路径上无 `sanitize`、`validate` | 未净化输入写入持久化记忆 |
| **AGENT-019** | AST：`ConversationBufferMemory` 等无 `max_token_limit`、`k=`；Redis/MongoDB 历史无 TTL | 无界记忆、无过期 |

**白名单**：通过 `rules/allowlists/framework_memory.yaml` 对框架内部合法调用进行豁免。

---

#### ASI-07: Insecure Inter-Agent Communication（不安全的 Agent 间通信）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-020** | AST/配置：`GroupChat`、`Crew` 等多 Agent 配置缺少 `authentication`、`tls`；URL 使用 `http://` | 无 TLS、无认证 |
| **AGENT-033** | MCP 配置：SSE/HTTP 传输无认证相关配置 | MCP 无认证 |

---

#### ASI-08: Cascading Failures（级联故障）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-021** | AST：`AgentExecutor`、`create_react_agent` 缺少 `max_iterations`、`max_execution_time`、`timeout` | 无迭代上限、无熔断 |
| **AGENT-022** | AST：@tool 函数体内无 try/except，且调用外部服务 | Tool 无错误处理 |
| **AGENT-028** | AST：跨框架检测 Agent 无 `max_iterations` | 无界迭代 |

---

#### ASI-09: Human-Agent Trust Exploitation（人机信任滥用）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-023** | AST：`AgentExecutor` 缺少 `return_intermediate_steps=True`、`verbose=True` | 输出不透明、无审计链 |
| **AGENT-037** | 见 ASI-02 | 关键操作无人审 |
| **AGENT-038** | AST：System 提示中包含「假装」「扮演」「impersonate」等指令 | 冒充风险 |
| **AGENT-039** | AST：多 Agent 系统中信任边界不清（需上下文分析） | 信任边界违规 |

---

#### ASI-10: Rogue Agents（恶意/失控 Agent）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-024** | AST：Agent 同时缺少 `max_iterations`、`max_execution_time`、`timeout`、`early_stopping`；daemon 无 `health_check` | 无 Kill Switch |
| **AGENT-025** | AST：Agent 缺少 `callbacks`、`callback_manager`、`verbose`、`langsmith` 等 | 无行为监控/可观测 |
| **AGENT-050** | LangChain：AgentExecutor 缺少安全参数（v0.15.0 从 AGENT-040 重命名） | 监控与安全参数缺失 |

---

#### 硬编码凭证（AGENT-004）

| 规则 | 检测方法 | 检测场景 |
|------|----------|----------|
| **AGENT-004** | SecretScanner + SemanticAnalyzer | 见 2.3 节 |

---

### 2.3 硬编码凭证检测（AGENT-004）— 三层语义分析

硬编码凭证检测采用 **三阶段语义分析**，在控制误报的同时保持对已知格式的高召回。

#### Stage 1: Candidate Discovery（候选发现）

- **正则模式**：按优先级匹配（CRITICAL → HIGH → MEDIUM → LOW → GENERIC）
  - CRITICAL：私钥头、数据库连接串
  - HIGH：`sk-proj-`、`sk-ant-`、`ghp_`、`AKIA` 等已知格式
  - MEDIUM：Stripe、Slack、SendGrid 等服务格式
  - LOW：`api_key=`、`secret=` 等泛化模式
  - GENERIC：高熵字符串
- **TreeSitter 解析**：区分赋值、类型注解、注释、文档，提取 `identifier`、`value`、`value_type`、`context`。

#### Stage 2: Value Analysis（值分析）

- **已知格式匹配**：`KNOWN_CREDENTIAL_FORMATS` 正则校验，匹配则高置信度。
- **UUID/占位符检测**：排除 UUID、`is_placeholder`、`is_vendor_example`。
- **框架 Schema 检测**：`api_key: str = Field(...)`、Pydantic `SecretStr` 等视为 Schema 定义，不报告。
- **框架内部路径**：`crewai/`、`langchain_core/` 等内部代码降权。
- **熵值分析**：Shannon 熵辅助判断随机性；过低则降权。

#### Stage 3: Context Adjustment（上下文调整）

- **文件类型乘数**：`.md`、`.rst`、测试文件降权；`.env` 保持高权。
- **路径模式**：`/tests/`、`/fixtures/`、`/examples/` 等降权。
- **测试上下文**：`mock_`、`fake_`、`@pytest.fixture` 等进一步降权。
- **基础设施上下文**：Dockerfile、CI 等场景对 AGENT-001/047 降权。

**输出**：`should_report`、`confidence`、`tier`（BLOCK/WARN/INFO）、`reason`。

---

## 3. 扫描器架构详解

### 3.1 PythonScanner

- **输入**：`.py` 文件
- **方法**：`ast.parse` + 自定义 Visitor 遍历
- **输出**：`dangerous_patterns`、`tools`、`function_calls`、`imports`
- **关键模式集**：
  - `EVAL_EXEC_PATTERNS_PYTHON`：eval、exec、compile
  - `SSRF_PATTERNS_PYTHON`：requests、urllib、aiohttp 等
  - `DANGEROUS_TOOL_INPUT_SINKS`：subprocess、eval、cursor.execute 等
  - `TOOL_DECORATORS_EXTENDED`：@tool、@tool_decorator 等
  - `INPUT_VALIDATION_PATTERNS`：validate、sanitize、allowlist
  - `UNSAFE_EXEC_FUNCTIONS`：eval、exec、subprocess
  - `SIDE_EFFECT_TOOL_PATTERNS`：delete、write、run、execute
  - `IMPERSONATION_PATTERNS`：假装、扮演、impersonate

### 3.2 SecretScanner

- **输入**：文本文件（含 `.py`、`.env`、`.json`、`.yaml` 等）
- **方法**：正则匹配 → 按优先级去重 → 调用 SemanticAnalyzer
- **输出**：`SecretMatch` 列表（含 `confidence`、`tier`）

### 3.3 MCPConfigScanner

- **输入**：`claude_desktop_config.json`、`mcp.json`、`docker-mcp.json` 等
- **方法**：JSON/YAML 解析 → 提取 `mcpServers`/`servers` → 校验来源、路径、env
- **输出**：`MCPServerConfig` 列表、`MCPSecurityFinding` 列表
- **校验项**：TRUSTED_SOURCES、DANGEROUS_PATHS、SENSITIVE_ENV_PATTERN

### 3.4 PrivilegeScanner

- **输入**：`.py`、`.ts`、`.js`、`.sh`、`.md`
- **方法**：AST/正则检测 daemon、NOPASSWD、credential store、subprocess 沙箱、插件权限
- **输出**：`PrivilegeFinding` 列表（AGENT-043~048）

### 3.5 RuleEngine

- **输入**：各 Scanner 的 `ScanResult`
- **方法**：`PATTERN_TYPE_TO_RULE_MAP` 映射、MCP 专用规则、权限评估、去重（AGENT-010 vs AGENT-027 等）
- **输出**：`Finding` 列表，含 `rule_id`、`severity`、`confidence`、`location`、`remediation`

---

## 4. 污点分析（TaintTracker）设计

### 4.1 组件

- **SourceClassifier**：识别污点源（函数参数、`os.getenv`、`request.json()`、`llm_output` 等）
- **DataFlowBuilder**：函数内数据流图（赋值、调用参数、f-string、拼接）
- **SanitizationDetector**：`isinstance`、`validate`、allowlist、`escape` 等
- **SinkReachabilityChecker**：检查污点是否到达 `subprocess.run`、`eval`、`cursor.execute` 等 Sink

### 4.2 保守策略

- 不确定时假定为污点（安全优先）
- 仅函数内分析（intra-procedural），不做跨函数追踪
- 依赖 AST，无外部符号解析

### 4.3 与 AGENT-034 的协同

AGENT-034 仅在以下条件同时满足时报告：

1. 函数是 Tool 入口点（`tool_boundary_detector`）
2. 存在 str/Any 类型参数
3. 污点分析显示参数流向危险 Sink，或危险操作分析确认参数流入危险函数
4. 未检测到有效 sanitization

---

## 5. 置信度与分级

- **confidence**：0.0–1.0，由各分析模块计算
- **tier**：BLOCK / WARN / INFO，由 `confidence_to_tier`、`compute_tier_with_context` 映射
- **BLOCK_EXEMPT_RULES**：部分规则（如 AGENT-022）即使高置信度也不强制 BLOCK

---

## 6. 局限与假设

| 维度 | 说明 |
|------|------|
| **静态分析** | 不执行代码，无法发现运行时逻辑漏洞 |
| **污点分析** | 仅函数内，无过程间分析；复杂别名/闭包可能漏报 |
| **跨语言** | Python 为主；PrivilegeScanner 支持 .ts/.js/.sh 有限模式 |
| **框架覆盖** | 深度支持 LangChain、CrewAI、AutoGen；其他框架为通用规则 |
| **误报/漏报** | 存在；通过语义分析、框架检测、allowlist 持续优化 |

---

## 7. 参考

- [OWASP Agentic Top 10 for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)（输出格式）

---

*文档维护：随 agent-audit 版本更新同步修订。*
