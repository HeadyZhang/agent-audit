# Agent Audit

> [English README](README.md)

**在 AI Agent 代码进入生产前，发现安全漏洞。**

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/HeadyZhang/agent-audit/graph/badge.svg?branch=master)](https://codecov.io/gh/HeadyZhang/agent-audit?branch=master)
[![Tests](https://img.shields.io/badge/tests-1142%20passed-brightgreen)]()

---

## 为什么 Agent 安全在生产中容易失效

AI Agent 不只是聊天机器人。它会执行代码、调用工具、接触真实系统，因此一条不安全的输入路径就可能演变成生产事故。

- Prompt Injection 会通过用户可控上下文改写 Agent 意图
- 不安全的工具输入可能进入 `subprocess` / `eval` 并导致命令执行
- MCP 配置错误可能泄露凭证并意外扩大访问范围

如果你的团队在上线 Agent 功能、维护 CI 安全门禁、或运营 MCP 服务与工具集成，这不是低概率边缘问题，而是高概率风险面。
只要 Agent 代码会触发工具、命令或外部系统，基本就需要在每次合并前扫描一次。

**Agent Audit** 在部署前拦截这些问题，当前分析核心专门面向 Agent 工作流：工具边界污点跟踪、MCP 配置审计、语义化密钥检测，并预留向学习辅助检测扩展的空间。

可以把它理解成 **AI Agent 的安全 lint**，当前已有 40+ 规则，映射到 [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)。

---

## 6 行快速开始

1. 安装

```bash
pip install agent-audit
```

2. 扫描项目

```bash
agent-audit scan ./your-agent-project
```

3. 解释结果并在 CI 设门禁

```bash
# 仅显示 high 及以上问题
agent-audit scan . --severity high

# 当 high 及以上问题存在时，让 CI 失败
agent-audit scan . --fail-on high
```

`--severity` 决定展示哪些发现，`--fail-on` 决定何时以 `exit code 1` 退出。

示例输出：

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ Agent Audit Security Report                                                  │
│ Scanned: ./your-agent-project                                                │
│ Files analyzed: 2                                                            │
│ Risk Score: 8.4/10 (HIGH)                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯

BLOCK -- Tier 1 (Confidence >= 90%) -- 16 findings

  AGENT-001: Command Injection via Unsanitized Input
    Location: agent.py:21
    Code: result = subprocess.run(command, shell=True, capture_output=True, text=True)

  AGENT-010: System Prompt Injection Vector in User Input Path
    Location: agent.py:13
    Code: system_prompt = f"You are a helpful {user_role} assistant..."

  AGENT-041: SQL Injection via String Interpolation
    Location: agent.py:31
    Code: cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")

  AGENT-031: Mcp Sensitive Env Exposure
    Location: mcp_config.json:1
    Code: env: {"API_KEY": "sk-a***"}

  ... and 15 more

Summary:
  BLOCK: 16 | WARN: 2 | INFO: 1
  Risk Score: =========================----- 8.4/10 (HIGH)
```

---

验证快照（截至 **2026-02-19**，v0.16 基准集）：**94.6% recall**、**87.5% precision**、**0.91 F1**，在 **9 个开源目标**上覆盖 **10/10 OWASP Agentic Top 10**。  
详情见：[Benchmark Results](docs/BENCHMARK-RESULTS.md) | [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md)

---

## 能检测什么

| 类别 | 典型问题 | 示例规则 |
|------|----------|----------|
| **注入攻击** | 用户输入流向 `exec()`、`subprocess`、SQL | AGENT-001, AGENT-041 |
| **提示词注入** | 用户输入拼接到 system prompt | AGENT-010 |
| **凭证泄露** | 源码或 MCP 配置中硬编码 API Key | AGENT-004, AGENT-031 |
| **输入校验缺失** | `@tool` 函数接收原始字符串无校验 | AGENT-034 |
| **不安全 MCP 服务** | 无鉴权、未固定版本、权限过宽 | AGENT-005, AGENT-029, AGENT-030, AGENT-033 |
| **缺少护栏** | Agent 无迭代上限或人工审批 | AGENT-028, AGENT-037 |
| **无限制代码执行** | 工具里 `eval()` 或 `shell=True` 无沙箱 | AGENT-035 |

覆盖 OWASP Agentic Security 全部 10 个类别。框架层面支持 **LangChain**、**CrewAI**、**AutoGen**、**AgentScope**。 [查看全部规则 ->](docs/RULES.md)

---

## 适用人群

- **Agent 开发者**：使用 LangChain、CrewAI、AutoGen、OpenAI Agents SDK 或原生 function-calling 的团队，建议每次部署前运行
- **安全工程师**：审计 Agent 代码库并输出 SARIF 到 GitHub Security 页签
- **MCP 服务团队**：校验 `mcp.json` / `claude_desktop_config.json` 中的密钥暴露、鉴权缺失与供应链风险

---

## 使用方式

```bash
# 扫描项目
agent-audit scan ./my-agent

# JSON 输出便于脚本处理
agent-audit scan ./my-agent --format json

# SARIF 输出用于 GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif

# 仅在 critical 级别问题出现时让 CI 失败
agent-audit scan . --fail-on critical

# 在线检查 MCP 服务（只读，不调用工具）
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Baseline 扫描

跨提交仅跟踪“新增”问题：

```bash
# 保存当前状态为 baseline
agent-audit scan . --save-baseline baseline.json

# 仅报告 baseline 中不存在的新问题
agent-audit scan . --baseline baseline.json --fail-on-new
```

### GitHub Actions

<details>
<summary><b>Show GitHub Action Example and Inputs</b></summary>
<br/>

```yaml
name: Agent Security Scan
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HeadyZhang/agent-audit@v1
        with:
          path: '.'
          fail-on: 'high'
          upload-sarif: 'true'
```

| 输入参数 | 说明 | 默认值 |
|----------|------|--------|
| `path` | 扫描路径 | `.` |
| `format` | 输出格式：`terminal`、`json`、`sarif`、`markdown` | `sarif` |
| `severity` | 最低报告严重级别 | `low` |
| `fail-on` | 在该严重级别及以上时以错误退出 | `high` |
| `baseline` | baseline 文件路径（增量扫描） | - |
| `upload-sarif` | 上传 SARIF 到 GitHub Security | `true` |

</details>

---

## 评估结果

<details>
<summary><b>Show Evaluation Details</b></summary>
<br/>

在 [**Agent-Vuln-Bench**](tests/benchmark/agent-vuln-bench/)（19 个样本，3 类漏洞）上，与 Bandit 和 Semgrep 对比：

| 工具 | Recall | Precision | F1 |
|------|-------:|----------:|---:|
| **agent-audit** | **94.6%** | **87.5%** | **0.91** |
| Bandit 1.8 | 29.7% | 100% | 0.46 |
| Semgrep 1.x | 27.0% | 100% | 0.43 |

| 类别 | agent-audit | Bandit | Semgrep |
|------|:-----------:|:------:|:-------:|
| Set A -- Injection / RCE | **100%** | 68.8% | 56.2% |
| Set B -- MCP Configuration | **100%** | 0% | 0% |
| Set C -- Data / Auth | **84.6%** | 0% | 7.7% |

> Bandit 与 Semgrep 都无法解析 MCP 配置文件，因此在 Agent 特有配置漏洞（Set B）上是 **0% recall**。

完整评估：[Benchmark Results](docs/BENCHMARK-RESULTS.md) | [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md)

</details>

## 工作原理

<details>
<summary><b>Show Architecture and Technical Notes</b></summary>
<br/>

```
Source Files (.py, .json, .yaml, .env, ...)
        |
        +-- PythonScanner ---- AST Analysis ---- Dangerous Patterns
        |        |                                Tool Metadata
        |        +-- TaintTracker --------------- Source->Sink Reachability
        |        +-- DangerousOperationAnalyzer - Tool Boundary Detection
        |
        +-- SecretScanner ---- Regex Candidates
        |        +-- SemanticAnalyzer ----------- 3-Stage Filtering
        |              (Known Formats -> Entropy/Placeholder -> Context)
        |
        +-- MCPConfigScanner -- Server Provenance / Path Permissions / Auth
        |
        +-- PrivilegeScanner -- Daemon / Sudoers / Sandbox / Credential Store
                 |
                 v
            RuleEngine -- 40+ Rules x OWASP Agentic Top 10 -- Findings
```

**关键技术点：**

- **工具边界感知的污点分析**：从 `@tool` 参数跟踪到危险 sink（`eval`、`subprocess.run`、`cursor.execute`），并识别是否已清洗，仅在确认工具入口且参数未清洗时触发。
- **MCP 配置审计**：解析 `claude_desktop_config.json` 与 MCP 网关配置，识别未验证来源、文件系统权限过宽、缺少鉴权、依赖未固定版本等问题。
- **三阶段语义凭证检测**：1) 正则候选发现，2) 值分析（已知格式、熵评分、占位符/UUID 排除），3) 上下文校正（文件类型、测试模式、框架 schema）。

</details>

## 威胁覆盖

40+ 规则覆盖 [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 全部 10 类：

| OWASP 类别 | 规则数 | 示例检测 |
|------------|------:|----------|
| ASI-01 Agent Goal Hijack | 4 | `SystemMessage` 中 f-string 注入 |
| ASI-02 Tool Misuse | 9 | `@tool` 输入未校验流向 `subprocess` |
| ASI-03 Identity & Privilege | 4 | 守护进程提权、MCP 服务器数量 >10 |
| ASI-04 Supply Chain | 5 | 未验证 MCP 源、`npx` 包未固定版本 |
| ASI-05 Code Execution | 3 | 工具中无沙箱 `eval`/`exec` |
| ASI-06 Memory Poisoning | 2 | 未净化输入写入向量库 `upsert` |
| ASI-07 Inter-Agent Comm | 1 | 多 Agent 经 HTTP 通信且无 TLS |
| ASI-08 Cascading Failures | 3 | `AgentExecutor` 缺少 `max_iterations` |
| ASI-09 Trust Exploitation | 6 | 关键操作缺少 `human_in_the_loop` |
| ASI-10 Rogue Agents | 3 | 无 kill switch、无行为监控 |

## 真实项目验证

<details>
<summary><b>Show Real-World Target Results</b></summary>
<br/>

在 9 个开源目标上进行了检测质量验证：

| Target | Project | Findings | OWASP Categories |
|--------|---------|----------|------------------|
| T1 | [damn-vulnerable-llm-agent](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent) | 4 | ASI-01, ASI-02, ASI-06 |
| T2 | [DamnVulnerableLLMProject](https://github.com/harishsg993010/DamnVulnerableLLMProject) | 41 | ASI-01, ASI-02, ASI-04 |
| T3 | [langchain-core](https://github.com/langchain-ai/langchain) | 3 | ASI-01, ASI-02 |
| T6 | [openai-agents-python](https://github.com/openai/openai-agents-python) | 25 | ASI-01, ASI-02 |
| T7 | [adk-python](https://github.com/google/adk-python) | 40 | ASI-02, ASI-04, ASI-10 |
| T8 | [agentscope](https://github.com/modelscope/agentscope) | 10 | ASI-02 |
| T9 | [crewAI](https://github.com/crewAIInc/crewAI) | 155 | ASI-01, ASI-02, ASI-04, ASI-07, ASI-08, ASI-10 |
| T10 | MCP Config (100-tool server) | 8 | ASI-02, ASI-03, ASI-04, ASI-05, ASI-09 |
| T11 | [streamlit-agent](https://github.com/langchain-ai/streamlit-agent) | 6 | ASI-01, ASI-04, ASI-08 |

在目标集中检测到 **10/10 OWASP Agentic Top 10**，质量门禁结论：**PASS**。

</details>

## 与现有工具对比

| 能力 | agent-audit | Bandit | Semgrep |
|------|:-----------:|:------:|:-------:|
| Agent 专属威胁模型（OWASP Agentic Top 10） | Yes | No | No |
| MCP 配置审计 | Yes | No | No |
| 工具边界污点分析 | Yes | No | No |
| `@tool` 装饰器识别 | Yes | No | No |
| 语义凭证检测 | Yes | Basic | Basic |
| 通用 Python 安全 | Partial | Yes | Yes |
| 多语言支持 | Python-focused | Python | Multi |

agent-audit 与通用 SAST 工具是 **互补关系**。它填补的是 AI Agent 应用特有的安全空白。

## 配置

```yaml
# .agent-audit.yaml
scan:
  exclude: ["tests/**", "venv/**"]
  min_severity: low
  fail_on: high

ignore:
  - rule_id: AGENT-003
    paths: ["auth/**"]
    reason: "Auth module legitimately communicates externally"

allowed_hosts:
  - "api.openai.com"
```

## 当前范围

<details>
<summary><b>Show Current Limitations and Scope</b></summary>
<br/>

- **当前核心是静态分析**：不会执行代码，因此可能漏掉仅在运行期出现的逻辑漏洞。
- **函数内污点分析**：当前跟踪函数内数据流，尚未覆盖跨函数/跨模块跟踪。
- **以 Python 为主**：主要支持 Python 源码和 MCP JSON 配置；其他语言仅有限模式匹配。
- **框架覆盖**：深度支持 LangChain、CrewAI、AutoGen、AgentScope；其他框架使用通用 `@tool` 规则。
- **误报控制**：通过语义分析、框架识别与 allowlist 持续优化（v0.16 误报下降 79%）。

</details>

## 文档

- [Technical Specification](docs/SECURITY-ANALYSIS-SPECIFICATION.md) -- 检测方法与分析流水线
- [Benchmark Results](docs/BENCHMARK-RESULTS.md) -- Agent-Vuln-Bench 详细结果
- [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md) -- 与 Bandit/Semgrep 三方对比
- [Rule Reference](docs/RULES.md) -- 完整规则目录、CWE 映射与修复建议
- [Architecture](docs/ARCHITECTURE.md) -- 内部设计与扩展点
- [CI/CD Integration](docs/CI-INTEGRATION.md) -- GitHub Actions、GitLab CI、Jenkins、Azure DevOps 集成

## 开发

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest ../../tests/ -v  # 1142 tests
```

更多开发细节见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 引用

如果你在研究中使用 agent-audit，可引用：

```bibtex
@software{agent_audit_2026,
  author = {Zhang, Haiyue},
  title = {Agent Audit: Static Security Analysis for AI Agent Applications},
  year = {2026},
  url = {https://github.com/HeadyZhang/agent-audit},
  note = {Based on OWASP Agentic Top 10 (2026) threat model}
}
```

## 致谢

- [OWASP Agentic Top 10 for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## 许可证

MIT -- 见 [LICENSE](LICENSE)。
