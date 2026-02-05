# agent-audit v0.3.1 热修复方案 & Claude Code Prompts

> **基于 v0.3.0 Benchmark 回归对比 | 目标版本: v0.3.1**
> **日期: 2026-02-04**

---

## 第一部分：v0.2.0 → v0.3.0 对比分析

### 1. Findings 数量对比

| ID  | 项目 | v0.2.0 | v0.3.0 | 变化 | 判定 |
|-----|------|--------|--------|------|------|
| T1  | damn-vulnerable-llm-agent | 0 | 0 | — | ❌ 仍未修复 |
| T2  | DamnVulnerableLLMProject | 80 | 80 | ±0 | ✅ 稳定 |
| T3  | langchain/agents | 93 | 8 | **-91%** | ✅ 大幅改善 |
| T4  | agents-from-scratch | 14 | 18 | +29% | ✅ 合理（新规则贡献） |
| T5  | deepagents | 35 | 71 | +103% | ⚠️ 需查 AGENT-028 贡献 |
| T6  | openai-agents-python | 23 | 23 | ±0 | ✅ 稳定 |
| T7  | adk-python | 64 | 64 | ±0 | ✅ 稳定 |
| T8  | agentscope | 26 | 26→26 | +37% | ⚠️ 新规则贡献 |
| T9  | crewAI | 124 | **739** | **+496%** | ❌ 严重回归 |
| T10 | 100-tool-mcp-server-json | 0 | 18 | **∞** | ✅ 修复成功 |
| T11 | streamlit-agent | 1 | 4 | +300% | ✅ 合理（新规则） |
| **合计** | | **453** | **1,051** | **+132%** | ⚠️ T9 拉高 |

### 2. OWASP 覆盖对比

| ASI | v0.2.0 | v0.3.0 | 变化 |
|-----|--------|--------|------|
| ASI-01 Agent Goal Hijack | ✅ | ✅ | 稳定 |
| ASI-02 Tool Misuse | ❌ | ✅ | **修复** ✅ |
| ASI-03 Identity/Privilege | ✅ | ❌ | **回归** ❌ |
| ASI-04 Supply Chain | ✅ | ✅ | 稳定 |
| ASI-05 Code Execution | ✅ | ✅ | 稳定 |
| ASI-06 Memory Poisoning | ✅ | ✅ | 稳定 |
| ASI-07 Inter-Agent Comm | ✅ | ✅ | 稳定 |
| ASI-08 Cascading Failures | ✅ | ✅ | 稳定 |
| ASI-09 Human-Agent Trust | ❌ | ✅ | **修复** ✅ |
| ASI-10 Rogue Agents | ✅ | ✅ | 稳定 |
| **总计** | **8/10** | **9/10** | +1 净增 |

**关键回归：** ASI-03 在 v0.2.0 中通过 T3(langchain) 和 T9(crewAI) 触发，v0.3.0 中消失。
很可能原因：v0.3.0 的 AGENT-018 白名单过滤掉了原来映射到 ASI-03 的 findings，
或者规则 ASI 映射被修改。

### 3. 核心问题清单

| 优先级 | 问题 | 根因分析 | 影响 |
|--------|------|---------|------|
| **P0** | T1 仍零检出 | AGENT-025/026/027 仅匹配新版 LangChain API；T1 使用旧版 `ConversationalChatAgent` + `AgentExecutor.from_agent_and_tools()` | 检出率 |
| **P1** | T9 crewAI 739 findings（+496%） | AGENT-028 (iteration limit) 在 crewAI 框架内部代码触发 489 次；crewAI 内部有自己的迭代控制但 AGENT-028 不识别 | 误报率 |
| **P1** | ASI-03 回归丢失 | v0.2.0 中 ASI-03 通过某些规则触发，v0.3.0 中这些 findings 被白名单过滤或 ASI 映射丢失 | OWASP 9/10→需恢复10/10 |
| **P2** | T2 ASI 映射退化 | v0.2.0 中 T2 映射 [ASI-04, ASI-05]，v0.3.0 中变为 [OWASP-AGENT-02]（格式不一致） | 报告质量 |
| **P2** | T5 翻倍至 71 | AGENT-028 在 deepagents 中过度触发 | 误报率 |

---

## 第二部分：v0.3.1 修复方案

### 修复 1：T1 LangChain 旧版 API 检测 [P0]

**问题：** AGENT-025/026/027 的 AST 匹配仅覆盖新版 API。

**T1 使用的旧版 API 模式：**
```python
# 旧版模式 1: ConversationalChatAgent
from langchain.agents import ConversationalChatAgent, AgentExecutor
agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools)
executor = AgentExecutor.from_agent_and_tools(agent=agent, tools=tools)

# 旧版模式 2: initialize_agent
from langchain.agents import initialize_agent, AgentType
agent = initialize_agent(tools, llm, agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION)

# 旧版模式 3: ZeroShotAgent
from langchain.agents import ZeroShotAgent, AgentExecutor
agent = ZeroShotAgent(llm_chain=llm_chain, tools=tools)
executor = AgentExecutor.from_agent_and_tools(agent=agent, tools=tools)
```

**修复：** 扩展 AGENT-025 的匹配范围，增加旧版 API 函数名列表。

### 修复 2：AGENT-028 框架白名单 [P1]

**问题：** AGENT-028 检测 "while loop without iteration limit" 或 "agent without max_iterations"。
crewAI 框架内部代码包含大量循环和 agent 定义，但 crewAI 自身有迭代控制机制，
扫描框架源码不应报这些。

**修复方案：**
- 类似 AGENT-018 的三级过滤，为 AGENT-028 添加框架白名单
- 白名单覆盖：crewAI 内部模块 (`crewai.*`)、deepagents 内部模块
- 区分 "扫描用户代码中对框架的调用" vs "扫描框架本身的源码"
- 如果扫描目标是框架仓库本身（检测 `packages/` 或 `src/crewai/` 等框架结构），对框架内部代码降低敏感度

### 修复 3：ASI-03 覆盖恢复 [P1]

**问题：** v0.2.0 中 ASI-03 (Identity & Privilege Abuse) 在 T3 和 T9 中被触发，
v0.3.0 中丢失。

**修复方案：**
1. 查找 v0.2.0 中哪些规则映射到 ASI-03（很可能是某些 AGENT-018 findings 或原有规则）
2. 如果是被白名单过滤了 → 确保至少保留 ASI-03 类别的检测能力
3. 如果是映射丢失 → 修复映射
4. 如果现有规则确实不覆盖 ASI-03 → 检查现有规则中是否有可以同时映射 ASI-03 的
   （例如 AGENT-038 agent_impersonation_risk 本质上也涉及身份滥用，可添加 ASI-03 映射）

### 修复 4：T2 ASI 映射格式统一 [P2]

**问题：** T2 输出 `OWASP-AGENT-02` 而非 `ASI-xx` 格式。

**修复：** 统一所有规则的 ASI 映射输出格式为 `ASI-xx`。

---

## 第三部分：Claude Code Prompts

### Prompt H1: T1 LangChain 旧版 API 检测修复 [P0]

```
你是 agent-audit 的核心开发者，正在修复一个 P0 级 bug：
T1 (damn-vulnerable-llm-agent) 在 v0.3.0 中仍然零检出。

## 根因
Claude Code 在 v0.3.0 中实现的 AGENT-025/026/027 规则只匹配新版 LangChain API:
- create_react_agent / create_openai_functions_agent
- AgentExecutor(...) 直接实例化

但 T1 使用旧版 API:
- ConversationalChatAgent.from_llm_and_tools()
- AgentExecutor.from_agent_and_tools()

## 你需要先做的
1. 阅读 T1 项目代码，确认其使用的 LangChain API 模式:
   ```bash
   ls /tmp/benchmark/repos/damn-vulnerable-llm-agent/
   cat /tmp/benchmark/repos/damn-vulnerable-llm-agent/*.py
   # 或者在项目的测试 fixtures 中找到 T1 相关代码
   ```
2. 阅读 AGENT-025 当前实现中的 AST 匹配逻辑
3. 阅读 AGENT-026 和 AGENT-027 的匹配逻辑

## 修复任务

### 任务 1: 扩展 AGENT-025 的函数名匹配

当前覆盖的函数/类（新版 API）:
```python
NEW_API = [
    "AgentExecutor",         # 直接实例化
    "create_react_agent",
    "create_openai_functions_agent",
    "create_structured_chat_agent",
    "create_tool_calling_agent",
]
```

需要新增的旧版 API:
```python
OLD_API = [
    # 旧版 Agent 类
    "ConversationalChatAgent",
    "ConversationalAgent",
    "ZeroShotAgent",
    "ChatAgent",
    "StructuredChatAgent",
    "OpenAIFunctionsAgent",
    "OpenAIMultiFunctionsAgent",
    "XMLAgent",
    "ReActDocstoreAgent",
    "ReActTextWorldAgent",
    "SelfAskWithSearchAgent",

    # 旧版工厂方法
    "initialize_agent",       # langchain.agents.initialize_agent()

    # 类方法模式
    # XXXAgent.from_llm_and_tools()
    # AgentExecutor.from_agent_and_tools()
]
```

AST 匹配需要扩展以捕获:
1. `XXXAgent.from_llm_and_tools(...)` — ast.Attribute 模式
2. `AgentExecutor.from_agent_and_tools(...)` — ast.Attribute 模式
3. `initialize_agent(tools, llm, agent=AgentType.XXX)` — ast.Call 模式

### 任务 2: 扩展 AGENT-026 的 tool 检测

当前 AGENT-026 仅检测 `@tool` 装饰器。T1 的 tools 可能使用旧版定义方式:
```python
# 旧版 Tool 定义
from langchain.agents import Tool
tools = [
    Tool(name="search", func=search_func, description="..."),
    Tool(name="calculator", func=calculator_func, description="..."),
]
```

需要额外检测:
- `Tool(name=..., func=some_function, ...)` — 追踪 `func` 参数指向的函数
- `StructuredTool.from_function(func=...)` — 同上

### 任务 3: 扩展 AGENT-027 的 prompt 模式

T1 可能使用旧版 prompt 构造:
```python
# 旧版
from langchain.prompts import PromptTemplate
template = PromptTemplate(
    input_variables=["input", "agent_scratchpad"],
    template="You are a helpful assistant. {input}"
)

# 或直接字符串
prefix = f"You are {role}. Help the user with {task}."
```

确保 AGENT-027 也检测:
- `PromptTemplate(template=f"...")` — f-string 在 template 参数中
- 变量拼接后赋值给 `prefix` / `suffix` / `system_message` 等

### 任务 4: 测试验证

在测试中添加 T1 风格的代码样本:
```python
# tests/test_langchain_rules.py 或对应位置追加

# Case: 旧版 AgentExecutor.from_agent_and_tools → 应触发 AGENT-025
code_old_agent = '''
from langchain.agents import ConversationalChatAgent, AgentExecutor
agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools)
executor = AgentExecutor.from_agent_and_tools(
    agent=agent, tools=tools, verbose=True
)
result = executor.run(user_input)
'''

# Case: initialize_agent → 应触发 AGENT-025
code_init_agent = '''
from langchain.agents import initialize_agent, AgentType
agent = initialize_agent(
    tools, llm,
    agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    verbose=True
)
'''

# Case: 旧版 Tool 定义中 func 指向不安全函数 → 应触发 AGENT-026
code_old_tool = '''
from langchain.agents import Tool
import subprocess
def run_command(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True).decode()
tools = [Tool(name="shell", func=run_command, description="Run shell")]
'''
```

## 端到端验证
```bash
# 修复后重新扫描 T1
agent-audit scan /tmp/benchmark/repos/damn-vulnerable-llm-agent --format json
# 预期: findings > 0, 包含 ASI-01 或 ASI-02 或 ASI-06
```

## 验收标准
□ T1 扫描 findings > 0
□ T1 至少覆盖 1 个 ASI 类别
□ 新增旧版 API 测试全部通过
□ 现有测试不受影响
□ T2-T11 的扫描结果无负面回归
```

---

### Prompt H2: AGENT-028 框架白名单 + T9 误报修复 [P1]

```
你是 agent-audit 的核心开发者，正在修复 P1 级问题：
T9 (crewAI) 的 findings 从 v0.2.0 的 124 飙升至 v0.3.0 的 739，
其中 AGENT-028 (Agent Without Iteration Limit) 贡献了 489 个 findings。

## 根因分析
AGENT-028 检测"缺少迭代限制的 agent/循环"。crewAI 作为成熟框架：
- 内部代码包含大量循环和 agent 定义（这是框架实现的一部分）
- crewAI 自身有迭代控制机制（max_iter 属性、内部 retry 逻辑）
- 扫描框架源码产生大量误报

同样的问题也影响 T5 (deepagents): findings 从 35 → 71。

## 你需要先做的
1. 阅读 AGENT-028 的当前实现逻辑
2. 查看 T9 扫描结果中 AGENT-028 的 findings 样本（哪些文件、哪些代码模式触发）:
   ```bash
   cat /tmp/benchmark/results/T9.json | python3 -c "
   import json, sys
   data = json.load(sys.stdin)
   findings = [f for f in data.get('findings', data) if f.get('rule_id') == 'AGENT-028']
   print(f'Total AGENT-028: {len(findings)}')
   # 打印前 10 个的 file 和 line
   for f in findings[:10]:
       print(f'{f.get(\"file\", \"?\")}:{f.get(\"line\", \"?\")} - {f.get(\"snippet\", \"\")[:80]}')
   "
   ```
3. 阅读 AGENT-018 的框架白名单实现（作为参考模式）

## 修复方案: 为 AGENT-028 添加框架感知过滤

### 方案 A: 框架源码检测（推荐）

当扫描目标是框架仓库本身时（而非用户项目中对框架的调用），
AGENT-028 应大幅降低敏感度。

检测框架仓库的信号:
- 目录结构含 `src/crewai/` 或 `crewai/` 作为 Python 包
- `pyproject.toml` / `setup.py` 中 `name = "crewai"` / `name = "deepagents"`
- 大量文件 import 自自身包名

当检测到扫描目标是框架仓库 → 对框架内部模块的 AGENT-028 findings 降级为 INFO。

### 方案 B: 白名单模块（与 AGENT-018 一致）

新增或扩展 `rules/allowlists/framework_iteration.yaml`:
```yaml
# AGENT-028 框架白名单
# 这些框架内部有自己的迭代控制机制

crewai:
  modules:
    - "crewai.agent"
    - "crewai.crew"
    - "crewai.task"
    - "crewai.tools"
    - "crewai.utilities"
    - "crewai.agents"
  rationale: "crewAI 内部通过 max_iter 属性和 CrewBase 控制迭代"

deepagents:
  modules:
    - "deepagents.agents"
    - "deepagents.tools"
    - "deepagents.workflows"
  rationale: "deepagents 框架内部有自己的执行控制"

langchain:
  modules:
    - "langchain.agents.agent"
    - "langchain.agents.executor"
    - "langchain_core.agents"
  rationale: "langchain AgentExecutor 内部有 max_iterations 默认值"

autogen:
  modules:
    - "autogen.agentchat"
    - "autogen.coding"
  rationale: "autogen 内部有 max_consecutive_auto_reply 控制"
```

### 方案 C: 文件路径过滤

如果当前扫描路径匹配以下模式，AGENT-028 降低敏感度:
- `*/site-packages/crewai/*`
- `*/crewai/src/crewai/*`
- 任何路径中包含框架名且该框架已在白名单中

### 推荐: 组合方案 B + C

1. 读取白名单 YAML
2. 对每个 AGENT-028 匹配:
   - 检查文件的 module path 是否匹配白名单
   - 检查文件路径是否在框架源码目录中
   - 如果匹配 → severity 降级为 INFO，confidence 设为 0.15

### 实现步骤

1. 创建 `rules/allowlists/framework_iteration.yaml`
2. 在 AGENT-028 检测逻辑中添加白名单过滤（复用 AGENT-018 的框架检测基础设施）
3. 添加 confidence 字段支持（如果 AGENT-028 还没有的话）

### 测试

```python
# 扫描框架源码中的循环 → 应被白名单过滤
code_framework_internal = '''
# 文件路径模拟: crewai/agents/executor.py
class CrewAgentExecutor:
    def _run(self):
        while not self._finished:
            self._step()
            if self._iterations >= self.max_iter:
                break
'''
# 预期: findings=0 或 severity=INFO

# 用户代码中无限循环调 LLM → 仍应检出
code_user_infinite = '''
# 文件路径: my_project/agent.py
while True:
    response = llm.invoke(prompt)
    if "DONE" in response:
        break
'''
# 预期: 仍触发 AGENT-028
```

## 端到端验证
```bash
# 重跑 T9
agent-audit scan /tmp/benchmark/repos/crewAI --format json | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Total: {len(d[\"findings\"])}')"
# 预期: findings < 200（从 739 大幅下降）
# AGENT-028 findings < 50（从 489 大幅下降）
```

## 验收标准
□ T9 总 findings < 200
□ T9 AGENT-028 findings < 50
□ T5 findings 回落到合理范围 (< 50)
□ T4/T6/T7/T8/T11 无负面回归
□ 用户代码中真正的无限循环仍被检出
□ 框架白名单 YAML 格式正确
```

---

### Prompt H3: ASI-03 覆盖恢复 + ASI 映射统一 [P1]

```
你是 agent-audit 的核心开发者，正在修复两个相关问题：
1. ASI-03 (Identity & Privilege Abuse) 在 v0.3.0 中回归丢失
2. T2 的 ASI 映射输出格式不一致 (OWASP-AGENT-02 而非 ASI-xx)

## 背景
v0.2.0 中 ASI-03 通过 T3 (langchain) 和 T9 (crewAI) 触发。
v0.3.0 中 ASI-03 未在任何项目中触发。
OWASP 覆盖从 8/10 变为 9/10（ASI-02 修复了，但 ASI-03 丢了）。

## 你需要先做的

### 1. 查找 v0.2.0 中 ASI-03 的来源
```bash
# 检查哪些规则映射到 ASI-03
grep -r "ASI-03\|ASI_03\|asi.03\|identity.*privilege\|privilege.*abuse" rules/ packages/ --include="*.py" --include="*.yaml" --include="*.yml"

# 查看 v0.2.0 的 T3 结果中 ASI-03 相关 findings
# (如果旧结果还在)
cat /tmp/benchmark/results/T3.json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    findings = data.get('findings', data)
    asi3 = [f for f in findings if 'ASI-03' in str(f.get('asi_category', '')) or 'ASI-03' in str(f.get('owasp', ''))]
    print(f'ASI-03 findings: {len(asi3)}')
    for f in asi3[:5]:
        print(json.dumps(f, indent=2)[:200])
except: print('No data')
"
```

### 2. 检查所有规则的 ASI 映射
```bash
# 列出所有规则及其 ASI 映射
grep -r "asi\|ASI\|owasp" rules/builtin/ --include="*.yaml" | sort
```

### 3. 检查 T2 的映射格式
```bash
grep -r "OWASP-AGENT\|owasp.agent" rules/ packages/ --include="*.py" --include="*.yaml"
```

## 修复任务

### 任务 1: 恢复 ASI-03 覆盖

ASI-03 (Identity & Privilege Abuse) 的定义:
> Agent 冒充其他身份、越权执行操作、或滥用特权

可能的修复路径（按优先级选择最适合的）:

**路径 A:** 如果 v0.2.0 中有规则映射 ASI-03 但 v0.3.0 中映射丢失
→ 恢复映射

**路径 B:** 如果 ASI-03 findings 是被 AGENT-018 白名单过滤掉的
→ 确保白名单不过滤涉及 identity/privilege 的 findings

**路径 C:** 为现有规则添加 ASI-03 映射（最可能需要）
- AGENT-038 (agent_impersonation_risk): 当前映射 ASI-09，
  但 agent 冒充身份本质上也是 ASI-03 (Identity Abuse)
  → **同时映射 ASI-03 和 ASI-09**
- AGENT-039 (trust_boundary_violation): agent 间无身份验证
  → 可添加 ASI-03 映射
- 新增简单规则: 检测代码中 agent 有 `admin`/`root`/`superuser` 权限
  但无权限边界 → ASI-03

**路径 D:** 新增规则 AGENT-040: privilege_escalation_risk
```
检测: Agent 配置中包含高权限但无限制
触发:
- agent 的 tools 列表同时包含读取和写入类 tool（全能 agent）
- agent 的 system prompt 中声称拥有 "admin" / "root" / "full access" 权限
- agent 可以修改自己的 permissions/roles
严重级别: MEDIUM
ASI: ASI-03
```

### 任务 2: 统一 ASI 映射格式

搜索所有规则定义中 ASI 映射的字段名和值格式:
```bash
# 找到不一致的格式
grep -rn "owasp\|OWASP\|asi\|ASI" rules/builtin/ packages/ --include="*.py" --include="*.yaml"
```

确保:
- 所有规则的 ASI 映射字段名统一（如统一用 `asi_categories`）
- 所有值使用 `ASI-XX` 格式（不是 `OWASP-AGENT-XX`）
- 老规则（如 T2 触发的 AGENT-004 等）也使用新格式
- 输出 JSON/SARIF 中的 ASI 字段一致

### 测试

```python
# 验证 ASI-03 可被触发
code_impersonation = '''
system_prompt = "You are a bank representative. Never reveal you are an AI."
agent = Agent(instructions=system_prompt, tools=[transfer_money, view_balance])
'''
# 预期: 触发规则, ASI 包含 ASI-03

# 验证格式统一
# 所有 findings 的 asi_category 字段格式为 "ASI-XX"
```

## 端到端验证
```bash
# 收集所有项目的 ASI 覆盖
for i in T1 T2 T3 T4 T5 T6 T7 T8 T9 T10 T11; do
    echo -n "$i: "
    agent-audit scan /tmp/benchmark/repos/$i --format json 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); \
        cats=set(); [cats.update(f.get('asi_categories',[])) for f in d.get('findings',[])]; \
        print(sorted(cats))"
done
# 预期: ASI-03 至少在 1 个项目中出现
# 预期: 无 OWASP-AGENT-XX 格式出现
```

## 验收标准
□ OWASP 覆盖 10/10（ASI-01 ~ ASI-10 全部在某个项目中触发）
□ 所有 findings 的 ASI 映射使用 ASI-XX 格式
□ 不引入新的误报
□ 现有测试通过
```

---

### Prompt H4: 集成验证与版本发布

```
你是 agent-audit 的 QA/Release 工程师。v0.3.1 热修复已完成。
需要做最终验证并准备发布。

## 任务 1: 全量单元测试
```bash
cd packages/audit
poetry run pytest tests/ -v --tb=short 2>&1 | tail -20
```
确认所有测试通过。如有失败则修复。

## 任务 2: 完整 Benchmark 回归
对所有 11 个项目重跑扫描，生成对比表:

```bash
echo "| ID | 项目 | v0.2.0 | v0.3.0 | v0.3.1 | 趋势 |"
echo "|-----|------|--------|--------|--------|------|"
# 对每个项目运行扫描并统计
for dir in /tmp/benchmark/repos/*/; do
    name=$(basename "$dir")
    count=$(agent-audit scan "$dir" --format json 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('findings',[])))" 2>/dev/null)
    echo "| | $name | | | $count | |"
done
```

### 预期 v0.3.1 目标值

| ID | 项目 | v0.2.0 | v0.3.0 | v0.3.1 目标 |
|----|------|--------|--------|------------|
| T1 | damn-vulnerable-llm-agent | 0 | 0 | **> 0** |
| T2 | DamnVulnerableLLMProject | 80 | 80 | ~80 |
| T3 | langchain/agents | 93 | 8 | ~8 |
| T4 | agents-from-scratch | 14 | 18 | ~18 |
| T5 | deepagents | 35 | 71 | **< 50** |
| T6 | openai-agents-python | 23 | 23 | ~23 |
| T7 | adk-python | 64 | 64 | ~64 |
| T8 | agentscope | 19 | 26 | ~26 |
| T9 | crewAI | 124 | 739 | **< 200** |
| T10 | 100-tool-mcp-server-json | 0 | 18 | ~18 |
| T11 | streamlit-agent | 1 | 4 | ~4 |

## 任务 3: OWASP 覆盖验证
确认 10/10 ASI 类别全部在至少一个项目中被触发。

## 任务 4: 输出格式验证
随机选一个项目的 JSON 输出，检查:
- 所有 findings 有 `confidence` 字段
- ASI 映射格式统一为 `ASI-XX`
- SARIF 输出有效

## 任务 5: 版本更新
1. 更新 pyproject.toml 版本号为 0.3.1
2. 更新 CHANGELOG.md 添加 v0.3.1 条目:
   - 修复: T1 零检出 — 扩展 LangChain 旧版 API 覆盖
   - 修复: T9 crewAI 误报 — AGENT-028 添加框架白名单
   - 修复: ASI-03 覆盖恢复
   - 修复: ASI 映射格式统一

## 验收标准
□ 所有单元测试通过
□ T1 findings > 0
□ T9 findings < 200
□ OWASP 10/10
□ 无格式不一致
□ 版本号和 CHANGELOG 已更新
```

---

## 附录：执行关系图

```
v0.3.0 benchmark 结果
        │
        ├──→ Prompt H1: T1 旧版 LangChain [P0]
        ├──→ Prompt H2: AGENT-028 白名单 [P1]  ← 可与 H1 并行
        └──→ Prompt H3: ASI-03 + 格式统一 [P1] ← 可与 H1/H2 并行
                │
                └──→ Prompt H4: 集成验证 + 发布
```

**H1/H2/H3 相互独立，可以并行执行，最后 H4 收尾验证。**

**预计工作量:** 每个 Prompt 约 20-40 分钟，总计约 2-3 小时。

---

## 版本对比汇总（预期）

| 指标 | v0.2.0 | v0.3.0 | v0.3.1(目标) |
|------|--------|--------|-------------|
| T1 检出 | 0 | 0 | > 0 ✅ |
| T9 findings | 124 | 739 | < 200 ✅ |
| OWASP 覆盖 | 8/10 | 9/10 | **10/10** ✅ |
| 检出率 | ⚠️ | ⚠️ | ✅ |
| 误报率 | ⚠️ | ❌ | ✅ |
| 健壮性 | ✅ | ✅ | ✅ |
| 最终评级 | 🟡 | 🟡 | 🟢 |
