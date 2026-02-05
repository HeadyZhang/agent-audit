# Claude Code 执行提示词 — agent-audit v0.2.0 真实项目基准测试

---

## 提示词正文

```
## 你的角色

你是一个 QA 基准测试工程师。你的任务是用 agent-audit v0.2.0 扫描一系列真实开源 AI Agent 项目，收集扫描结果，生成结构化的基准测试报告。

你不修改 agent-audit 的源码。你不修复被测项目。你只做扫描、记录、分析。

## 前置准备

先执行以下命令确认环境就绪：

```bash
agent-audit --version
# 断言：输出 0.2.0。如果不是，先执行 pip install agent-audit==0.2.0 --force-reinstall
```

创建工作目录：

```bash
mkdir -p /tmp/benchmark/{repos,results}
```

---

## 测试矩阵

共 3 层、11 个目标。严格按 T1 → T11 顺序执行。

### 第一层：故意漏洞项目（期望高检出率）

| ID  | 仓库                                                    | 扫描路径                | 预期 |
|-----|---------------------------------------------------------|------------------------|------|
| T1  | ReversecLabs/damn-vulnerable-llm-agent                  | 整个仓库               | 应报出 5+ critical/high |
| T2  | harishsg993010/DamnVulnerableLLMProject                 | 整个仓库               | 应报出 5+ critical/high |

### 第二层：真实 Agent 框架（验证误报率 + 真实覆盖）

| ID  | 仓库                                                    | 扫描路径                              | 预期 |
|-----|---------------------------------------------------------|--------------------------------------|------|
| T3  | langchain-ai/langchain                                  | libs/langchain/langchain/agents/     | 有 findings 但 critical < 20 |
| T4  | langchain-ai/agents-from-scratch                        | src/                                 | 有 findings |
| T5  | langchain-ai/deepagents                                 | 整个仓库                              | 有 findings，尤其 ASI-03/10 |
| T6  | openai/openai-agents-python                             | src/                                 | 有 findings |
| T7  | google/adk-python                                       | src/ 或 google/                      | 有 findings |
| T8  | agentscope-ai/agentscope                                | agentscope/ 或 src/                  | 应检出 ASI-05 (execute_shell_command) |
| T9  | crewAIInc/crewAI                                        | crewai/ 或 src/                      | 有 findings |

### 第三层：MCP 配置文件（测试 MCP Scanner）

| ID  | 仓库                                                    | 扫描路径                | 预期 |
|-----|---------------------------------------------------------|------------------------|------|
| T10 | angrysky56/100-tool-mcp-server-json-example             | 整个仓库               | 应检出 hardcoded credentials |
| T11 | langchain-ai/streamlit-agent                            | 整个仓库               | 应检出 ASI-05 (PythonAstREPLTool) |

---

## 每个目标的执行流程

对每个 T{N}，严格执行以下 5 步：

### 步骤 1：克隆

```bash
git clone --depth 1 https://github.com/{owner}/{repo}.git /tmp/benchmark/repos/{repo}
```

如果 clone 失败（网络问题、仓库不存在、重命名），记录为 ⚠️ SKIP 并继续下一个。不要卡住。

### 步骤 2：确认扫描路径

```bash
ls /tmp/benchmark/repos/{repo}/
```

根据实际目录结构确定扫描路径。测试矩阵中的路径是预估值——以实际 ls 结果为准。原则：

- 如果矩阵指定了子路径且存在 → 用子路径（减少扫描时间）
- 如果矩阵指定的子路径不存在 → 扫描整个仓库
- 对于大型仓库（langchain），必须限定子路径，避免扫描 10 分钟+

### 步骤 3：执行扫描

```bash
agent-audit scan {实际扫描路径} --format json > /tmp/benchmark/results/T{N}-{repo}.json 2>/tmp/benchmark/results/T{N}-{repo}.stderr
echo "Exit code: $?"
```

关键：
- 超时保护：如果某个扫描 3 分钟还没完成，Ctrl+C 中断，记录为 ⏰ TIMEOUT
- 如果 agent-audit 自身 crash（traceback），这是 agent-audit 的 bug，完整记录 stderr
- 即使 exit code 非 0 也继续，不要中断整个流程

### 步骤 4：提取关键指标

```bash
python3 -c "
import json, sys
try:
    with open('/tmp/benchmark/results/T{N}-{repo}.json') as f:
        data = json.load(f)
except Exception as e:
    print(f'JSON parse error: {e}')
    sys.exit(0)

# 适配可能的输出格式差异
findings = data.get('findings', data.get('results', []))
if not isinstance(findings, list):
    print(f'Unexpected findings type: {type(findings)}')
    sys.exit(0)

total = len(findings)

# 按严重性统计
severity_count = {}
for f in findings:
    sev = f.get('severity', f.get('level', 'unknown'))
    severity_count[sev] = severity_count.get(sev, 0) + 1

# 按规则统计
rule_count = {}
for f in findings:
    rid = f.get('rule_id', f.get('ruleId', 'unknown'))
    rule_count[rid] = rule_count.get(rid, 0) + 1

# 提取 OWASP 覆盖
owasp_hit = set()
for f in findings:
    oid = f.get('owasp_agentic_id', '')
    if oid:
        owasp_hit.add(oid)
    # 也从 rule_id 推断
    rid = f.get('rule_id', f.get('ruleId', ''))
    # AGENT-010~011 → ASI-01, AGENT-013~014 → ASI-03, etc.
    agent_to_asi = {
        'AGENT-001': 'ASI-05', 'AGENT-002': 'ASI-03', 'AGENT-003': 'ASI-09',
        'AGENT-004': 'ASI-04', 'AGENT-005': 'ASI-04',
        'AGENT-010': 'ASI-01', 'AGENT-011': 'ASI-01',
        'AGENT-013': 'ASI-03', 'AGENT-014': 'ASI-03',
        'AGENT-015': 'ASI-04', 'AGENT-016': 'ASI-04',
        'AGENT-017': 'ASI-05', 'AGENT-018': 'ASI-06', 'AGENT-019': 'ASI-06',
        'AGENT-020': 'ASI-07', 'AGENT-021': 'ASI-08', 'AGENT-022': 'ASI-08',
        'AGENT-023': 'ASI-09', 'AGENT-024': 'ASI-10', 'AGENT-025': 'ASI-10',
    }
    if rid in agent_to_asi:
        owasp_hit.add(agent_to_asi[rid])

print(f'Total findings: {total}')
print(f'By severity: {dict(sorted(severity_count.items()))}')
print(f'Top 5 rules: {dict(sorted(rule_count.items(), key=lambda x: -x[1])[:5])}')
print(f'OWASP ASI covered: {sorted(owasp_hit)} ({len(owasp_hit)}/10)')
"
```

### 步骤 5：记录结果行

在终端打印这一行标准化摘要（后面汇总用）：

```
[T{N}] {repo} | {total} findings | critical:{n} high:{n} medium:{n} low:{n} | OWASP: {ASI-列表} | {状态}
```

状态值：✅ PASS / ❌ CRASH / ⏰ TIMEOUT / ⚠️ SKIP

---

## 特殊情况处理

### agent-audit 自身 crash

如果扫描某个项目时 agent-audit 出现 Python traceback：

```bash
cat /tmp/benchmark/results/T{N}-{repo}.stderr
```

完整记录 traceback，标记为 ❌ CRASH。这是 agent-audit 的 bug，需要后续修复。继续测下一个项目。

### JSON 输出为空或格式异常

```bash
wc -c /tmp/benchmark/results/T{N}-{repo}.json
cat /tmp/benchmark/results/T{N}-{repo}.json | head -20
```

记录实际输出内容，标记为 ⚠️ FORMAT_ERROR。继续下一个。

### 大型仓库扫描过慢

如果 ls 发现仓库特别大（如 langchain 有 3000+ 文件），先确认子路径再扫描：

```bash
find /tmp/benchmark/repos/{repo}/ -name "*.py" | wc -l
```

如果 Python 文件 > 500 且扫描路径是整个仓库，缩小范围到最相关的子目录。

---

## 最终输出

所有 T1~T11 完成后，生成以下三份报告：

### 报告 1：总览表

```
===== agent-audit v0.2.0 基准测试报告 =====
日期: {当前日期}
测试目标: 11 个开源 AI Agent 项目

| ID  | 项目                          | Findings | Critical | High | Medium | Low | OWASP 覆盖    | 状态 |
|-----|-------------------------------|----------|----------|------|--------|-----|---------------|------|
| T1  | damn-vulnerable-llm-agent     |          |          |      |        |     |               |      |
| T2  | DamnVulnerableLLMProject      |          |          |      |        |     |               |      |
| T3  | langchain/agents              |          |          |      |        |     |               |      |
| T4  | agents-from-scratch           |          |          |      |        |     |               |      |
| T5  | deepagents                    |          |          |      |        |     |               |      |
| T6  | openai-agents-python          |          |          |      |        |     |               |      |
| T7  | adk-python                    |          |          |      |        |     |               |      |
| T8  | agentscope                    |          |          |      |        |     |               |      |
| T9  | crewAI                        |          |          |      |        |     |               |      |
| T10 | 100-tool-mcp-server-json      |          |          |      |        |     |               |      |
| T11 | streamlit-agent               |          |          |      |        |     |               |      |
```

### 报告 2：质量评估

根据以下标准判定 agent-audit 的质量：

**检出率（故意漏洞项目 T1-T2）**
- ✅ 优秀：每个项目报出 5+ findings，且覆盖 3+ ASI 类别
- ⚠️ 一般：有 findings 但 < 5 或 ASI 覆盖 < 3
- ❌ 差：0 findings 或 crash

**误报率（真实框架 T3-T9）**
- ✅ 优秀：findings 合理（每个项目 < 50），无明显误报
- ⚠️ 一般：个别项目 findings 过多（50-200）但大部分合理
- ❌ 差：某个项目 200+ findings，或大量明显误报

**健壮性（全部 T1-T11）**
- ✅ 优秀：0 crash, 0 timeout
- ⚠️ 一般：1-2 crash 或 timeout
- ❌ 差：3+ crash

**OWASP 覆盖（全部 T1-T11 合并）**
- ✅ 优秀：10 个 ASI 类别中至少 7 个被触发
- ⚠️ 一般：4-6 个被触发
- ❌ 差：< 4 个被触发

给出最终综合评级：🟢 发布质量达标 / 🟡 可发布但需改进 / 🔴 需重大修复

### 报告 3：发现的 agent-audit 自身问题

列出在测试过程中发现的 agent-audit 问题（如果有）：

```
| 问题类型     | 项目    | 描述                                | 严重性 |
|-------------|---------|-------------------------------------|--------|
| CRASH       | T{N}    | traceback: ...                      | P0     |
| FALSE_POS   | T{N}    | 规则 X 误报：...                    | P1     |
| MISS        | T{N}    | 明显应检出但未检出：...              | P1     |
| FORMAT      | T{N}    | JSON 输出异常：...                  | P2     |
| PERF        | T{N}    | 扫描时间过长 > 3min                 | P2     |
```

将三份报告合并写入：

```bash
cat > /tmp/benchmark/BENCHMARK-REPORT.md << 'REPORT_EOF'
{报告内容}
REPORT_EOF
```

---

## 执行规则

1. 严格按 T1 → T11 顺序。不跳步，不并行。
2. 每个目标完成后立即打印标准化摘要行，不要攒到最后。
3. 任何一个目标的失败不阻断后续目标——记录后继续。
4. 不修改 agent-audit 源码。不修改被测项目。
5. 如果 clone 失败，重试一次。两次都失败则 SKIP。
6. 对大型仓库（langchain, agentscope），务必用子路径扫描，不要扫整个仓库。
7. 始终保留 stderr 输出——crash 诊断需要它。

现在开始。先确认 agent-audit --version，然后从 T1 开始。
```

---

## 精简版（如果上下文窗口紧张）

```
你是 QA 工程师。用 agent-audit v0.2.0 依次扫描以下 11 个项目，每个项目执行：git clone --depth 1 → 确认路径 → agent-audit scan {path} --format json > /tmp/benchmark/results/T{N}.json 2>stderr → 提取 findings 数、severity 分布、OWASP 覆盖 → 打印单行摘要。

目标列表：
T1  ReversecLabs/damn-vulnerable-llm-agent（整个仓库）
T2  harishsg993010/DamnVulnerableLLMProject（整个仓库）
T3  langchain-ai/langchain（libs/langchain/langchain/agents/）
T4  langchain-ai/agents-from-scratch（src/）
T5  langchain-ai/deepagents（整个仓库）
T6  openai/openai-agents-python（src/）
T7  google/adk-python（src/ 或 google/）
T8  agentscope-ai/agentscope（agentscope/ 或 src/）
T9  crewAIInc/crewAI（crewai/ 或 src/）
T10 angrysky56/100-tool-mcp-server-json-example（整个仓库）
T11 langchain-ai/streamlit-agent（整个仓库）

完成后输出总览表 + 质量评估（检出率/误报率/健壮性/OWASP覆盖）+ agent-audit 自身问题列表。写入 /tmp/benchmark/BENCHMARK-REPORT.md。

每个目标如果 crash 或 timeout 则记录后继续，不阻断。大型仓库用子路径扫描。先确认 agent-audit --version 然后从 T1 开始。
```
