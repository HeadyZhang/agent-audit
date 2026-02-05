# agent-audit v0.3.2 双次 Benchmark 偏差分析 & v0.4.0 方案

> **日期: 2026-02-04**
> **核心发现：同版本两次 benchmark 结果差异巨大，需先修 benchmark 再修工具**

---

## 第一部分：v0.3.2 两次 Benchmark 对比

### Findings 数量偏差

| ID | 项目 | Run1 | Run2 | 差值 | 倍数 |
|----|------|------|------|------|------|
| T1 | damn-vulnerable-llm-agent | 3 | 3 | 0 | — |
| T2 | DamnVulnerableLLMProject | 82 | 82 | 0 | — |
| T3 | langchain | **389** | **9** | -380 | 43x |
| T4 | agents-from-scratch | 18 | 18 | 0 | — |
| T5 | deepagents | 151 | 151 | 0 | — |
| T6 | openai-agents-python | **117** | **47** | -70 | 2.5x |
| T7 | adk-python | **145** | **64** | -81 | 2.3x |
| T8 | agentscope | **21** | **3** | -18 | 7x |
| T9 | crewAI | **134** | **107** | -27 | 1.3x |
| T10 | MCP Config | 19 | 19 | 0 | — |
| T11 | streamlit-agent | 6 | 6 | 0 | — |
| **合计** | | **1,155** | **509** | **-646** | 2.3x |

**稳定项 (5/11):** T1, T2, T4, T5, T10, T11 — 两次结果完全一致。
**不稳定项 (6/11):** T3, T6, T7, T8, T9 — 差异从 1.3x 到 43x。

### ASI 映射偏差（最关键）

| ID | 项目 | Run1 ASI | Run2 ASI |
|----|------|----------|----------|
| T1 | DVLLM | ASI-01, ASI-02 | **—** (无) |
| T2 | DamnVuln | ASI-01, ASI-02 | **ASI-04, ASI-05** |
| T3 | langchain | ASI-01,02,05,06,08 | **—** (无) |
| T5 | deepagents | ASI-01,02,07,08 | ASI-01,**04**,05,07,08 |
| T6 | openai-agents | ASI-02,06,07,08,09 | **ASI-04**,06 |
| T7 | adk-python | ASI-02,06,07,08,09 | **ASI-04**,06 |
| T9 | crewAI | ASI-01,02,07,08,10 | ASI-01,**03,04**,05,07,08,10 |

**关键发现：**
- **ASI-02 在 Run1 广泛出现，Run2 完全消失** — 变成了 ASI-04
- **ASI-09 在 Run1 出现 2 次，Run2 完全消失**
- **ASI-03 在 Run2 出现（T9），Run1 中不在 T9**
- **ASI-04 在 Run2 大量出现，Run1 中罕见**

### OWASP 覆盖对比

| ASI | Run1 | Run2 |
|-----|------|------|
| ASI-01 | ✅ | ✅ |
| ASI-02 | ✅ | ❌ |
| ASI-03 | ✅ (T10) | ✅ (T9) |
| ASI-04 | ✅ | ✅ |
| ASI-05 | ✅ | ✅ |
| ASI-06 | ✅ | ✅ |
| ASI-07 | ✅ | ✅ |
| ASI-08 | ✅ | ✅ |
| ASI-09 | ✅ | ❌ |
| ASI-10 | ✅ | ✅ |
| **总计** | **10/10** | **8/10** |

---

## 第二部分：偏差根因分析

### 根因 1：扫描范围不一致

T3 的差异（389 vs 9）是最强信号：

| 版本/次 | T3 标注 | Findings | 推测扫描范围 |
|---------|---------|----------|-------------|
| v0.2.0 | langchain/core | 93 | `langchain-core` 子包 |
| v0.3.0 | langchain/agents | 8 | `langchain/agents` 子目录 |
| v0.3.1 | langchain/agents | 10 | 同上 |
| v0.3.2 Run1 | langchain | **389** | **整个 langchain 仓库** |
| v0.3.2 Run2 | langchain/agents | **9** | `langchain/agents` 子目录 |

**结论：Run1 扫描了整个 langchain 仓库（包含 libs/langchain, libs/core,
libs/community 等），Run2 只扫描了 langchain/agents 子目录。**

这同样解释了 T6/T7/T8 的差异 — 不同 benchmark 脚本可能扫描了不同的目录层级。

### 根因 2：ASI 映射提取逻辑不一致

Run2 报告注明"脚本原设计为 v0.2.0"。两次 run 使用了不同的 benchmark 脚本，
对 ASI 类别的提取字段名不同：

| 字段 | Run1 脚本 | Run2 脚本 (v0.2.0 原版) |
|------|----------|------------------------|
| 提取字段 | `asi_categories` (v0.3.x 新字段) | `owasp_agentic_id` (v0.2.0 原字段) |
| T2 映射 | ASI-01, ASI-02 | ASI-04, ASI-05 |

**结论：代码中可能存在两套 ASI 映射字段（新旧并存），两个脚本各读一套，
导致同一 finding 报出不同的 ASI 类别。**

### 根因 3：框架白名单生效范围可能受扫描路径影响

T8 (agentscope) 从 21→3，差异 7 倍。如果 Run1 扫描了 agentscope 完整仓库
（含 examples/tests/docs），而 Run2 只扫描了 src/，白名单对 examples 目录可能不生效。

---

## 第三部分：哪次 Run 更可信？

| 维度 | Run1 | Run2 | 判断 |
|------|------|------|------|
| 脚本来源 | v0.3.2 新脚本 | v0.2.0 原始脚本 | Run2 更成熟 |
| 扫描范围 | 可能不一致 | 与 v0.2.0 基线一致 | **Run2 更可对比** |
| ASI 提取 | 新字段 | 旧字段 | Run1 更准确（如果代码迁移完成） |
| T3 合理性 | 389 (整仓库) | 9 (子目录) | 取决于扫描目标定义 |

**判断：** 两次 Run 都不完全可信。需要先标准化 benchmark 再评估工具。

---

## 第四部分：v0.3.2 真实状态评估（综合两次 Run）

取两次 Run 中更合理/可解释的数据：

| ID | 项目 | 可信值 | 依据 | 评估 |
|----|------|--------|------|------|
| T1 | DVLLM | **3** | 两次一致 | ⚠️ 偏低 |
| T2 | DamnVuln | **82** | 两次一致 | ⚠️ ASI 窄 |
| T3 | langchain | **9** (子目录) / **389** (全仓) | 取决于扫描定义 | ✅/❌ |
| T4 | from-scratch | **18** | 两次一致 | ✅ |
| T5 | deepagents | **151** | 两次一致 | ⚠️ 需查 AGENT-041 |
| T6 | openai-agents | **47** (Run2) | Run2 范围与 v0.2.0 一致 | ✅ (23→47 合理) |
| T7 | adk-python | **64** (Run2) | Run2 与 v0.2.0/v0.3.1 一致 | ✅ 稳定 |
| T8 | agentscope | **3-21** | 范围问题 | 需标准化 |
| T9 | crewAI | **107-134** | 范围问题 | ✅ 趋势向好 (vs 739) |
| T10 | MCP | **19** | 两次一致 | ✅ |
| T11 | streamlit | **6** | 两次一致 | ✅ |

### 真实 OWASP 覆盖

合并两次 Run 的 ASI 触发（因为是同一份代码的不同字段提取）：
- ASI-01 ✅ | ASI-02 ✅(Run1) | ASI-03 ✅ | ASI-04 ✅ | ASI-05 ✅
- ASI-06 ✅ | ASI-07 ✅ | ASI-08 ✅ | ASI-09 ✅(Run1) | ASI-10 ✅

**如果两套字段都正确提取 → 10/10**。问题在于提取逻辑不统一。

---

## 第五部分：v0.4.0 方案 — 基础设施优先

### 策略

四轮迭代暴露的最大问题不是规则质量，而是**测量质量**：
- benchmark 扫描范围不一致 → 无法横向比较
- ASI 映射新旧字段并存 → OWASP 覆盖数据不可信
- CC 执行报告 vs 实际 benchmark 偏差 → 决策依据错误

**v0.4.0 优先修基础设施，再优化规则。**

### 优先级

| 优先级 | 任务 | 目标 |
|--------|------|------|
| **P0** | 标准化 benchmark | 所有版本可复现比较 |
| **P0** | 统一 ASI 映射 | 一套字段、一个提取逻辑 |
| **P1** | T5 AGENT-041 误报 | T5 < 90 |
| **P1** | T1/T2 检出提升 | T1 ≥ 5, T2 ASI ≥ 3 |
| **P2** | ASI-09 覆盖 | 在实际项目中触发 |

---

## 第六部分：Claude Code Prompts

### Prompt B0: Benchmark 标准化 [P0]

```
你是 agent-audit 项目的基础设施工程师。
当前最关键的问题是 benchmark 不可复现，导致四轮迭代的数据无法可靠比较。

## 背景
v0.3.2 的两次 benchmark 运行产生了完全不同的结果：
- T3: 389 vs 9（43倍差异）
- T6: 117 vs 47（2.5倍差异）
- ASI 映射完全不同（同一 finding 报 ASI-02 或 ASI-04）
- OWASP 覆盖 10/10 vs 8/10

根因：
1. 扫描范围不一致（整仓库 vs 子目录）
2. ASI 提取字段不一致（asi_categories vs owasp_agentic_id）
3. 无标准化的 benchmark 配置文件

## 任务 1: 创建标准化 Benchmark 配置

创建 `tests/benchmark/benchmark_config.yaml`:

```yaml
# agent-audit Benchmark 标准配置
# 所有版本的 benchmark 必须使用此配置以确保可比性

version: 1
date_created: "2026-02-04"

targets:

  # ===== 故意漏洞项目 =====
  T1:
    name: "damn-vulnerable-llm-agent"
    repo: "https://github.com/WithSecureLabs/damn-vulnerable-llm-agent"
    ref: "main"  # 锁定分支
    scan_path: "."  # 扫描整个仓库
    category: "intentional_vuln"
    expected_min_findings: 3
    expected_asi_min: 2

  T2:
    name: "DamnVulnerableLLMProject"
    repo: "https://github.com/harishsg993010/DamnVulnerableLLMProject"
    ref: "main"
    scan_path: "."
    category: "intentional_vuln"
    expected_min_findings: 50
    expected_asi_min: 3

  # ===== 真实框架 =====
  T3:
    name: "langchain-core"
    repo: "https://github.com/langchain-ai/langchain"
    ref: "master"
    scan_path: "libs/core"  # ← 锁定扫描路径！
    category: "framework"
    expected_max_findings: 50  # 框架项目设上限

  T4:
    name: "agents-from-scratch"
    repo: "https://github.com/neural-maze/agents-from-scratch"
    ref: "main"
    scan_path: "."
    category: "educational"

  T5:
    name: "deepagents"
    repo: "https://github.com/agiresearch/deepagents"
    ref: "main"
    scan_path: "."
    category: "framework"
    expected_max_findings: 100

  T6:
    name: "openai-agents-python"
    repo: "https://github.com/openai/openai-agents-python"
    ref: "main"
    scan_path: "src"  # ← 只扫源码，不含 tests/examples
    category: "framework"

  T7:
    name: "adk-python"
    repo: "https://github.com/google/adk-python"
    ref: "main"
    scan_path: "src"
    category: "framework"

  T8:
    name: "agentscope"
    repo: "https://github.com/modelscope/agentscope"
    ref: "main"
    scan_path: "src/agentscope"  # ← 只扫核心包
    category: "framework"

  T9:
    name: "crewAI"
    repo: "https://github.com/crewAIInc/crewAI"
    ref: "main"
    scan_path: "src/crewai"  # ← 只扫核心包
    category: "framework"
    expected_max_findings: 150

  T10:
    name: "100-tool-mcp-server"
    repo: "local"
    scan_path: "tests/benchmark/fixtures/mcp_config.json"
    category: "config"

  T11:
    name: "streamlit-agent"
    repo: "https://github.com/pablomarin/streamlit-agent"
    ref: "main"
    scan_path: "."
    category: "application"

# ASI 提取配置
asi_extraction:
  primary_field: "asi_categories"
  fallback_field: "owasp_agentic_id"
  format: "ASI-XX"  # 统一格式

# 输出
output:
  format: "json"
  include_fields:
    - rule_id
    - severity
    - confidence
    - asi_categories
    - file
    - line
```

## 任务 2: 创建 Benchmark Runner 脚本

创建 `tests/benchmark/run_benchmark.py`:

```python
"""
标准化 benchmark runner。
用法: python tests/benchmark/run_benchmark.py [--config benchmark_config.yaml]

功能:
1. 从 config 读取目标列表和扫描路径
2. 克隆/更新仓库（锁定 ref）
3. 对每个目标执行 agent-audit scan
4. 统一提取 ASI 类别（兼容新旧字段名）
5. 生成标准化报告（Markdown + JSON）
6. 与上一次结果对比，高亮变化
"""
```

关键实现要点：

### 2.1 统一 ASI 提取
```python
def extract_asi_categories(finding: dict) -> list[str]:
    """从 finding 中提取 ASI 类别，兼容新旧字段名"""
    # 优先新字段
    categories = finding.get("asi_categories", [])
    if not categories:
        # fallback 到旧字段
        old_id = finding.get("owasp_agentic_id", "")
        if old_id:
            categories = [old_id] if isinstance(old_id, str) else old_id
    # 统一格式为 ASI-XX
    normalized = []
    for cat in categories:
        cat = str(cat).strip().upper()
        if cat.startswith("ASI-"):
            normalized.append(cat)
        elif cat.startswith("OWASP-AGENT-"):
            # 映射旧格式
            num = cat.replace("OWASP-AGENT-", "").zfill(2)
            normalized.append(f"ASI-{num}")
    return sorted(set(normalized))
```

### 2.2 结果对比
```python
def compare_results(current: dict, previous: dict) -> dict:
    """对比两次 benchmark 结果"""
    comparison = {}
    for target_id in current:
        cur = current[target_id]
        prev = previous.get(target_id, {})
        comparison[target_id] = {
            "findings_current": cur["total_findings"],
            "findings_previous": prev.get("total_findings", "N/A"),
            "delta": cur["total_findings"] - prev.get("total_findings", 0),
            "asi_current": cur["asi_categories"],
            "asi_previous": prev.get("asi_categories", []),
            "regression": cur["total_findings"] > prev.get("total_findings", 0) * 1.2
        }
    return comparison
```

### 2.3 报告生成
输出 `benchmark_report.md` 包含:
- 总览表（与当前报告格式一致）
- 与上次对比表（delta 列）
- 质量评估（自动计算检出率/误报率/OWASP 覆盖）
- 自动判定综合评级

## 任务 3: 统一代码中的 ASI 映射

```bash
# 查找所有 ASI 映射相关字段
grep -rn "owasp_agentic_id\|asi_categories\|OWASP-AGENT\|ASI-" \
    rules/ packages/ --include="*.py" --include="*.yaml" | \
    grep -v "test\|benchmark\|__pycache__"
```

确保:
1. 所有规则 YAML 中使用统一字段名 `asi_categories: [ASI-XX]`
2. 如果仍保留 `owasp_agentic_id`，确保其值与 `asi_categories` 一致
3. Reporter 输出 JSON 中两个字段都有（向后兼容），但 `asi_categories` 为主

## 任务 4: 验证

```bash
# 用标准化脚本运行一次 benchmark
cd tests/benchmark
python run_benchmark.py --config benchmark_config.yaml

# 检查输出报告
cat benchmark_report.md

# 验证 ASI 一致性：同一 finding 的两个字段应一致
python3 -c "
import json, glob
for f in glob.glob('/tmp/benchmark/results/*.json'):
    data = json.load(open(f))
    findings = data.get('findings', data) if isinstance(data, dict) else data
    for finding in findings[:5]:
        asi_new = finding.get('asi_categories', [])
        asi_old = finding.get('owasp_agentic_id', '')
        if asi_new or asi_old:
            print(f'{finding.get(\"rule_id\")}: new={asi_new} old={asi_old}')
"
```

## 验收标准
□ benchmark_config.yaml 定义了所有 12 个目标的精确扫描路径
□ run_benchmark.py 可一键运行完整 benchmark
□ 报告自动生成且格式标准
□ ASI 字段统一，两次运行同一代码产生一致结果
□ 现有测试不受影响
```

---

### Prompt B1: AGENT-041 精度修复 + T5 误报 [P1]

```
你是 agent-audit 的核心开发者。在 Benchmark 标准化后（B0），
处理 T5 (deepagents) 的误报问题。

## 前置条件
B0 已完成，benchmark 标准化脚本可用。

## 问题
T5 deepagents 有 151 findings，其中 AGENT-041 (SQL injection) 贡献 86 个。
deepagents 是一个 AI agent 研究框架，不太可能有 86 个真正的 SQL injection。

## 阶段 1: 诊断

用标准化 benchmark 重新扫描 T5 并分析 AGENT-041:
```bash
# 用标准化脚本扫描
agent-audit scan /tmp/benchmark/repos/deepagents --format json > /tmp/t5_results.json

# 分析 AGENT-041 的触发模式
python3 -c "
import json
data = json.load(open('/tmp/t5_results.json'))
findings = data.get('findings', [])
a041 = [f for f in findings if f.get('rule_id') == 'AGENT-041']
print(f'AGENT-041 total: {len(a041)}')

# 按文件分组
files = {}
for f in a041:
    fp = f.get('file', '?')
    files[fp] = files.get(fp, 0) + 1
print('\nBy file:')
for fp, count in sorted(files.items(), key=lambda x: -x[1])[:10]:
    print(f'  {count:3d} | {fp}')

# 打印典型样本
print('\nSamples:')
for f in a041[:5]:
    print(f'  {f.get(\"file\")}:{f.get(\"line\")}')
    print(f'  {f.get(\"snippet\", \"\")[:120]}')
    print()
"
```

## 阶段 2: 根据诊断结果修复

阅读 AGENT-041 当前实现。根据 T5 误报样本判断:

如果误报主要是非 SQL 的 f-string → 收紧触发条件（参考 v0.4.0 G1 方案）:
- 仅在 f-string 结果传入 DB 执行函数时触发
- 或字符串变量名含 sql/query 且传入执行函数
- 或字符串以 SQL 关键字开头

如果误报主要是框架内部代码 → 添加框架白名单

## 阶段 3: 验证

```bash
# 标准化 benchmark 重跑 T5 及关联项目
for project in T1 T2 T5; do
    echo "=== $project ==="
    agent-audit scan /tmp/benchmark/repos/$project --format json | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(f'findings: {len(d.get(\"findings\",[]))}')"
done
```

## 验收标准
□ T5 findings < 90（从 151 下降）
□ T1 findings >= 3（不回归）
□ T2 findings >= 80（不回归）
□ 标准化 benchmark 全量跑通
```

---

### Prompt B2: T1/T2 精准检出 + ASI-09 [P1]

```
B0 和 B1 完成后执行此 Prompt。

## 任务 1: T1 检出提升

用标准化 benchmark 的精确扫描路径重跑 T1，然后逐文件分析:

```bash
find /tmp/benchmark/repos/damn-vulnerable-llm-agent -name "*.py" -exec echo "=== {} ===" \; -exec cat {} \;
```

对每个文件输出:
| 文件 | 安全风险 | 当前匹配规则 | 遗漏规则 | 遗漏原因 | 是否安全修复 |

只修复"安全修复=Yes"的项。每修一个立刻跑 T3/T5 验证不增误报。

目标: T1 >= 5 findings, ASI >= 3

## 任务 2: T2 ASI 拓宽

分析 T2 中非 AGENT-004 的 findings，检查其 ASI 映射是否正确。
如果某些 findings 映射到了错误的 ASI → 修正。
如果 T2 有漏洞类型未被检出 → 精准分析并修复匹配。

目标: T2 ASI >= 3

## 任务 3: ASI-09 在实际项目中触发

ASI-09 (Human-Agent Trust Exploitation) 在两次 Run 中状态矛盾(Run1 有 Run2 无)。

确认当前规则状态:
```bash
# 哪些规则映射 ASI-09?
grep -rn "ASI-09\|ASI.09" rules/ packages/ --include="*.py" --include="*.yaml"
```

如果 AGENT-033 (mcp_missing_auth) 和 AGENT-037 (missing_human_in_loop) 映射了 ASI-09
但在 benchmark 中不触发 → 分析原因并修复匹配精度。

## 约束
每次修改后立刻验证 T3/T5/T6/T7 不增加误报（使用标准化扫描路径）。

## 验收标准
□ T1 findings >= 5, ASI >= 3
□ T2 ASI >= 3
□ ASI-09 在至少 1 个项目中触发
□ 框架项目 findings 不增加
□ 标准化 benchmark 全量通过
```

---

### Prompt B3: 最终验证与发版

```
v0.4.0 所有修复完成。运行标准化 benchmark 并生成最终报告。

```bash
cd tests/benchmark
python run_benchmark.py --config benchmark_config.yaml
```

## 最终对比（填入实际值）

| ID | 项目 | v0.2.0 | v0.3.2(Run2) | v0.4.0 | 状态 |
|----|------|--------|-------------|--------|------|
| T1 | DVLLM | 0 | 3 | ? | |
| T2 | DamnVuln | 80 | 82 | ? | |
| T3 | langchain/core | 93 | 9 | ? | |
| T4 | from-scratch | 14 | 18 | ? | |
| T5 | deepagents | 35 | 151 | ? | |
| T6 | openai-agents/src | 23 | 47 | ? | |
| T7 | adk-python/src | 64 | 64 | ? | |
| T8 | agentscope/src | 19 | 3 | ? | |
| T9 | crewAI/src | 124 | 107 | ? | |
| T10 | MCP | 0 | 19 | ? | |
| T11 | streamlit | 1 | 6 | ? | |

## 达标检查

| 指标 | 目标 | 实际 | Pass? |
|------|------|------|-------|
| T1 findings | >= 5 | | |
| T2 ASI | >= 3 | | |
| T5 findings | < 90 | | |
| OWASP | 10/10 | | |
| 检出率 | ✅ | | |
| 误报率 | ✅ | | |
| 总评 | 🟢 | | |

## 版本更新
- pyproject.toml → 0.4.0
- CHANGELOG.md
```

---

## 附录：迭代教训总结

```
教训 1: 测量先于优化
   四轮迭代中 benchmark 不一致导致大量无效工作。
   v0.4.0 先标准化 benchmark，再优化规则。

教训 2: 新规则必须附带误报验证
   每次新增/扩展规则（AGENT-041/027/028/039），
   必须同步在框架项目上验证误报不增加。

教训 3: CC 报告不可信，以 benchmark 为准
   Claude Code 的测试通过 ≠ 实际效果。
   每轮修改必须跑标准化全量 benchmark。

教训 4: 扫描范围必须锁定
   框架仓库（T3/T6/T7/T8/T9）扫描整仓库 vs 子目录，
   结果差数十倍。benchmark_config.yaml 锁定 scan_path。

教训 5: 字段迁移必须完整
   ASI 映射从 owasp_agentic_id → asi_categories 的迁移
   不彻底，导致两个脚本读到不同值。
```
