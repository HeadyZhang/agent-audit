# Agent-Audit Benchmark 工业级优化技术方案 & Claude Code Prompts

> **版本**: v2.0 (基于 Agent-Vuln-Bench Baseline 数据驱动)
> **日期**: 2026-02-04
> **核心目标**: Benchmark 三层体系全面升级 — Layer 1 样本扩充 + Agent-Vuln-Bench 数据集扩展 + Harness 引擎增强 + CI 集成
> **当前基线**: Layer 1 F1=100% (虚假繁荣) | Agent-Vuln-Bench Recall=17.6% (真实能力)

---

## 第一部分：问题诊断与优化全景图

### 1.1 三层 Benchmark 现状评估矩阵

| 维度 | Layer 1 (合成) | Layer 2 (多目标) | Agent-Vuln-Bench | 综合评分 |
|------|---------------|-----------------|------------------|---------|
| **样本规模** | 42样本/198标注 ⚠️ | 11个目标项目 ✅ | 5 Knowns + 2 Wilds ⚠️ | 6/10 |
| **精度评估** | P=98.5% R=100% F1=99.25% ✅ | 无精度指标 ❌ | P=100% R=17.6% ❌ | 5/10 |
| **OWASP覆盖** | 10/10 ASI ✅ | 部分覆盖 ⚠️ | Set A/B/C 映射 ✅ | 8/10 |
| **真实性** | 合成样本/规则友好 ❌ | 真实项目/无oracle ⚠️ | CVE复现+野样本 ✅ | 6/10 |
| **可重现性** | 本地fixtures ✅ | 依赖外部仓库 ⚠️ | 本地化 ✅ | 7/10 |
| **CI集成** | 未集成 ❌ | 未集成 ❌ | 未集成 ❌ | 0/10 |
| **跨工具对比** | 无 ❌ | 无 ❌ | 适配器框架存在 ⚠️ | 3/10 |

**综合评分: 50/100 → 目标: 85/100**

### 1.2 核心问题根因分析 (5-Why)

```
问题: Agent-Vuln-Bench Recall = 17.6%

Why 1: 7个漏洞样本只检出3个
Why 2: Set B (MCP) 和 Set C (Data) 完全未检出
Why 3: 规则触发范围过窄 + 扫描入口不完整
Why 4: Benchmark 设计与工具能力评估脱节
Why 5 (根因): Benchmark 优化 与 工具优化 未形成闭环

              ┌─────────────────────────────────────────┐
              │          优化闭环 (目标状态)              │
              │                                         │
              │  Benchmark暴露Gap → 工具修复 → 复测验证  │
              │       ↑                         │       │
              │       └─────────────────────────┘       │
              │                                         │
              │  当前断裂点:                              │
              │  ✗ Benchmark样本不足以暴露所有Gap         │
              │  ✗ 没有自动化复测流程                     │
              │  ✗ Layer 1 与 Agent-Vuln-Bench 指标割裂  │
              └─────────────────────────────────────────┘
```

### 1.3 优化目标矩阵 (量化KPI)

| 指标 | 当前值 | 目标值 | 验收方式 |
|------|--------|--------|---------|
| **Layer 1 样本数** | 42 | **≥80** | `wc -l labeled_samples.yaml` |
| **Layer 1 每ASI样本数** | 3-5 | **≥8** | 每个 asi-XX 目录下文件数 |
| **Agent-Vuln-Bench Knowns** | 5 | **≥12** | `ls datasets/knowns/` |
| **Agent-Vuln-Bench Wilds** | 2 | **≥6** | `ls datasets/wilds/` |
| **Set A 样本覆盖** | 3 | **≥6** | catalog.yaml 统计 |
| **Set B 样本覆盖** | 1 | **≥4** | catalog.yaml 统计 |
| **Set C 样本覆盖** | 1 | **≥4** | catalog.yaml 统计 |
| **Oracle 完整率** | 100% | **100%** | 每个样本必须有 oracle.yaml |
| **Harness 自动化** | 手动运行 | **单命令全量** | `python run_eval.py --all` |
| **CI 集成** | 无 | **GitHub Actions** | `.github/workflows/benchmark.yml` |
| **跨工具对比** | 0工具 | **≥2** (Bandit+Semgrep) | `compare_tools.py` 输出 |
| **质量门限自动化** | 部分 | **全自动+阻断** | CI red/green |

---

## 第二部分：优化架构设计

### 2.1 Benchmark 优化分层架构

```
优化前 (当前)                              优化后 (目标)
┌────────────────────────┐                ┌──────────────────────────────────────┐
│ Layer 1: 42 fixtures   │                │ Layer 1: 80+ fixtures                │
│ - 合成样本              │                │ - 扩充 Set B/C 样本                   │
│ - precision_recall.py   │                │ - 新增 boundary/edge_case 变种        │
│ - quality_gates.yaml    │                │ - confidence 分层测试                 │
│ ❌ 无 confidence 测试   │                │ - precision_recall_v2.py              │
└────────────────────────┘                └──────────────────────────────────────┘
                                                       │
┌────────────────────────┐                ┌──────────────────────────────────────┐
│ Layer 2: 11 targets    │                │ Layer 2: 11 targets (稳定化)          │
│ - benchmark_config.yaml │                │ - commit pinning                     │
│ - run_benchmark.py      │                │ - snapshot caching                   │
│ ❌ 无 oracle            │                │ - delta tracking                     │
└────────────────────────┘                └──────────────────────────────────────┘
                                                       │
┌────────────────────────┐                ┌──────────────────────────────────────┐
│ Agent-Vuln-Bench: 7    │                │ Agent-Vuln-Bench: 18+ samples        │
│ - 5 Knowns + 2 Wilds   │                │ - 12+ Knowns (覆盖全部4个Gap)        │
│ - 2 Noise              │                │ - 6+ Wilds                           │
│ - Recall=17.6%         │                │ - 2 Noise (保留)                     │
│ ❌ 无 CI               │                │ - Recall 目标 ≥80%                   │
└────────────────────────┘                │ - CI 自动复测                        │
                                          └──────────────────────────────────────┘
                                                       │
                                          ┌──────────────────────────────────────┐
                                          │ CI/CD Pipeline (全新)                 │
                                          │ - Layer 1 回归 (每PR)                │
                                          │ - Agent-Vuln-Bench 复测 (每Release)  │
                                          │ - 质量门限自动阻断                    │
                                          │ - 跨工具对比报告                      │
                                          └──────────────────────────────────────┘
```

### 2.2 模块分解与依赖关系

```
Prompt B1: Layer 1 样本扩充 + Confidence 测试
    │
    ├── 新增 ≥38 个 fixture 样本 (覆盖 Gap 1-4)
    ├── 新增 confidence 断言 (tier 分层测试)
    ├── 更新 labeled_samples.yaml
    └── 更新 quality_gates.yaml
         │
Prompt B2: Agent-Vuln-Bench 数据集扩展
    │
    ├── 新增 7+ Knowns (KNOWN-006~012)
    ├── 新增 4+ Wilds (WILD-003~006)
    ├── 每个样本: vuln/ + fixed/ + oracle.yaml
    ├── 更新 catalog.yaml
    └── Set A/B/C 均衡分布
         │
Prompt B3: Harness 引擎增强
    │
    ├── oracle_eval.py 增强 (confidence/tier 评估)
    ├── run_eval.py 增强 (批量运行+报告)
    ├── compute_metrics.py 增强 (Set A/B/C 分组)
    ├── compare_tools.py 增强 (多工具对比)
    └── 适配器更新 (agent_audit_adapter.py)
         │
Prompt B4: CI 集成 + 质量门限
    │
    ├── GitHub Actions workflow
    ├── 质量门限自动化脚本
    ├── 报告生成 + Artifact 上传
    └── 跨层统一仪表盘

执行顺序: B1 → B2 → B3 → B4 (严格顺序)
```

---

## 第三部分：B1 — Layer 1 样本扩充详细设计

### 3.1 当前样本缺口分析

```
当前 Layer 1 样本分布 (42个):

ASI-01 (Goal Hijack):     4 samples  ⚠️ 需要 +4
ASI-02 (Tool Misuse):     5 samples  ⚠️ 需要 +3 (含 eval/exec 扩展)
ASI-03 (Excessive Agency): 4 samples  ⚠️ 需要 +4 (含权限升级)
ASI-04 (Supply Chain):    4 samples  ⚠️ 需要 +4
ASI-05 (Data Leak):       4 samples  ⚠️ 需要 +4 (含凭证格式)
ASI-06 (Improper Output): 3 samples  ⚠️ 需要 +5
ASI-07 (TOCTOU):          4 samples  ⚠️ 需要 +4
ASI-08 (Overreliance):    4 samples  ⚠️ 需要 +4
ASI-09 (Insufficient Log): 5 samples  ⚠️ 需要 +3
ASI-10 (Rogue Agent):     5 samples  ⚠️ 需要 +3

良性样本 (FP测试):        9 samples  ⚠️ 需要 +11 (含 confidence 测试)
```

### 3.2 新增样本设计矩阵 (38+个)

#### 针对 Benchmark Gap 的定向样本

| 样本组 | 对应Gap | 样本数 | ASI | 描述 |
|--------|---------|--------|-----|------|
| **eval_exec_bare** | Gap-1 (eval/exec) | 3 | ASI-02 | 裸 eval()/exec() 无 @tool 上下文 |
| **eval_exec_indirect** | Gap-1 | 2 | ASI-02 | compile()+exec(), Function() 间接执行 |
| **mcp_json_standalone** | Gap-2 (MCP JSON) | 3 | ASI-04 | 独立 .json MCP 配置过度权限 |
| **mcp_yaml_override** | Gap-2 | 2 | ASI-04 | YAML 格式 MCP 配置 |
| **credential_new_formats** | Gap-3 (凭证) | 4 | ASI-05 | sk-proj-, sk-ant-, co-*, anthropic key |
| **credential_conn_strings** | Gap-3 | 2 | ASI-05 | MongoDB/MySQL/Redis 连接串 |
| **ssrf_bare** | Gap-4 (SSRF) | 3 | ASI-02 | 裸 requests.get(user_input) 无 @tool |
| **ssrf_urllib** | Gap-4 | 2 | ASI-02 | urllib/aiohttp SSRF 变种 |

#### 针对 v0.5.0 新规则的样本

| 样本组 | 规则 | 样本数 | ASI | 描述 |
|--------|------|--------|-----|------|
| **daemon_escalation** | AGENT-043 | 2 | ASI-03 | systemctl/launchctl 守护进程 |
| **sudoers_nopasswd** | AGENT-044 | 2 | ASI-03 | NOPASSWD sudoers 配置 |
| **browser_unsandboxed** | AGENT-045 | 2 | ASI-02 | CDP/Playwright 无沙箱 |
| **credential_store** | AGENT-046 | 2 | ASI-05 | Keychain/DPAPI 访问 |
| **subprocess_unsandboxed** | AGENT-047 | 2 | ASI-02 | child_process.exec 无沙箱 |
| **extension_no_boundary** | AGENT-048 | 2 | ASI-04 | 扩展无权限隔离 |

#### Confidence 分层测试样本 (良性/FP)

| 样本组 | 样本数 | 预期 Tier | 描述 |
|--------|--------|-----------|------|
| **placeholder_values** | 3 | SUPPRESSED | YOUR_KEY_HERE, CHANGE_ME 等 |
| **env_read_patterns** | 2 | SUPPRESSED | process.env.X, os.environ["X"] |
| **function_call_values** | 2 | SUPPRESSED | token = getToken() |
| **schema_definitions** | 2 | SUPPRESSED | z.string().optional() |
| **test_file_credentials** | 2 | INFO (不是WARN) | 测试文件中的假凭证 |

### 3.3 labeled_samples.yaml 扩展格式

```yaml
# 新增样本的标注格式 (v2.2)
- id: "vuln_eval_bare_001"
  file: "fixtures/asi-02-tool-misuse/direct/eval_bare_tool.py"
  vulnerabilities:
    - line: 15
      rule_id: "AGENT-034"
      owasp_id: "ASI-02"
      is_true_positive: true
      # 新增 v2.2 字段:
      expected_confidence_min: 0.60    # 新增: 最低期望置信度
      expected_tier: "WARN"            # 新增: 期望分层
      benchmark_gap: "Gap-1"          # 新增: 对应的gap编号
      agent_vuln_bench_link: "KNOWN-001"  # 新增: 关联的 AVB 样本

- id: "benign_placeholder_001"
  file: "fixtures/benign/validated/placeholder_api_key.py"
  vulnerabilities:
    - line: 5
      rule_id: "AGENT-004"
      owasp_id: "ASI-05"
      is_true_positive: false
      expected_tier: "SUPPRESSED"      # 占位符应被抑制
      expected_confidence_max: 0.30    # 新增: 最高期望置信度
```

---

## 第四部分：B2 — Agent-Vuln-Bench 数据集扩展详细设计

### 4.1 新增样本矩阵

#### 新增 Knowns (CVE 复现)

| ID | 漏洞类型 | Set | CVE/来源 | 语言 | 预期规则 |
|----|---------|-----|---------|------|---------|
| KNOWN-006 | eval() 在 Calculator 工具中 | A | CVE-2023-46229 | Python | AGENT-034 |
| KNOWN-007 | MCP 配置 allowAll: true | B | MCP Spec violation | JSON | AGENT-029/030 |
| KNOWN-008 | MCP 工具无输入校验 | B | MCP best practice | Python | AGENT-026 |
| KNOWN-009 | JWT 硬编码在源码 | C | OWASP Top 10 | Python | AGENT-004 |
| KNOWN-010 | SSRF 通过 requests.get | A | CWE-918 | Python | AGENT-037 |
| KNOWN-011 | subprocess.Popen shell=True | A | CWE-78 | Python | AGENT-036 |
| KNOWN-012 | 日志输出敏感数据 | C | CWE-532 | Python | AGENT-039 |

#### 新增 Wilds (GitHub 野生样本)

| ID | 模式 | Set | 来源描述 | 预期规则 |
|----|------|-----|---------|---------|
| WILD-003 | Agent 自修改代码 | A | GitHub agent self-modify pattern | AGENT-050 |
| WILD-004 | 多平台 token 聚合 | C | Discord+Telegram token collector | AGENT-052 |
| WILD-005 | MCP 配置 stdio 全权限 | B | Real MCP config in the wild | AGENT-029 |
| WILD-006 | Prompt injection 通过用户输入 | A | LLM prompt concatenation | AGENT-027 |

### 4.2 Oracle 模板 (每个新样本必须遵循)

```yaml
# oracle.yaml 模板 — KNOWN-006 示例
metadata:
  sample_id: "KNOWN-006"
  source: "CVE-2023-46229"
  commit: "synthetic"
  language: "python"
  provenance: "cve"
  date_added: "2026-02-04"
  difficulty: "medium"  # easy|medium|hard

taxonomy:
  set_class: "A"
  owasp_asi: "ASI-02"
  cwe_id: "CWE-95"
  attack_vector: "user_input → eval()"
  impact_type: "RCE"

vulnerabilities:
  - id: "VULN-006-001"
    file: "vuln/calculator_agent.py"
    line: 23
    rule_expected: "AGENT-034"
    severity: "CRITICAL"
    description: "eval() used on unsanitized user input in calculator tool"
    taint:
      source:
        type: "user_input"
        location: "calculator_agent.py:15"
        code: "expression = request.get('expression')"
      propagation:
        - step: 1
          location: "calculator_agent.py:20"
          code: "cleaned = expression.strip()"
      sink:
        type: "eval"
        location: "calculator_agent.py:23"
        code: "result = eval(cleaned)"
      sanitizer: null
    impact:
      primary: "RCE"
      blast_radius: "full_system"
      cvss_estimate: 9.8

safe_patterns:
  - id: "SAFE-006-001"
    file: "fixed/calculator_agent.py"
    line: 23
    description: "Uses ast.literal_eval() instead of eval()"
    trap_type: "safe_alternative"
  - id: "SAFE-006-002"
    file: "vuln/calculator_agent.py"
    line: 8
    description: "Import statement for eval-related module"
    trap_type: "identifier_collision"
```

### 4.3 Set 均衡性目标

```
优化前:                          优化后:
Set A (Injection): 5 samples    Set A (Injection): 10+ samples
Set B (MCP):       1 sample     Set B (MCP):       5+ samples
Set C (Data):      1 sample     Set C (Data):      5+ samples
                                         ↓
                                均衡度: 每Set ≥ 4 samples
                                Recall 目标: Set A ≥90%, Set B ≥80%, Set C ≥70%
```

---

## 第五部分：B3 — Harness 引擎增强详细设计

### 5.1 oracle_eval.py 增强

```python
# 当前: 只评估 rule_id + file + line 匹配
# 增强: 添加 confidence/tier 评估 + taint 链部分匹配

class EnhancedOracleEvaluator:
    """增强版 Oracle 评估器"""

    def evaluate_finding(self, finding, oracle_vuln):
        """
        评估一个 finding 对 oracle 漏洞的匹配度

        返回:
        - match_type: EXACT | PARTIAL | MISS
        - details: {
            rule_match: bool,
            file_match: bool,
            line_proximity: int,      # 行号差距
            confidence_check: bool,   # 新增: confidence 是否在期望范围
            tier_check: bool,         # 新增: tier 是否匹配
            taint_overlap: float,     # 新增: taint 链重叠度 0.0-1.0
          }
        """

    def evaluate_safe_pattern(self, findings, oracle_safe):
        """
        评估 safe_pattern 是否被误报

        返回:
        - false_positive: bool       # 是否被错误标记
        - finding_details: Finding | None
        """

    def compute_sample_score(self, findings, oracle):
        """
        计算单个样本的综合得分

        返回:
        - recall: float              # 漏洞检出率
        - precision: float           # 非误报率
        - taint_accuracy: float      # taint 链准确度
        - confidence_accuracy: float # 新增: confidence 准确度
        """
```

### 5.2 run_eval.py 增强

```python
# 当前: 逐样本运行，手动触发
# 增强: 批量运行 + 并行 + 报告生成

class EnhancedEvalRunner:
    """增强版评估运行器"""

    def run_all(self, tool="agent-audit", parallel=4):
        """
        运行所有样本的评估

        流程:
        1. 发现所有样本 (knowns/ + wilds/ + noise/)
        2. 并行运行扫描 (ThreadPoolExecutor)
        3. 对每个样本执行 oracle 评估
        4. 聚合指标
        5. 生成报告
        """

    def run_by_set(self, set_class: str):
        """按 Set A/B/C 运行"""

    def run_regression(self, baseline_file: str):
        """
        回归测试: 对比当前结果与基线

        检查:
        - 已通过的样本不能回退
        - 新增通过的样本记录
        - 指标不能下降
        """

    def generate_report(self, results) -> str:
        """
        生成 Markdown 报告

        包含:
        - 总体指标 (Recall, Precision, F1)
        - 分 Set 指标
        - 分样本详情
        - 与基线对比 (如果有)
        - 未通过样本的根因分析
        """
```

### 5.3 compute_metrics.py 增强

```python
# 当前: Overall Recall/Precision
# 增强: 分组指标 + 趋势追踪

def compute_metrics(results: list[SampleResult]) -> dict:
    """
    计算增强版指标

    返回:
    {
        "overall": {
            "recall": float,
            "precision": float,
            "f1": float,
            "fp_rate": float,
        },
        "by_set": {
            "A": {"recall": float, "precision": float, "sample_count": int},
            "B": {"recall": float, ...},
            "C": {"recall": float, ...},
        },
        "by_severity": {
            "CRITICAL": {"recall": float, ...},
            "HIGH": {"recall": float, ...},
        },
        "confidence_analysis": {         # 新增
            "mean_confidence_tp": float,  # TP 的平均 confidence
            "mean_confidence_fp": float,  # FP 的平均 confidence
            "tier_accuracy": float,       # tier 分层准确率
        },
        "taint_analysis": {              # 新增
            "taint_accuracy": float,      # taint 链准确率
            "source_match_rate": float,
            "sink_match_rate": float,
        },
        "regression": {                  # 新增
            "newly_passing": list[str],
            "newly_failing": list[str],
            "unchanged": int,
        }
    }
```

### 5.4 agent_audit_adapter.py 增强

```python
# 当前: 基本扫描 + finding 提取
# 增强: confidence/tier 提取 + JSON 输出解析

class EnhancedAgentAuditAdapter(BaseAdapter):
    """增强版 agent-audit 适配器"""

    def scan(self, target_path: str) -> list[ToolFinding]:
        """
        运行 agent-audit 并提取结果

        增强:
        - 使用 --output json 获取结构化输出
        - 提取 confidence 和 tier 字段
        - 提取 risk_score
        """

    def parse_json_output(self, json_str: str) -> list[ToolFinding]:
        """解析 JSON 输出"""

    def to_tool_finding(self, raw) -> ToolFinding:
        """
        转换为统一格式

        新增字段:
        - confidence: float
        - tier: str (BLOCK/WARN/INFO/SUPPRESSED)
        - asi_categories: list[str]
        """
```

---

## 第六部分：B4 — CI 集成设计

### 6.1 GitHub Actions Workflow

```yaml
# .github/workflows/benchmark.yml
name: Benchmark Suite
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # 每周一 6:00 UTC

jobs:
  layer1:
    name: Layer 1 - Precision/Recall
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Layer 1
        run: |
          python tests/benchmark/precision_recall.py \
            --config tests/benchmark/quality_gates.yaml \
            --output results/layer1.json
      - name: Quality Gate Check
        run: python tests/benchmark/quality_gate_check.py results/layer1.json

  agent-vuln-bench:
    name: Agent-Vuln-Bench
    runs-on: ubuntu-latest
    needs: layer1
    steps:
      - uses: actions/checkout@v4
      - name: Run Agent-Vuln-Bench
        run: |
          python tests/benchmark/agent-vuln-bench/harness/run_eval.py \
            --tool agent-audit \
            --output results/avb.json
      - name: Check Recall Threshold
        run: |
          python -c "
          import json
          r = json.load(open('results/avb.json'))
          assert r['overall']['recall'] >= 0.60, f'Recall {r[\"overall\"][\"recall\"]} < 0.60'
          print('✅ Recall threshold passed')
          "
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-report
          path: results/
```

### 6.2 质量门限定义 (quality_gates_v2.yaml)

```yaml
# quality_gates_v2.yaml
version: "2.0"

layer1:
  precision_min: 0.90
  recall_min: 0.85
  f1_min: 0.87
  fp_rate_max: 0.05
  per_asi:
    ASI-01: { recall_min: 0.80 }
    ASI-02: { recall_min: 0.80 }
    # ... 所有 ASI 类别

agent_vuln_bench:
  overall_recall_min: 0.60         # v0.5.0 目标 (从 17.6%)
  set_a_recall_min: 0.70           # Injection 类
  set_b_recall_min: 0.60           # MCP 类
  set_c_recall_min: 0.50           # Data 类
  precision_min: 0.80
  regression_tolerance: 0          # 不允许已通过样本回退

blocking: true                     # 不通过则阻断 CI
```

---

## 第七部分：Prompt 执行顺序与依赖关系

```
Prompt B1 ─────────────────────┐
(Layer 1 样本扩充)              │
  - 新增 38+ fixtures          │
  - confidence 测试用例         ├──→ Prompt B3 ──────────→ Prompt B4
  - labeled_samples v2.2       │    (Harness 增强)         (CI 集成)
                               │     - oracle_eval v2       - workflow
Prompt B2 ─────────────────────┤     - run_eval v2          - quality gates
(Agent-Vuln-Bench 扩展)        │     - metrics v2           - 自动报告
  - 7+ Knowns                  │     - adapter v2
  - 4+ Wilds                   │
  - oracle.yaml 全覆盖         │
  - catalog.yaml 更新          │
                               │
                               └──→ (B1/B2 可并行执行)

执行顺序: [B1, B2] (可并行) → B3 → B4
```

---

## 附录 A：样本编写规范

### A.1 漏洞样本规范

每个漏洞样本必须包含:
1. `vuln/` 目录: 含漏洞的代码 (最小可复现)
2. `fixed/` 目录: 修复后的代码 (作为 safe_pattern 验证)
3. `oracle.yaml`: 完整的 oracle 定义
4. 代码行数: 10-50行 (聚焦单一漏洞)
5. 无外部依赖 (可 mock imports)

### A.2 命名规范

```
KNOWN-{NNN}/
├── vuln/
│   └── {descriptive_name}.py     # 如 calculator_eval.py
├── fixed/
│   └── {descriptive_name}.py     # 同名，修复版
└── oracle.yaml

WILD-{NNN}/
├── vuln/
│   └── {descriptive_name}.py
├── fixed/
│   └── {descriptive_name}.py
└── oracle.yaml
```

### A.3 Oracle 字段必填检查

```python
REQUIRED_FIELDS = {
    "metadata": ["sample_id", "source", "language", "provenance"],
    "taxonomy": ["set_class", "owasp_asi", "cwe_id"],
    "vulnerabilities": ["id", "file", "line", "rule_expected", "severity"],
    "vulnerabilities.taint": ["source", "sink"],
    "safe_patterns": ["id", "file", "line", "description", "trap_type"],
}
```
# Agent-Audit Benchmark 优化 — Claude Code Prompts

> **用途**: 按顺序喂给 Claude Code 执行的 4 个工业级 Prompt
> **执行顺序**: B1 → B2 → B3 → B4（B1 和 B2 理论上可并行，但建议顺序执行以避免冲突）
> **每个 Prompt 预估时长**: 30-60min

---

## Prompt B1: Layer 1 样本扩充 + Confidence 分层测试

```markdown
# 角色
你是 agent-audit 的安全测试工程师。你正在扩充 Layer 1 benchmark 的测试样本，
让它能真正覆盖工具的检测盲区，而不是只测试工具已经能做好的事情。

# 核心原则
**Benchmark 的价值在于暴露工具的短板，而非证明工具的长处。**
当前 Layer 1 的 F1=100%（393 测试通过）是虚假繁荣——它只测试了工具已有能力，
完全未覆盖 Agent-Vuln-Bench 暴露的 4 个 Gap。

# 背景数据

Agent-Vuln-Bench v0.4.1 Baseline 暴露了 4 个关键 Gap：

| Gap | 问题 | 受影响样本 | 根因 |
|-----|------|-----------|------|
| Gap-1 | eval/exec 只在 @tool 上下文检测 | KNOWN-001/002, WILD-001 | AGENT-034 触发范围窄 |
| Gap-2 | 独立 .json MCP 配置被跳过 | KNOWN-003 | 扫描入口文件类型过滤 |
| Gap-3 | sk-proj- 等新凭证格式未覆盖 | KNOWN-004 | AGENT-004 格式列表过时 |
| Gap-4 | 非 @tool 上下文 SSRF 不检测 | WILD-002 | AGENT-026/037 触发范围窄 |

# 任务（按顺序执行）

## 第一步：理解现有 Layer 1 结构

```bash
# 1. 查看 benchmark 目录结构
find tests/benchmark -type f -name "*.py" -o -name "*.yaml" -o -name "*.yml" -o -name "*.md" | head -40
ls -la tests/benchmark/

# 2. 查看现有 fixtures 结构和 ASI 分布
ls tests/benchmark/fixtures/
for dir in tests/benchmark/fixtures/asi-*/; do
    echo "=== $dir ===" && find "$dir" -type f | wc -l
done

# 3. 查看良性样本
ls tests/benchmark/fixtures/benign/

# 4. 读取 labeled_samples.yaml 的格式和现有样本
head -80 tests/benchmark/ground_truth/labeled_samples.yaml

# 5. 读取 quality_gates.yaml
cat tests/benchmark/quality_gates.yaml

# 6. 读取 precision_recall.py 理解评估逻辑
cat tests/benchmark/precision_recall.py

# 7. 读取 schema.yaml 理解标注格式
cat tests/benchmark/ground_truth/schema.yaml
```

**先完成所有读取，彻底理解现有结构后再开始编码。**
将你的发现总结为一段注释，确认：
- 现有样本总数
- 每个 ASI 类别的样本数
- labeled_samples.yaml 的字段格式
- precision_recall.py 的评估逻辑

## 第二步：创建 Gap-1 定向样本（eval/exec 扩展）

在 `tests/benchmark/fixtures/asi-02-tool-misuse/` 下创建新目录和文件。

### 样本 1: eval_bare_no_decorator.py
```python
"""
漏洞: 裸 eval() 调用，无 @tool 装饰器上下文
预期: AGENT-034 应检出 (当前漏报 — Gap-1)
对应: KNOWN-001 (CVE-2023-29374)
"""
import json

def calculate(expression: str) -> float:
    """Simple calculator that evaluates expressions"""
    # 危险: 直接 eval 用户输入
    result = eval(expression)  # LINE 11 — 应被 AGENT-034 检出
    return float(result)

def process_request(request_data: str):
    data = json.loads(request_data)
    return calculate(data["expression"])
```

### 样本 2: exec_dynamic_code.py
```python
"""
漏洞: exec() 执行动态生成的代码
预期: AGENT-034 应检出
对应: KNOWN-002 (CVE-2023-36258)
"""
def run_python_code(code: str, context: dict) -> dict:
    """Execute Python code in a given context"""
    local_vars = {}
    exec(code, {"__builtins__": {}}, local_vars)  # LINE 8 — 应被 AGENT-034 检出
    return local_vars

class PythonREPLTool:
    def execute(self, code_input: str):
        return run_python_code(code_input, {})
```

### 样本 3: compile_exec_indirect.py
```python
"""
漏洞: compile() + exec() 间接执行
预期: AGENT-034 应检出
"""
def safe_looking_execute(source_code: str):
    compiled = compile(source_code, "<agent>", "exec")
    exec(compiled)  # LINE 5 — 间接但同样危险
```

### 良性对照: eval_safe_literal.py (放在 benign/validated/)
```python
"""
良性: 使用 ast.literal_eval 安全替代
预期: AGENT-034 不应检出 (或 SUPPRESSED)
"""
import ast

def safe_parse(value_str: str):
    result = ast.literal_eval(value_str)  # 安全的
    return result
```

## 第三步：创建 Gap-2 定向样本（MCP JSON）

在 `tests/benchmark/fixtures/asi-04-supply-chain/` 下创建。

### 样本 1: mcp_standalone_json.json
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-filesystem", "/"],
      "alwaysAllow": ["read_file", "write_file", "list_directory"]
    },
    "shell": {
      "command": "npx",
      "args": ["-y", "mcp-shell-server"],
      "alwaysAllow": ["run_command"]
    }
  }
}
```

### 样本 2: mcp_excessive_permissions.json
```json
{
  "mcpServers": {
    "database": {
      "command": "npx",
      "args": ["-y", "mcp-server-postgres", "postgresql://admin:password@localhost/prod"],
      "alwaysAllow": ["query", "execute", "drop_table"]
    }
  }
}
```

### 良性对照: mcp_restricted.json (放在 benign/validated/)
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-filesystem", "./workspace"],
      "alwaysAllow": ["read_file"]
    }
  }
}
```

## 第四步：创建 Gap-3 定向样本（新凭证格式）

在 `tests/benchmark/fixtures/asi-05-data-leak/` 下创建。

### 样本 1: credential_new_formats.py
```python
"""
漏洞: 新格式 API 密钥硬编码
预期: AGENT-004 应检出
对应: KNOWN-004
"""
# OpenAI 新格式
OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345"  # LINE 6

# Anthropic 格式
ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"  # LINE 9

# Cohere 格式
COHERE_KEY = "co-abcdefghijklmnopqrstuvwxyz012345"  # LINE 12
```

### 样本 2: credential_connection_strings.py
```python
"""
漏洞: 数据库连接串硬编码
预期: AGENT-004 应检出
"""
MONGO_URI = "mongodb://admin:secretpass@mongo.internal:27017/agentdb"  # LINE 5
REDIS_URL = "redis://:mypassword@redis.internal:6379/0"  # LINE 6
MYSQL_DSN = "mysql://root:hunter2@mysql.internal:3306/agents"  # LINE 7
```

### 良性对照: credential_placeholder.py (放在 benign/validated/)
```python
"""
良性: 占位符/模板值
预期: SUPPRESSED
"""
API_KEY = "YOUR_API_KEY_HERE"          # 占位符
TOKEN = "sk-proj-REPLACE_WITH_REAL_KEY"  # 提示替换
DATABASE_URL = "postgres://user:password@localhost:5432/dbname"  # 通用模板
```

## 第五步：创建 Gap-4 定向样本（SSRF 扩展）

在 `tests/benchmark/fixtures/asi-02-tool-misuse/` 下创建。

### 样本 1: ssrf_bare_requests.py
```python
"""
漏洞: 裸 requests.get() 使用用户输入 URL，无 @tool 上下文
预期: AGENT-037 应检出
对应: WILD-002
"""
import requests

def fetch_url(url: str) -> str:
    """Fetch content from any URL"""
    response = requests.get(url)  # LINE 9 — SSRF: 无 URL 校验
    return response.text

def process_agent_action(action: dict):
    if action["type"] == "web_fetch":
        return fetch_url(action["url"])  # 用户控制的 URL
```

### 样本 2: ssrf_urllib.py
```python
"""
漏洞: urllib SSRF 变种
预期: AGENT-037 应检出
"""
from urllib.request import urlopen

def read_remote_config(config_url: str) -> str:
    with urlopen(config_url) as response:  # LINE 7 — SSRF
        return response.read().decode()
```

## 第六步：创建 v0.5.0 新规则对应样本（权限类）

在适当的 ASI 目录下创建。

### AGENT-043 样本: daemon_systemctl.sh (放在 asi-03/)
```bash
#!/bin/bash
# 漏洞: 创建 systemd 服务获得持久化权限
# 预期: AGENT-043 应检出

cat > /etc/systemd/system/agent-gateway.service << 'EOF'
[Unit]
Description=Agent Gateway Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/agent-gateway
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable agent-gateway.service  # LINE 17
systemctl start agent-gateway.service
```

### AGENT-044 样本: sudoers_config.sh (放在 asi-03/)
```bash
#!/bin/bash
# 漏洞: NOPASSWD sudoers 配置
# 预期: AGENT-044 应检出
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/agent-runner  # LINE 4
```

### AGENT-045 样本: browser_cdp.py (放在 asi-02/)
```python
"""
漏洞: CDP 浏览器自动化无沙箱
预期: AGENT-045 应检出
"""
from playwright.sync_api import sync_playwright

def capture_page(url: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])  # LINE 8
        page = browser.new_page()
        page.goto(url)
        result = page.evaluate("() => document.cookie")  # LINE 11 — 可执行任意JS
        browser.close()
        return result
```

### AGENT-046 样本: keychain_access.py (放在 asi-05/)
```python
"""
漏洞: 访问系统凭证存储
预期: AGENT-046 应检出 (不是 AGENT-004!)
"""
import subprocess

def read_keychain_password(service: str) -> str:
    result = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-w"],  # LINE 8
        capture_output=True, text=True
    )
    return result.stdout.strip()
```

### AGENT-047 样本: subprocess_unsandboxed.py (放在 asi-02/)
```python
"""
漏洞: Agent 中无沙箱子进程执行
预期: AGENT-047 应检出
"""
import subprocess

def agent_execute_command(command: str) -> str:
    result = subprocess.run(
        command, shell=True,  # LINE 8 — shell=True + 用户输入
        capture_output=True, text=True
    )
    return result.stdout
```

## 第七步：更新 labeled_samples.yaml

将所有新增样本添加到 `tests/benchmark/ground_truth/labeled_samples.yaml`。

格式要求（参照现有格式）：
- 每个漏洞样本: is_true_positive: true
- 每个良性样本: is_true_positive: false
- 新增字段（如果现有 schema 支持）:
  - expected_tier: "BLOCK" | "WARN" | "INFO" | "SUPPRESSED"
  - benchmark_gap: "Gap-1" | "Gap-2" | "Gap-3" | "Gap-4" | null

**关键**: 先读取现有 labeled_samples.yaml 的完整格式，严格遵循其格式添加新条目。
不要修改任何现有条目。

## 第八步：更新 quality_gates.yaml

如果现有 quality_gates.yaml 中有样本数量相关的阈值，更新它们以反映新增样本。

## 第九步：运行验证

```bash
# 1. 确认所有新文件都存在
find tests/benchmark/fixtures -name "*.py" -o -name "*.json" -o -name "*.sh" -newer tests/benchmark/ground_truth/labeled_samples.yaml 2>/dev/null | sort

# 2. 验证 labeled_samples.yaml 格式
python -c "
import yaml
with open('tests/benchmark/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
print(f'Total samples: {len(data)}')
tp = sum(1 for s in data for v in s.get('vulnerabilities', []) if v.get('is_true_positive'))
fp = sum(1 for s in data for v in s.get('vulnerabilities', []) if not v.get('is_true_positive'))
print(f'True positives: {tp}, False positive tests: {fp}')
"

# 3. 运行现有测试确保不破坏
pytest tests/ -v --tb=short -x 2>&1 | tail -30

# 4. 如果 precision_recall.py 可以独立运行，运行它
python tests/benchmark/precision_recall.py 2>&1 | tail -20
```

## 约束

- **不修改任何现有样本文件** — 只新增
- **不修改 precision_recall.py 的核心逻辑** — 本 Prompt 只扩数据，不改引擎
- **每个样本文件 ≤50 行** — 聚焦单一漏洞模式
- **良性样本必须有清晰注释** — 说明为什么它是安全的
- **漏洞样本注释标明**: 预期规则、对应 Gap、对应 Agent-Vuln-Bench 样本

## 自验证清单

完成后请逐项确认:
□ 新增漏洞样本 ≥ 20 个
□ 新增良性样本 ≥ 6 个
□ 每个 Gap (1-4) 至少有 2 个定向样本
□ labeled_samples.yaml 新增条目格式与现有条目一致
□ 所有现有测试仍然通过 (pytest tests/ 无失败)
□ 无语法错误的 Python/JSON/Shell 文件
□ 每个样本的注释清楚说明预期行为
```

---

## Prompt B2: Agent-Vuln-Bench 数据集扩展

```markdown
# 角色
你是 agent-audit 的 benchmark 数据工程师。你正在扩展 Agent-Vuln-Bench 数据集，
从 7 个样本扩展到 18+ 个样本，覆盖所有 3 个 Set 的检测盲区。

# 前置条件
Prompt B1 已完成。Layer 1 fixtures 已扩充。
请先验证:
```bash
# 确认 Layer 1 新样本已就位
find tests/benchmark/fixtures -name "*.py" -o -name "*.json" -o -name "*.sh" | wc -l
# 应该比之前多 20+
```

# 背景

Agent-Vuln-Bench v0.4.1 Baseline:
- Overall Recall: 17.6% (3/17 漏洞)
- Set A (Injection/RCE): 33.3%  → 目标 ≥90%
- Set B (MCP/Component): 0.0%   → 目标 ≥80%
- Set C (Data/Auth): 0.0%       → 目标 ≥70%

当前样本分布:
- Knowns: 5 (KNOWN-001~005)
- Wilds: 2 (WILD-001~002)
- Noise: 2 (T12/T13)

# 任务

## 第一步：理解现有 Agent-Vuln-Bench 结构

```bash
# 1. 完整目录结构
find tests/benchmark/agent-vuln-bench -type f | head -60
ls -la tests/benchmark/agent-vuln-bench/datasets/

# 2. 读取 catalog.yaml
cat tests/benchmark/agent-vuln-bench/datasets/catalog.yaml

# 3. 读取 taxonomy 映射
cat tests/benchmark/agent-vuln-bench/taxonomy/owasp_agentic_mapping.yaml
cat tests/benchmark/agent-vuln-bench/taxonomy/impact_taxonomy.yaml

# 4. 读取一个现有样本的完整结构作为参照
ls -la tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-001/
cat tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-001/oracle.yaml
cat tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-001/vuln/*.py 2>/dev/null || \
  find tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-001/ -type f -exec echo "=== {} ===" \; -exec head -30 {} \;

# 5. 读取另一个样本对比
cat tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-003/oracle.yaml
find tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-003/ -type f -exec echo "=== {} ===" \; -exec head -30 {} \;

# 6. 读取 Wild 样本
cat tests/benchmark/agent-vuln-bench/datasets/wilds/WILD-001/oracle.yaml
find tests/benchmark/agent-vuln-bench/datasets/wilds/WILD-001/ -type f -exec echo "=== {} ===" \; -exec head -30 {} \;

# 7. 读取 harness 代码
cat tests/benchmark/agent-vuln-bench/harness/run_eval.py
cat tests/benchmark/agent-vuln-bench/harness/oracle_eval.py
cat tests/benchmark/agent-vuln-bench/harness/adapters/base_adapter.py
```

**彻底理解现有格式后再继续。** 特别注意:
- oracle.yaml 的完整 schema（所有必填/可选字段）
- vuln/ 和 fixed/ 目录的命名规范
- taint 链的格式
- safe_patterns 的 trap_type 枚举值

## 第二步：创建 KNOWN-006 — eval() 在 Calculator 工具

```
tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-006/
├── vuln/
│   └── calculator_eval.py
├── fixed/
│   └── calculator_eval.py
└── oracle.yaml
```

### vuln/calculator_eval.py
```python
"""
CVE-2023-46229 复现: eval() 在计算器工具中
Set A | ASI-02 | CWE-95
"""
import json

class CalculatorTool:
    """A tool that evaluates mathematical expressions"""
    name = "calculator"
    description = "Evaluate mathematical expressions"

    def run(self, expression: str) -> str:
        try:
            result = eval(expression)  # LINE 13 — VULN: RCE via eval
            return str(result)
        except Exception as e:
            return f"Error: {e}"

def handle_agent_action(action_json: str):
    action = json.loads(action_json)
    if action["tool"] == "calculator":
        tool = CalculatorTool()
        return tool.run(action["input"])
```

### fixed/calculator_eval.py
```python
"""修复版: 使用 ast.literal_eval + 数学表达式解析器"""
import ast
import operator

SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

class CalculatorTool:
    name = "calculator"
    description = "Evaluate mathematical expressions safely"

    def run(self, expression: str) -> str:
        try:
            tree = ast.parse(expression, mode='eval')
            result = self._eval_node(tree.body)
            return str(result)
        except Exception as e:
            return f"Error: {e}"

    def _eval_node(self, node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            op = SAFE_OPS.get(type(node.op))
            if op is None:
                raise ValueError(f"Unsupported operator: {type(node.op)}")
            return op(left, right)
        raise ValueError(f"Unsupported expression: {type(node)}")
```

### oracle.yaml
严格按照 KNOWN-001 的 oracle.yaml 格式编写，包含:
- metadata (sample_id, source, language, provenance)
- taxonomy (set_class: "A", owasp_asi: "ASI-02", cwe_id: "CWE-95")
- vulnerabilities (完整 taint 链)
- safe_patterns (fixed 版本 + identifier collision trap)

## 第三步：创建 KNOWN-007 — MCP 配置 allowAll

```
tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-007/
├── vuln/
│   └── mcp_config.json
├── fixed/
│   └── mcp_config.json
└── oracle.yaml
```

### vuln/mcp_config.json
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-filesystem", "/"],
      "alwaysAllow": ["read_file", "write_file", "list_directory", "delete_file"]
    },
    "shell": {
      "command": "npx",
      "args": ["-y", "mcp-shell-server"],
      "alwaysAllow": ["run_command"]
    }
  }
}
```

### fixed/mcp_config.json
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-server-filesystem", "./workspace"],
      "alwaysAllow": ["read_file"]
    }
  }
}
```

### oracle.yaml
- set_class: "B"
- owasp_asi: "ASI-04"
- 两个漏洞点: 根路径访问 + shell alwaysAllow

## 第四步：创建 KNOWN-008 — MCP 工具无输入校验

vuln/ 包含一个 MCP tool 定义（Python），接受用户输入执行 SQL 但无参数化。
fixed/ 使用参数化查询。
set_class: "B", owasp_asi: "ASI-02"

## 第五步：创建 KNOWN-009 — JWT 硬编码

vuln/ 包含硬编码的 JWT secret 和一个完整的 JWT token。
fixed/ 从环境变量读取 secret。
set_class: "C", owasp_asi: "ASI-05"

## 第六步：创建 KNOWN-010 — SSRF 通过 requests

vuln/ 包含直接使用 requests.get(user_url) 的代码。
fixed/ 包含 URL 白名单校验。
set_class: "A", owasp_asi: "ASI-02"

## 第七步：创建 KNOWN-011 — subprocess shell=True

vuln/ 包含 subprocess.Popen(cmd, shell=True) 执行用户输入。
fixed/ 使用 subprocess.run(["cmd", arg], shell=False)。
set_class: "A", owasp_asi: "ASI-02"

## 第八步：创建 KNOWN-012 — 日志输出敏感数据

vuln/ 包含 logging.info(f"User token: {token}") 日志泄露。
fixed/ 使用 logging.info("User authenticated") 不含敏感数据。
set_class: "C", owasp_asi: "ASI-09"

## 第九步：创建 Wild 样本 (WILD-003~006)

### WILD-003: Agent 自修改代码 (Set A)
模拟一个 Agent 可以修改自己的配置文件或代码的模式。
预期规则: AGENT-050 (如果存在) 或 AGENT-034

### WILD-004: 多平台 token 聚合 (Set C)
模拟聚合 Discord + Telegram + Slack token 的代码。
预期规则: AGENT-004 或 AGENT-052

### WILD-005: MCP 配置 stdio 全权限 (Set B)
一个真实风格的 claude_desktop_config.json，包含多个 MCP server 且全部 alwaysAllow。
预期规则: AGENT-029/030/031

### WILD-006: Prompt Injection 通过用户输入 (Set A)
一个使用 f-string 将用户输入直接拼接到 system prompt 的模式。
预期规则: AGENT-027

## 第十步：更新 catalog.yaml

读取现有 catalog.yaml 格式，为所有新样本添加条目。
每个条目必须包含:
- sample_id
- set_class
- owasp_asi
- provenance (cve/wild)
- language
- status (active)

## 第十一步：验证

```bash
# 1. 确认所有新样本目录存在
for i in $(seq 6 12); do
    dir="tests/benchmark/agent-vuln-bench/datasets/knowns/KNOWN-$(printf '%03d' $i)"
    echo "=== KNOWN-$(printf '%03d' $i) ===" && ls "$dir" 2>&1
done

for i in $(seq 3 6); do
    dir="tests/benchmark/agent-vuln-bench/datasets/wilds/WILD-$(printf '%03d' $i)"
    echo "=== WILD-$(printf '%03d' $i) ===" && ls "$dir" 2>&1
done

# 2. 验证所有 oracle.yaml 存在
find tests/benchmark/agent-vuln-bench/datasets -name "oracle.yaml" | wc -l
# 应该 ≥ 18 (5旧Knowns + 7新Knowns + 2旧Wilds + 4新Wilds)

# 3. 验证 oracle.yaml 格式
python -c "
import yaml, os, sys
errors = []
base = 'tests/benchmark/agent-vuln-bench/datasets'
for root, dirs, files in os.walk(base):
    if 'oracle.yaml' in files:
        path = os.path.join(root, 'oracle.yaml')
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            # 检查必填字段
            assert 'metadata' in data, 'missing metadata'
            assert 'taxonomy' in data, 'missing taxonomy'
            assert 'vulnerabilities' in data, 'missing vulnerabilities'
            assert data['taxonomy'].get('set_class') in ('A','B','C'), 'invalid set_class'
            print(f'✅ {path}')
        except Exception as e:
            errors.append(f'❌ {path}: {e}')
            print(f'❌ {path}: {e}')
if errors:
    print(f'\n{len(errors)} errors found')
    sys.exit(1)
print(f'\nAll oracle files valid')
"

# 4. 验证 catalog.yaml 包含所有样本
python -c "
import yaml
with open('tests/benchmark/agent-vuln-bench/datasets/catalog.yaml') as f:
    catalog = yaml.safe_load(f)
samples = catalog.get('samples', catalog) if isinstance(catalog, dict) else catalog
print(f'Catalog entries: {len(samples) if isinstance(samples, list) else \"check format\"}')
"

# 5. Set 分布检查
python -c "
import yaml, os
sets = {'A': 0, 'B': 0, 'C': 0}
base = 'tests/benchmark/agent-vuln-bench/datasets'
for root, dirs, files in os.walk(base):
    if 'oracle.yaml' in files:
        with open(os.path.join(root, 'oracle.yaml')) as f:
            data = yaml.safe_load(f)
        sc = data.get('taxonomy', {}).get('set_class', '?')
        sets[sc] = sets.get(sc, 0) + 1
print('Set distribution:', sets)
assert sets['A'] >= 6, f'Set A needs ≥6, got {sets[\"A\"]}'
assert sets['B'] >= 4, f'Set B needs ≥4, got {sets[\"B\"]}'
assert sets['C'] >= 4, f'Set C needs ≥4, got {sets[\"C\"]}'
print('✅ Set balance OK')
"
```

## 约束

- **严格遵循现有 oracle.yaml 格式** — 先读懂现有样本再创建
- **每个样本必须有 vuln/ 和 fixed/ 两个版本** — fixed 作为 safe_pattern 验证
- **每个 oracle.yaml 必须有完整的 taint 链** — source → propagation → sink
- **safe_patterns 至少 1 个** — 防止误报的陷阱
- **不修改任何现有样本** — 只新增

## 自验证清单

□ 新增 Knowns ≥ 7 个 (KNOWN-006~012)
□ 新增 Wilds ≥ 4 个 (WILD-003~006)
□ 每个样本都有 vuln/ + fixed/ + oracle.yaml
□ Set A ≥ 6 样本, Set B ≥ 4 样本, Set C ≥ 4 样本
□ 所有 oracle.yaml 格式验证通过
□ catalog.yaml 已更新包含所有新样本
□ 所有 Python 文件无语法错误: `python -m py_compile file.py`
```

---

## Prompt B3: Harness 引擎增强 + 指标计算升级

```markdown
# 角色
你是 agent-audit 的 DevTools 工程师。你正在增强 Agent-Vuln-Bench 的评估引擎，
使其能自动化运行全量测试、计算分组指标、生成对比报告。

# 前置条件
Prompt B1 和 B2 已完成。数据集已扩展。

请先验证:
```bash
# 确认数据集扩展完成
find tests/benchmark/agent-vuln-bench/datasets -name "oracle.yaml" | wc -l
# 应该 ≥ 18

# 确认 Layer 1 样本已扩充
python -c "
import yaml
with open('tests/benchmark/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
print(f'Layer 1 samples: {len(data)}')
" 2>/dev/null || echo "Check path"
```

# 任务

## 第一步：深度阅读现有 Harness 代码

```bash
# 逐个读取所有 harness 文件
cat tests/benchmark/agent-vuln-bench/harness/adapters/base_adapter.py
cat tests/benchmark/agent-vuln-bench/harness/adapters/agent_audit_adapter.py
cat tests/benchmark/agent-vuln-bench/harness/oracle_eval.py
cat tests/benchmark/agent-vuln-bench/harness/run_eval.py
cat tests/benchmark/agent-vuln-bench/metrics/compute_metrics.py
cat tests/benchmark/agent-vuln-bench/metrics/compare_tools.py

# 理解现有运行方式
grep -rn "def main\|if __name__\|argparse\|click" \
    tests/benchmark/agent-vuln-bench/harness/ --include="*.py"
```

**总结你的发现：**
1. ToolFinding 的数据结构（有哪些字段）
2. BaseAdapter 的接口定义
3. oracle_eval.py 的匹配逻辑（如何判定 TP/FP/FN）
4. run_eval.py 的运行流程
5. compute_metrics.py 的指标计算方式
6. 当前的输出格式

## 第二步：增强 oracle_eval.py

在现有 oracle_eval.py 的基础上增强（不破坏现有接口）：

### 增强 1: Confidence/Tier 评估

```python
def evaluate_finding_enhanced(self, finding, oracle_vuln):
    """
    增强版匹配评估

    新增:
    - confidence_check: finding.confidence 是否在合理范围
    - tier_check: finding.tier 是否匹配 oracle 预期
    """
    base_result = self.evaluate_finding(finding, oracle_vuln)  # 调用原方法

    # 新增 confidence 评估
    if hasattr(finding, 'confidence') and finding.confidence is not None:
        base_result['confidence'] = finding.confidence
        base_result['tier'] = getattr(finding, 'tier', 'UNKNOWN')

        # 检查 confidence 是否合理: TP 的 confidence 应该 ≥ 0.60
        if base_result.get('match_type') in ('EXACT', 'PARTIAL'):
            base_result['confidence_reasonable'] = finding.confidence >= 0.60

    return base_result
```

### 增强 2: Taint 链部分匹配

```python
def evaluate_taint_overlap(self, finding, oracle_taint):
    """
    评估 taint 链重叠度

    返回 0.0 - 1.0:
    - source 匹配: +0.33
    - sink 匹配: +0.34
    - propagation 有重叠: +0.33
    """
    score = 0.0

    # Source 匹配: 检查 finding 是否覆盖了 taint source 的文件/行
    if self._location_match(finding, oracle_taint.get('source', {})):
        score += 0.33

    # Sink 匹配: 检查 finding 是否覆盖了 taint sink 的文件/行
    if self._location_match(finding, oracle_taint.get('sink', {})):
        score += 0.34

    # Propagation 匹配: 任何一步匹配即可
    for step in oracle_taint.get('propagation', []):
        if self._location_match(finding, step):
            score += 0.33
            break

    return min(1.0, score)
```

## 第三步：增强 compute_metrics.py

增加分组指标计算：

```python
def compute_metrics_enhanced(results: list) -> dict:
    """
    增强版指标计算

    新增:
    - by_set: Set A/B/C 分组指标
    - by_severity: CRITICAL/HIGH/MEDIUM 分组
    - confidence_analysis: confidence 分布分析
    - taint_analysis: taint 链准确度
    - regression: 与基线对比
    """
    metrics = compute_metrics(results)  # 调用原方法

    # Set 分组
    for set_class in ('A', 'B', 'C'):
        set_results = [r for r in results if r.get('set_class') == set_class]
        if set_results:
            metrics[f'set_{set_class}'] = {
                'recall': compute_recall(set_results),
                'precision': compute_precision(set_results),
                'sample_count': len(set_results),
            }

    # Confidence 分析
    tp_confidences = [r['confidence'] for r in results
                      if r.get('match_type') == 'EXACT' and r.get('confidence')]
    fp_confidences = [r['confidence'] for r in results
                      if r.get('false_positive') and r.get('confidence')]

    if tp_confidences:
        metrics['confidence_analysis'] = {
            'mean_tp_confidence': sum(tp_confidences) / len(tp_confidences),
            'mean_fp_confidence': sum(fp_confidences) / len(fp_confidences) if fp_confidences else 0,
        }

    return metrics
```

## 第四步：增强 agent_audit_adapter.py

让适配器提取 confidence 和 tier：

```python
def parse_output(self, output: str) -> list:
    """
    增强输出解析

    尝试顺序:
    1. JSON 输出 (如果 agent-audit 支持 --output json)
    2. 文本输出解析 (fallback)
    """
    # 尝试 JSON
    try:
        data = json.loads(output)
        return [self._json_to_finding(f) for f in data.get('findings', [])]
    except json.JSONDecodeError:
        pass

    # Fallback: 文本解析
    return self._parse_text_output(output)

def _json_to_finding(self, raw: dict) -> ToolFinding:
    """从 JSON 输出创建 ToolFinding"""
    return ToolFinding(
        rule_id=raw.get('rule_id', ''),
        file=raw.get('location', {}).get('file', ''),
        line=raw.get('location', {}).get('line', 0),
        severity=raw.get('severity', 'MEDIUM'),
        message=raw.get('message', ''),
        confidence=raw.get('confidence', 1.0),  # 新增
        tier=raw.get('tier', 'WARN'),            # 新增
    )
```

## 第五步：增强 run_eval.py

添加批量运行和报告生成：

```python
def main():
    parser = argparse.ArgumentParser(description='Agent-Vuln-Bench Evaluation')
    parser.add_argument('--tool', default='agent-audit', choices=['agent-audit', 'bandit', 'semgrep'])
    parser.add_argument('--dataset', default='all', choices=['all', 'knowns', 'wilds', 'noise'])
    parser.add_argument('--set', default=None, choices=['A', 'B', 'C'])
    parser.add_argument('--output', default='results/avb_results.json')
    parser.add_argument('--baseline', default=None, help='Baseline file for regression')
    parser.add_argument('--report', default='results/avb_report.md', help='Markdown report')
    args = parser.parse_args()

    # 运行评估
    results = run_evaluation(args.tool, args.dataset, args.set)

    # 计算指标
    metrics = compute_metrics_enhanced(results)

    # 回归检查
    if args.baseline:
        regression = check_regression(metrics, args.baseline)
        metrics['regression'] = regression

    # 保存结果
    save_json(metrics, args.output)

    # 生成报告
    report = generate_markdown_report(metrics, results)
    save_text(report, args.report)

    # 输出摘要
    print_summary(metrics)
```

## 第六步：添加 Markdown 报告生成

```python
def generate_markdown_report(metrics: dict, results: list) -> str:
    """生成 Markdown 格式的评估报告"""
    lines = [
        "# Agent-Vuln-Bench Evaluation Report",
        f"",
        f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Tool**: agent-audit",
        f"",
        "## Overall Metrics",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Recall | {metrics['overall']['recall']:.1%} |",
        f"| Precision | {metrics['overall']['precision']:.1%} |",
        f"| F1 | {metrics['overall']['f1']:.1%} |",
        f"",
        "## By Set",
        f"",
        f"| Set | Recall | Precision | Samples |",
        f"|-----|--------|-----------|---------|",
    ]

    for set_key in ('A', 'B', 'C'):
        s = metrics.get(f'set_{set_key}', {})
        lines.append(
            f"| Set {set_key} | {s.get('recall', 0):.1%} | "
            f"{s.get('precision', 0):.1%} | {s.get('sample_count', 0)} |"
        )

    lines.extend([
        f"",
        "## Per-Sample Details",
        f"",
        f"| Sample | Status | Rule | Confidence |",
        f"|--------|--------|------|------------|",
    ])

    for r in results:
        status = "✅ PASS" if r.get('match_type') == 'EXACT' else "❌ MISS"
        lines.append(
            f"| {r.get('sample_id', '?')} | {status} | "
            f"{r.get('rule_id', '?')} | {r.get('confidence', '?')} |"
        )

    return "\n".join(lines)
```

## 第七步：创建基线保存/加载机制

```python
# 在 metrics/ 下创建 baseline.py

def save_baseline(metrics: dict, path: str = "results/baseline.json"):
    """保存当前指标为基线"""
    baseline = {
        "version": "v0.4.1",
        "date": datetime.now().isoformat(),
        "metrics": metrics,
        "passing_samples": [r['sample_id'] for r in metrics.get('results', [])
                           if r.get('match_type') == 'EXACT'],
    }
    with open(path, 'w') as f:
        json.dump(baseline, f, indent=2)

def check_regression(current: dict, baseline_path: str) -> dict:
    """检查是否有回退"""
    with open(baseline_path) as f:
        baseline = json.load(f)

    prev_passing = set(baseline.get('passing_samples', []))
    curr_passing = set(current.get('passing_samples', []))

    return {
        "newly_passing": sorted(curr_passing - prev_passing),
        "newly_failing": sorted(prev_passing - curr_passing),
        "total_prev": len(prev_passing),
        "total_curr": len(curr_passing),
        "regression_free": len(prev_passing - curr_passing) == 0,
    }
```

## 第八步：验证

```bash
# 1. 确保增强后的代码可导入
python -c "
from tests.benchmark.agent_vuln_bench.harness.oracle_eval import *
from tests.benchmark.agent_vuln_bench.metrics.compute_metrics import *
print('All imports OK')
" 2>&1 || echo "Fix import paths"

# 2. 运行 Agent-Vuln-Bench (如果 agent-audit 可用)
cd tests/benchmark/agent-vuln-bench
python harness/run_eval.py --tool agent-audit --dataset knowns --output /tmp/avb_test.json 2>&1 | tail -20

# 3. 验证报告生成
ls results/*.md 2>/dev/null

# 4. 现有测试不破坏
pytest tests/ -v --tb=short -x 2>&1 | tail -20
```

## 约束

- **不破坏现有 harness 接口** — 所有增强通过新方法或可选参数实现
- **兼容现有 oracle.yaml** — 新字段全部可选
- **报告必须人类可读** — Markdown 格式，关键指标突出
- **错误处理** — 扫描失败不中断批量运行，记录错误继续

## 自验证清单

□ oracle_eval.py 增强后仍能处理旧格式 oracle
□ compute_metrics.py 输出包含 by_set 分组
□ agent_audit_adapter.py 能解析 JSON 和文本输出
□ run_eval.py 支持 --dataset, --set, --output, --baseline 参数
□ Markdown 报告包含 Overall + By Set + Per-Sample
□ 基线保存/加载机制工作
□ 现有测试不破坏
```

---

## Prompt B4: CI 集成 + 质量门限 + 统一仪表盘

```markdown
# 角色
你是 agent-audit 的 DevOps/CI 工程师。你正在创建自动化 CI pipeline，
将三层 Benchmark 统一为自动化质量门限系统。

# 前置条件
Prompt B1-B3 已全部完成。

验证:
```bash
# 数据集
find tests/benchmark/agent-vuln-bench/datasets -name "oracle.yaml" | wc -l
# Layer 1 样本
python -c "
import yaml
with open('tests/benchmark/ground_truth/labeled_samples.yaml') as f:
    print(f'Layer 1: {len(yaml.safe_load(f))} samples')
" 2>/dev/null
# Harness
python -c "
import importlib, sys
sys.path.insert(0, '.')
# 尝试导入增强模块
print('Prerequisites check OK')
"
```

# 任务

## 第一步：创建统一质量门限配置

创建 `tests/benchmark/quality_gates_v2.yaml`:

```yaml
# Unified Quality Gates for agent-audit v0.5.0
version: "2.0"
last_updated: "2026-02-04"

# Layer 1: 合成样本精度评估
layer1:
  enabled: true
  blocking: true  # 不通过则 CI 失败
  thresholds:
    precision_min: 0.90
    recall_min: 0.85
    f1_min: 0.87
    fp_rate_max: 0.05
  per_asi_recall_min:
    ASI-01: 0.80
    ASI-02: 0.80
    ASI-03: 0.75
    ASI-04: 0.75
    ASI-05: 0.80
    ASI-06: 0.70
    ASI-07: 0.70
    ASI-08: 0.70
    ASI-09: 0.75
    ASI-10: 0.70

# Agent-Vuln-Bench: 真实漏洞检测能力
agent_vuln_bench:
  enabled: true
  blocking: true
  thresholds:
    overall_recall_min: 0.60    # 从 17.6% → 60%+
    set_a_recall_min: 0.70      # Injection/RCE
    set_b_recall_min: 0.60      # MCP/Component
    set_c_recall_min: 0.50      # Data/Auth
    precision_min: 0.80
  regression:
    allow_regression: false     # 已通过样本不能回退
    baseline_file: "results/baseline.json"

# Layer 2: 多目标扫描稳定性
layer2:
  enabled: true
  blocking: false  # 不阻断，但报告
  thresholds:
    owasp_coverage_min: 10      # 10/10 ASI
    max_scan_time_seconds: 120  # 每个项目 2 分钟内
```

## 第二步：创建质量门限检查脚本

创建 `tests/benchmark/quality_gate_check.py`:

```python
#!/usr/bin/env python3
"""
统一质量门限检查脚本

用法:
  python quality_gate_check.py --config quality_gates_v2.yaml --results results/

退出码:
  0 = 全部通过
  1 = 有门限未通过 (blocking)
  2 = 有警告但无阻断
"""
import argparse
import json
import yaml
import sys
from pathlib import Path

def check_layer1(config: dict, results_dir: Path) -> list:
    """检查 Layer 1 门限"""
    issues = []
    layer1_config = config.get('layer1', {})
    if not layer1_config.get('enabled', True):
        return issues

    results_file = results_dir / "layer1.json"
    if not results_file.exists():
        issues.append(("SKIP", "Layer 1 results not found"))
        return issues

    with open(results_file) as f:
        results = json.load(f)

    thresholds = layer1_config.get('thresholds', {})

    for metric, min_val in thresholds.items():
        if metric.endswith('_min'):
            actual = results.get(metric.replace('_min', ''), 0)
            if actual < min_val:
                issues.append(("FAIL", f"Layer 1 {metric}: {actual:.3f} < {min_val}"))
        elif metric.endswith('_max'):
            actual = results.get(metric.replace('_max', ''), 1)
            if actual > min_val:
                issues.append(("FAIL", f"Layer 1 {metric}: {actual:.3f} > {min_val}"))

    return issues

def check_avb(config: dict, results_dir: Path) -> list:
    """检查 Agent-Vuln-Bench 门限"""
    issues = []
    avb_config = config.get('agent_vuln_bench', {})
    if not avb_config.get('enabled', True):
        return issues

    results_file = results_dir / "avb_results.json"
    if not results_file.exists():
        issues.append(("SKIP", "AVB results not found"))
        return issues

    with open(results_file) as f:
        results = json.load(f)

    thresholds = avb_config.get('thresholds', {})
    overall = results.get('overall', {})

    if overall.get('recall', 0) < thresholds.get('overall_recall_min', 0):
        issues.append(("FAIL",
            f"AVB Recall: {overall['recall']:.1%} < {thresholds['overall_recall_min']:.0%}"))

    # 检查 Set 分组
    for set_key in ('a', 'b', 'c'):
        min_key = f'set_{set_key}_recall_min'
        if min_key in thresholds:
            set_data = results.get(f'set_{set_key.upper()}', {})
            actual = set_data.get('recall', 0)
            if actual < thresholds[min_key]:
                issues.append(("FAIL",
                    f"AVB Set {set_key.upper()} Recall: {actual:.1%} < {thresholds[min_key]:.0%}"))

    # 回归检查
    regression = results.get('regression', {})
    if not regression.get('regression_free', True):
        failing = regression.get('newly_failing', [])
        issues.append(("FAIL", f"AVB Regression: {len(failing)} samples regressed: {failing}"))

    return issues

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='tests/benchmark/quality_gates_v2.yaml')
    parser.add_argument('--results', default='results/')
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    results_dir = Path(args.results)
    all_issues = []

    # Layer 1
    all_issues.extend(check_layer1(config, results_dir))

    # Agent-Vuln-Bench
    all_issues.extend(check_avb(config, results_dir))

    # 输出
    blocking_failures = [i for i in all_issues if i[0] == "FAIL"]
    warnings = [i for i in all_issues if i[0] == "WARN"]
    skips = [i for i in all_issues if i[0] == "SKIP"]

    print("=" * 60)
    print("Quality Gate Results")
    print("=" * 60)

    for level, msg in all_issues:
        icon = {"FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️"}.get(level, "?")
        print(f"  {icon} [{level}] {msg}")

    if not all_issues:
        print("  ✅ All quality gates passed!")

    print(f"\nSummary: {len(blocking_failures)} failures, {len(warnings)} warnings, {len(skips)} skipped")

    if blocking_failures:
        print("\n🚫 QUALITY GATE BLOCKED — fix the above failures before merging")
        sys.exit(1)
    elif warnings:
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
```

## 第三步：创建 GitHub Actions Workflow

创建 `.github/workflows/benchmark.yml`:

```yaml
name: Benchmark Suite

on:
  push:
    branches: [main, develop]
    paths:
      - 'agent_audit/**'
      - 'tests/**'
  pull_request:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6AM UTC

jobs:
  layer1-precision:
    name: "Layer 1: Precision & Recall"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e ".[dev]"

      - name: Run Layer 1 Benchmark
        run: |
          mkdir -p results
          python tests/benchmark/precision_recall.py \
            --output results/layer1.json \
            2>&1 | tee results/layer1.log

      - name: Upload Layer 1 Results
        uses: actions/upload-artifact@v4
        with:
          name: layer1-results
          path: results/layer1*

  agent-vuln-bench:
    name: "Agent-Vuln-Bench"
    runs-on: ubuntu-latest
    needs: layer1-precision
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Run Agent-Vuln-Bench
        run: |
          mkdir -p results
          python tests/benchmark/agent-vuln-bench/harness/run_eval.py \
            --tool agent-audit \
            --dataset all \
            --output results/avb_results.json \
            --report results/avb_report.md \
            2>&1 | tee results/avb.log

      - name: Upload AVB Results
        uses: actions/upload-artifact@v4
        with:
          name: avb-results
          path: results/avb*

  quality-gate:
    name: "Quality Gate Check"
    runs-on: ubuntu-latest
    needs: [layer1-precision, agent-vuln-bench]
    steps:
      - uses: actions/checkout@v4

      - name: Download all results
        uses: actions/download-artifact@v4
        with:
          path: results/
          merge-multiple: true

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install pyyaml

      - name: Run Quality Gate
        run: |
          python tests/benchmark/quality_gate_check.py \
            --config tests/benchmark/quality_gates_v2.yaml \
            --results results/

      - name: Upload Final Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-report
          path: results/
```

## 第四步：创建统一运行脚本（本地开发用）

创建 `tests/benchmark/run_all.sh`:

```bash
#!/bin/bash
set -e

echo "============================================"
echo "  agent-audit Benchmark Suite"
echo "============================================"
echo ""

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

# Layer 1
echo ">>> [1/3] Running Layer 1: Precision & Recall..."
python tests/benchmark/precision_recall.py \
    --output "$RESULTS_DIR/layer1.json" 2>&1 | tail -5
echo ""

# Agent-Vuln-Bench
echo ">>> [2/3] Running Agent-Vuln-Bench..."
python tests/benchmark/agent-vuln-bench/harness/run_eval.py \
    --tool agent-audit \
    --dataset all \
    --output "$RESULTS_DIR/avb_results.json" \
    --report "$RESULTS_DIR/avb_report.md" 2>&1 | tail -10
echo ""

# Quality Gate
echo ">>> [3/3] Running Quality Gate Check..."
python tests/benchmark/quality_gate_check.py \
    --config tests/benchmark/quality_gates_v2.yaml \
    --results "$RESULTS_DIR/"

echo ""
echo "============================================"
echo "  Reports: $RESULTS_DIR/"
echo "============================================"
```

## 第五步：创建 BENCHMARK_STATUS.md 模板更新

更新 `tests/benchmark/BENCHMARK_STATUS.md` (或创建) 添加统一状态跟踪:

```markdown
# Benchmark Status

## Current Metrics (auto-updated by CI)

### Layer 1
| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Precision | TBD | ≥90% | ⏳ |
| Recall | TBD | ≥85% | ⏳ |
| F1 | TBD | ≥0.87 | ⏳ |
| FP Rate | TBD | ≤5% | ⏳ |

### Agent-Vuln-Bench
| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Overall Recall | 17.6% | ≥60% | ❌ |
| Set A Recall | 33.3% | ≥70% | ❌ |
| Set B Recall | 0.0% | ≥60% | ❌ |
| Set C Recall | 0.0% | ≥50% | ❌ |
| Precision | 100% | ≥80% | ✅ |

### Dataset Size
| Dataset | Samples | Target |
|---------|---------|--------|
| Layer 1 Fixtures | ~80 | ≥80 |
| AVB Knowns | ~12 | ≥12 |
| AVB Wilds | ~6 | ≥6 |
| AVB Noise | 2 | 2 |
```

## 第六步：验证

```bash
# 1. quality_gates_v2.yaml 格式正确
python -c "
import yaml
with open('tests/benchmark/quality_gates_v2.yaml') as f:
    config = yaml.safe_load(f)
print('Config sections:', list(config.keys()))
assert 'layer1' in config
assert 'agent_vuln_bench' in config
print('✅ Config valid')
"

# 2. quality_gate_check.py 可运行 (即使没有结果文件)
python tests/benchmark/quality_gate_check.py \
    --config tests/benchmark/quality_gates_v2.yaml \
    --results /tmp/nonexistent/ 2>&1 || true

# 3. run_all.sh 可执行
chmod +x tests/benchmark/run_all.sh
# 实际运行取决于 agent-audit 是否可用

# 4. GitHub Actions 语法检查
python -c "
import yaml
with open('.github/workflows/benchmark.yml') as f:
    wf = yaml.safe_load(f)
print('Jobs:', list(wf.get('jobs', {}).keys()))
print('✅ Workflow YAML valid')
" 2>/dev/null || echo "Create .github/workflows/ dir first"

# 5. 现有测试不破坏
pytest tests/ -v --tb=short -x 2>&1 | tail -20
```

## 约束

- **不修改现有 CI 配置** — 只新增 workflow
- **质量门限初始值要现实** — 基于当前基线设置，避免首次就全部失败
- **本地和 CI 使用相同的检查逻辑** — quality_gate_check.py 统一
- **报告格式人类可读** — 失败原因要清晰具体

## 自验证清单

□ quality_gates_v2.yaml 包含 Layer 1 + AVB + Layer 2 三层配置
□ quality_gate_check.py 可独立运行，输出清晰的 PASS/FAIL
□ GitHub Actions workflow 定义了 3 个 job (layer1 → avb → gate)
□ run_all.sh 本地一键运行全量 benchmark
□ BENCHMARK_STATUS.md 有统一状态模板
□ 所有新文件无语法错误
□ 现有测试不破坏
```

---

## 附录：Prompt 执行检查表

```
┌─────────────┬────────────────────────────────┬───────────┐
│ Prompt      │ 完成标志                        │ 状态      │
├─────────────┼────────────────────────────────┼───────────┤
│ B1          │ Layer 1 样本 ≥ 80              │ ☐ 待执行  │
│             │ labeled_samples.yaml 已更新     │           │
│             │ pytest tests/ 通过              │           │
├─────────────┼────────────────────────────────┼───────────┤
│ B2          │ Knowns ≥ 12, Wilds ≥ 6        │ ☐ 待执行  │
│             │ 所有 oracle.yaml 格式验证通过   │           │
│             │ Set A≥6, B≥4, C≥4             │           │
├─────────────┼────────────────────────────────┼───────────┤
│ B3          │ oracle_eval.py 增强完成         │ ☐ 待执行  │
│             │ compute_metrics.py 有分组指标   │           │
│             │ run_eval.py 支持批量+报告       │           │
├─────────────┼────────────────────────────────┼───────────┤
│ B4          │ quality_gates_v2.yaml 存在      │ ☐ 待执行  │
│             │ quality_gate_check.py 可运行    │           │
│             │ GitHub Actions workflow 存在    │           │
│             │ run_all.sh 本地可用             │           │
└─────────────┴────────────────────────────────┴───────────┘
```
