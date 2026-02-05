# Agent-Audit Benchmark 工业级优化技术方案 v3 & Claude Code Prompts

> **版本**: v3.0  
> **日期**: 2026-02-04  
> **目标**: 补齐 v2 执行 Summary 中「未完成/部分完成」的 6 项，形成可落地的工业级 Benchmark 体系  
> **适用**: 按顺序喂给 Claude Code 执行；每段 Prompt 可独立运行，建议顺序执行以保持依赖一致

---

## 提示词工程原则（本方案采用）

- **角色单一**：每段 Prompt 开头明确「你是谁、负责哪一块」，避免泛化执行。
- **先读后写**：要求先执行查看/阅读命令（如统计样本数、读现有代码），再改代码或数据，减少误改。
- **单职责**：一个 Prompt 只完成一个可交付目标（如「只加 per_asi 输出」「只加 per-ASI 检查」），便于回滚与验收。
- **约束显式**：用「仅新增」「不删除」「不破坏现有」等约束限制行为，避免破坏已有能力。
- **接口约定**：用表格或代码块明确文件路径、JSON/YAML 结构、字段含义，保证与现有脚本兼容。
- **可验收**：每段末尾提供「自检命令」和「交付清单」，便于 Claude Code 自验或人工抽查。

---

## 第一部分：优化技术方案总览

### 1.1 当前缺口与目标

| 缺口项 | 当前状态 | 目标 | 依赖 |
|--------|----------|------|------|
| **Layer 1 样本数 ≥80** | ~68 条 | ≥80 条 | 无 |
| **per-ASI 质量门限** | 未实现 | precision_recall 输出 per_asi；quality_gate_check 按 ASI-01～10 检查 | Layer 1 输出扩展 |
| **Layer 2 门限检查** | 未实现 | quality_gate_check 读取 layer2 结果，检查 owasp_coverage / max_scan_time | run_benchmark 输出约定 |
| **compare_tools 增强** | 有基础实现 | run_eval 可调 compare_tools；CI 产出多工具对比报告 | run_eval 集成 |
| **Baseline 自动化** | 无 | 提供 baseline 生成脚本 + CI 中可选保存/使用 baseline | run_eval 已有 --baseline |
| **labeled_samples v2.2** | 无扩展字段 | schema + YAML 增加 expected_confidence_min、expected_tier、benchmark_gap、agent_vuln_bench_link | 无 |

### 1.2 模块依赖关系

```
P1 (Layer 1 样本 + v2.2 字段)  可并行
         │
         ├──► P2 (precision_recall per-ASI 输出)
         │              │
         │              └──► P3 (quality_gate_check per-ASI + Layer2)
         │
P4 (compare_tools 集成) 可独立
P5 (Baseline 自动化)    可独立，依赖 run_eval 现有能力
```

### 1.3 文件与接口约定

| 组件 | 路径 | 变更要点 |
|------|------|----------|
| Layer 1 标注 | `tests/ground_truth/labeled_samples.yaml` | 新增样本至 ≥80；可选补 v2.2 字段 |
| 标注 schema | `tests/ground_truth/schema.yaml` | 新增 v2.2 可选字段定义 |
| Layer 1 评估 | `tests/benchmark/precision_recall.py` | --output-json 增加 `per_asi` 结构 |
| 门限配置 | `tests/benchmark/quality_gates_v2.yaml` | 已有 per_asi_recall_min / layer2；无需改 |
| 门限脚本 | `tests/benchmark/quality_gate_check.py` | 实现 check_layer1_per_asi()、check_layer2() |
| Layer 2 结果 | 约定 `results/layer2.json` | owasp_coverage, max_scan_time_seconds, per_target |
| 多工具对比 | `tests/benchmark/agent-vuln-bench/metrics/compare_tools.py` | 可被 run_eval 调用；输出 comparison_report.md |
| Baseline | `results/baseline.json` | passing_samples, metrics, version, date；脚本生成 + CI 可选上传 |

---

## 第二部分：工业级 Prompt（按执行顺序）

以下每个 Prompt 设计为：**角色清晰、先读后写、单职责、可验收**，便于 Claude Code 按顺序执行。

---

## Prompt P1: Layer 1 样本补齐至 ≥80 + labeled_samples v2.2 字段与 schema

```markdown
# 角色
你是 agent-audit 的 Benchmark 数据工程师。你的任务是将 Layer 1 样本数从当前约 68 条补齐到 **≥80 条**，并为标注与 schema 增加 v2.2 扩展字段（可选写入，不破坏现有 loader）。

# 约束
- **仅新增**：不删除、不修改现有样本文件与现有 labeled_samples 条目。
- **路径规范**：所有新 fixture 必须放在 `tests/fixtures/` 下（与 `precision_recall.py` 的 `--fixtures` 默认一致），路径在 labeled_samples 中为相对 `tests/fixtures/` 的路径。
- **单文件 ≤50 行**，单样本聚焦单一漏洞或单一良性模式。
- **标注格式**：必须与现有 `tests/ground_truth/labeled_samples.yaml` 的 `samples[].file` 与 `samples[].vulnerabilities[]` 结构一致；v2.2 字段为可选键，若 loader 未读则忽略即可。

# 第一步：确认当前数量与结构
执行并理解输出：
```bash
cd /Users/heady/Documents/agent-audit/agent-security-suite
python3 -c "
import yaml
with open('tests/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
samples = data.get('samples', [])
print('Current sample count:', len(samples))
# 按 ASI 统计（从 vulnerabilities[].owasp_id 推断）
from collections import Counter
asi = []
for s in samples:
    for v in s.get('vulnerabilities', []):
        o = v.get('owasp_id')
        if o: asi.append(o)
print('Per-ASI label count:', dict(Counter(asi)))
"
```
确认当前样本数；若已 ≥80 则本 Prompt 只做 v2.2 与 schema，否则继续下一步。

# 第二步：补齐样本至 ≥80
1. 在 `tests/fixtures/` 下适当目录（如 `asi-02-tool-misuse/direct/`、`asi-05-rce/direct/`、`benign/validated/` 等）**新增至少 12 个** fixture 文件（.py / .json / .sh），覆盖：
   - 至少 2 个 ASI 类别仍偏少的（根据上一步统计），各增加 1～2 个漏洞样本；
   - 至少 2 个良性/FP 样本（放 `benign/validated/`），用于 FP 率与 SUPPRESSED 行为验证。
2. 每个新文件需在文件头用注释标明：预期规则（如 AGENT-034）、对应 owasp_id（如 ASI-02）、是否良性。
3. 在 `tests/ground_truth/labeled_samples.yaml` 的 **samples** 列表末尾，为每个新 fixture **追加一条**，格式与现有条目一致：
   - `file`: 相对 `tests/fixtures/` 的路径（如 `asi-02-tool-misuse/direct/xxx.py`）；
   - `vulnerabilities`: 列表，每项含 `line`, `rule_id`, `owasp_id`, `is_true_positive`, 可选 `confidence`, `notes`；
   - 良性样本可为 `vulnerabilities: []` 或单条 `is_true_positive: false`（对应可能被误报的行）。

# 第三步：schema 与 v2.2 扩展字段
1. 编辑 `tests/ground_truth/schema.yaml`：在 `vulnerabilities` 的 `properties` 下**新增可选**字段（不加入 `required`）：
   - `expected_confidence_min` (number, 0~1)
   - `expected_confidence_max` (number, 0~1)
   - `expected_tier` (string: BLOCK | WARN | INFO | SUPPRESSED)
   - `benchmark_gap` (string, 如 Gap-1)
   - `agent_vuln_bench_link` (string, 如 KNOWN-001)
2. 在 `tests/ground_truth/labeled_samples.yaml` 中，**仅对已有或新加的部分条目**在对应 `vulnerabilities[]` 下补充上述 v2.2 字段（不必全量补全）；保证 YAML 合法、现有 loader 不报错（loader 未读的键可忽略）。

# 第四步：自检
```bash
python3 -c "
import yaml
with open('tests/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
n = len(data.get('samples', []))
assert n >= 80, f'samples {n} < 80'
print('Samples:', n)
"
```
确认 `tests/ground_truth/schema.yaml` 可被正常解析（若有 schema 校验脚本则运行）。

# 交付清单
- [ ] Layer 1 样本数 ≥80（新增至少 12 个 fixture + 对应 labeled_samples 条目）
- [ ] `schema.yaml` 中已添加 v2.2 可选字段定义
- [ ] 至少部分样本的 vulnerabilities 含 v2.2 字段（可选）
- [ ] 未修改或删除任何现有样本与现有条目
```

---

## Prompt P2: precision_recall.py 输出 per-ASI 指标到 --output-json

```markdown
# 角色
你是 agent-audit 的 Benchmark 引擎工程师。任务：在 **不改变现有评估逻辑** 的前提下，让 `tests/benchmark/precision_recall.py` 在写入 `--output-json` 时，**额外输出 per-ASI 的 recall 与样本数**，供 quality_gate_check 使用。

# 背景
- 当前 `load_ground_truth()` 返回 `Dict[file_path, List[VulnerabilityLabel]]`，`VulnerabilityLabel` 含 `owasp_id`（如 ASI-01）。
- 当前 `evaluate()` 只计算全局 TP/FP/FN；未按 owasp_id 分组。
- `quality_gates_v2.yaml` 已定义 `layer1.per_asi_recall_min`（ASI-01～ASI-10），需要 layer1.json 中有 `per_asi` 结构与之对应。

# 约束
- 不修改 `evaluate()` 的入参/返回值语义；可在内部或调用后基于同一 `ground_truth` 与 `findings` 再算一遍 per-ASI。
- 保持现有 `--output-json` 的顶层字段（true_positives, false_positives, false_negatives, precision, recall, f1_score, false_positive_rate, tp_details, fp_details, fn_details）；**仅新增**一个顶层键 `per_asi`。

# 实现要求
1. **per-ASI 计算**：对 ground_truth 中每个 label，用其 `owasp_id`（若为空则跳过或归入 "unknown"）分组；对每组计算：
   - 该组内的 expected vuln 数（is_true_positive 的 label 数）；
   - 该组内被匹配到的 TP 数（与现有 evaluate 的匹配逻辑一致：同一 file/line/rule_id 或 line_tolerance 内匹配）；
   - recall_per_asi = TP_per_asi / expected_per_asi（若 expected_per_asi==0 则不计入或记为 N/A）。
2. **输出结构**：在写入的 JSON 中增加：
   ```json
   "per_asi": {
     "ASI-01": { "recall": 0.85, "expected": 10, "tp": 8 },
     "ASI-02": { "recall": 0.90, "expected": 20, "tp": 18 },
     ...
   }
   ```
   仅包含在 ground_truth 中实际出现过的 ASI-XX；若某 ASI 无 expected 则可不输出或 recall 为 0。
3. **复用匹配逻辑**：与 `evaluate()` 中 TP 判定一致（file + rule_id + line 或 line_tolerance），避免重复实现：可从 `evaluate()` 返回的 `result.tp_details` 与 ground_truth 反推每个 TP 属于哪个 owasp_id，或在内部分组统计 TP/FN。

# 验收
运行并确认输出 JSON 含 `per_asi` 且各 ASI 的 recall/expected/tp 合理：
```bash
cd /Users/heady/Documents/agent-audit/agent-security-suite
python3 tests/benchmark/precision_recall.py --output-json /tmp/layer1.json 2>/dev/null; python3 -c "
import json
with open('/tmp/layer1.json') as f:
    d = json.load(f)
assert 'per_asi' in d
print('per_asi keys:', list(d['per_asi'].keys())[:5])
print('sample ASI-02:', d['per_asi'].get('ASI-02'))
"
```

# 交付清单
- [ ] --output-json 输出中新增 `per_asi` 对象，键为 ASI-01～ASI-10 等，值为 { recall, expected, tp }
- [ ] 未改变现有 evaluate 逻辑与现有 JSON 其他字段
```

---

## Prompt P3: quality_gate_check.py 实现 per-ASI 与 Layer 2 检查

```markdown
# 角色
你是 agent-audit 的 CI/质量门限工程师。任务：在 `tests/benchmark/quality_gate_check.py` 中**新增**两类检查并保持现有 Layer 1 overall 与 AVB 检查不变：（1）Layer 1 **per-ASI** recall 门限；（2）**Layer 2** 门限（owasp_coverage_min、max_scan_time_seconds）。

# 约束
- 不删除、不破坏现有 `check_layer1()`、`check_avb()` 的调用与输出；仅扩展 Layer 1 的检查内容，并新增 Layer 2 检查函数。
- 配置来源仍为 `quality_gates_v2.yaml`（已含 `layer1.per_asi_recall_min` 与 `layer2.thresholds`）。

# 第一步：读懂现有逻辑与配置
- 阅读 `tests/benchmark/quality_gate_check.py` 中 `check_layer1()`、`check_avb()` 及 `main()` 如何收集 issues 并退出。
- 阅读 `tests/benchmark/quality_gates_v2.yaml` 中 `layer1.per_asi_recall_min` 与 `layer2.enabled`、`layer2.thresholds`（owasp_coverage_min、max_scan_time_seconds）的结构。

# 第二步：Layer 1 per-ASI 检查
1. 在 `check_layer1()` 中，当 `results_file` 存在且成功加载 JSON 后：
   - 若 JSON 中有 `per_asi` 对象，则读取 `config["layer1"].get("per_asi_recall_min", {})`；
   - 对每个 ASI（如 ASI-01～ASI-10），若配置中存在该 ASI 的 recall_min（如 0.80），则比较 `results["per_asi"].get(asi, {}).get("recall", 0)` 与门限；
   - 若某 ASI 的 recall < 门限，则追加一条 issue：`("FAIL", f"Layer 1 {asi} recall {actual:.1%} < {min_val:.0%}")`。
2. 若 JSON 中无 `per_asi`，则**不**因 per-ASI 报错（可视为未实现，仅跳过 per-ASI 检查），保持与现有行为兼容。

# 第三步：Layer 2 检查
1. 新增函数 `check_layer2(config: dict, results_dir: Path) -> list`：
   - 若 `config["layer2"].get("enabled", True)` 为 False，返回空列表。
   - 读取 `results_dir / "layer2.json"`；若不存在，则追加 `("SKIP", "Layer 2 results not found")` 并返回。
   - 约定 layer2.json 结构至少为：`{ "owasp_coverage": <int>, "max_scan_time_seconds": <float>, 可选 "per_target": [...] }`。
   - 从 `config["layer2"]["thresholds"]` 读取 `owasp_coverage_min`、`max_scan_time_seconds`（作为单次扫描最大耗时上限）；
   - 若 `owasp_coverage < owasp_coverage_min`，则 FAIL；
   - 若存在 `max_scan_time_seconds` 且结果中有某次扫描超过该值（可从 per_target 或顶层字段判断），则 FAIL 或 WARN（由你定，建议 WARN）。
2. 在 `main()` 中把 `check_layer2(config, results_dir)` 的结果并入 `all_issues`。

# 第四步：文档与自检
- 在脚本顶部的 docstring 中注明：支持 Layer 1 per-ASI 与 Layer 2 检查，Layer 2 结果文件为 `results/layer2.json`。
- 自检：无 layer2.json 时运行应出现 SKIP 而非崩溃；有 layer1.json 且含 per_asi 时，若某 ASI 低于门限应出现 FAIL。

# 交付清单
- [ ] Layer 1 在存在 per_asi 时按 per_asi_recall_min 逐项检查并报 FAIL
- [ ] 新增 check_layer2()，读取 layer2.json，检查 owasp_coverage_min 与 max_scan_time
- [ ] main() 中集成 check_layer2 的 issues
- [ ] 未破坏现有 Layer 1 overall 与 AVB 检查
```

---

## Prompt P4: run_benchmark.py 输出 layer2.json 供 quality_gate_check 使用

```markdown
# 角色
你是 agent-audit 的 Benchmark 工程师。任务：让 `tests/benchmark/run_benchmark.py` 在生成报告时**同时写入**一份 `results/layer2.json`（或通过参数指定路径），结构满足 `quality_gate_check.py` 的 Layer 2 检查约定。

# 约定（与 P3 一致）
`layer2.json` 至少包含：
- `owasp_coverage`: int，本次 run 中检测到的 ASI 类别数（1～10）。
- `max_scan_time_seconds`: float，所有 target 中单次扫描最大耗时（秒）。
- 可选 `per_target`: list，每项含 target_id、scan_duration_seconds、asi_count 等，便于后续扩展。

# 实现要求
1. 阅读 `tests/benchmark/run_benchmark.py` 中如何计算 `owasp_coverage`（如 `report.owasp_coverage`、`all_asi`）以及每个 target 的 `scan_duration_seconds`。
2. 在生成 JSON 报告（或单独逻辑）时，写入一份 layer2.json：
   - 路径可由 `--output-dir` 或新增 `--layer2-json` 指定，默认 `results/layer2.json`（相对当前工作目录或与现有报告同目录）。
3. 确保 `max_scan_time_seconds` 取值为各 target 的 `scan_duration_seconds` 的最大值。

# 验收
运行 run_benchmark（若依赖外部仓库可 mock 或跳过实际 scan，仅保证写入逻辑和文件结构正确）后检查：
```bash
python3 -c "
import json
with open('results/layer2.json') as f:
    d = json.load(f)
assert 'owasp_coverage' in d and 'max_scan_time_seconds' in d
print(d)
"
```

# 交付清单
- [ ] run_benchmark 运行后产出 layer2.json，含 owasp_coverage、max_scan_time_seconds
- [ ] quality_gate_check 能读取该文件并执行 P3 中约定的检查
```

---

## Prompt P5: compare_tools 集成到 run_eval + CI 多工具对比报告

```markdown
# 角色
你是 agent-audit 的 Benchmark 工程师。任务：（1）在 `tests/benchmark/agent-vuln-bench/harness/run_eval.py` 中，当使用 `--tool all` 时，在保存结果后**调用** `metrics.compare_tools` 的对比报告生成，并写入一份多工具对比报告；（2）在 CI（.github/workflows/benchmark.yml）中增加可选 job 或步骤，运行多工具评估并上传对比报告。

# 约束
- 不改变 `--tool agent-audit` 的默认行为；仅当 `--tool all` 且成功得到多工具结果时，生成对比报告。
- `compare_tools.py` 已有 `generate_comparison_matrix()`、`generate_detailed_report()`、`generate_json_comparison()`；可直接导入使用。

# 实现要求
1. **run_eval.py**：
   - 在 `save_results()` 之后（或在其内部，当 `all_results` 含多于一个 tool 时），调用 `generate_detailed_report(all_results)` 或等价函数，将返回的 Markdown 字符串写入到输出目录下的 `comparison_report.md`（或通过 `--comparison-report` 指定路径）。
   - 若存在 `generate_json_comparison(all_results)`，也可将 JSON 写入 `comparison_results.json`，便于 CI 解析。
2. **CI**：
   - 在 `.github/workflows/benchmark.yml` 中，在现有 `agent-vuln-bench` job 之后增加一个**可选** job（例如 `compare-tools`），条件为：仅当需要多工具对比时运行（例如通过 workflow_dispatch 的 input 或 schedule 触发）；或在同一 job 内增加一步：安装 bandit/semgrep 后执行 `python harness/run_eval.py --tool all --output results/`，然后上传 `results/comparison_report.md` 与 `results/comparison_results.json` 作为 artifact。
   - 若 CI 中不强制安装 bandit/semgrep，可设为 continue-on-error: true，并注明“多工具对比为可选”。

# 验收
- 本地执行：`python tests/benchmark/agent-vuln-bench/harness/run_eval.py --tool all --output results/` 后，存在 `results/comparison_report.md`（且内容含多工具矩阵）。
- CI 中新 job 或新步骤可成功上传 artifact（或跳过时不影响主流程）。

# 交付清单
- [ ] run_eval 在 --tool all 时生成 comparison_report.md（及可选 comparison_results.json）
- [ ] CI 中增加多工具对比步骤或 job，并上传对比报告 artifact
```

---

## Prompt P6: Baseline 生成脚本 + CI 中 baseline 的保存与使用

```markdown
# 角色
你是 agent-audit 的 DevOps/Benchmark 工程师。任务：（1）新增一个**可执行脚本**，用于在本地或 CI 中生成 Agent-Vuln-Bench 的 baseline 文件；（2）在 CI 中实现：在 main 或 release 分支通过时**可选**保存当前结果为 baseline，在 PR 或后续 run 中**可选**使用该 baseline 做回归检查。

# 约定
- **baseline 文件**：JSON，至少包含 `passing_samples`（list of sample_id）、`metrics`（overall recall/precision 等）、`version`、`date`。
- `run_eval.py` 已支持 `--baseline <path>`，会对比当前 passing 与 baseline 的 passing_samples，并写入 `regression` 段。

# 实现要求
1. **生成脚本**（建议路径 `tests/benchmark/agent-vuln-bench/scripts/save_baseline.py` 或 `tests/benchmark/scripts/save_avb_baseline.py`）：
   - 接受参数：`--output`（默认 `results/baseline.json`）、`--eval-results`（可选，指向 run_eval 产出的 JSON；若不提供则内部调用 run_eval 或要求用户先跑完 run_eval）。
   - 逻辑：读取 eval 结果（单工具 agent-audit 的 CI 格式或 run_eval 的 results.json），提取 passing 的 sample_id 列表与 overall 指标，写入 baseline 文件，格式为 `{ "version": "v0.5.0", "date": "<iso>", "passing_samples": [...], "metrics": { "recall": ..., "precision": ... } }`。
2. **CI**：
   - 在 `benchmark.yml` 的 `agent-vuln-bench` job 中，当分支为 `main` 或 `master` 且 quality-gate 通过时，增加一步：生成 baseline（例如从当前 run 的 avb_results.json 生成）并**上传为 artifact**（如 `baseline`），不强制覆盖仓库内文件。
   - 在 `quality-gate` job 或 `agent-vuln-bench` job 中，增加**可选**步骤：下载上一次的 baseline artifact（若存在），传入 `run_eval.py --baseline` 或让 quality_gate_check 读取 avb_results.json 中的 regression 段；若配置 `agent_vuln_bench.regression.allow_regression: false` 且存在 newly_failing，则 FAIL。

# 验收
- 运行 `python tests/benchmark/.../save_avb_baseline.py --eval-results results/avb_results.json --output results/baseline.json` 后，存在 baseline.json 且含 passing_samples 与 metrics。
- CI 中能上传/下载 baseline artifact，且 quality_gate_check 或 run_eval 能使用 baseline 做回归判断。

# 交付清单
- [ ] 新增 baseline 生成脚本，可从 run_eval 结果生成 baseline.json
- [ ] CI 中 main 通过时上传 baseline artifact；quality-gate 或 agent-vuln-bench 可选使用 baseline 做回归
```

---

## 第三部分：执行顺序与验收总表

| 顺序 | Prompt | 产出 | 验收命令 |
|------|--------|------|----------|
| 1 | P1 | 样本 ≥80，schema v2.2，labeled_samples 部分 v2.2 | `python3 -c "import yaml; d=yaml.safe_load(open('tests/ground_truth/labeled_samples.yaml')); assert len(d['samples'])>=80"` |
| 2 | P2 | precision_recall --output-json 含 per_asi | `python3 tests/benchmark/precision_recall.py --output-json /tmp/l1.json && python3 -c "import json; print(json.load(open('/tmp/l1.json')).get('per_asi',{}))"` |
| 3 | P3 | quality_gate_check 支持 per-ASI + Layer2 | `python3 tests/benchmark/quality_gate_check.py --config tests/benchmark/quality_gates_v2.yaml --results results/` |
| 4 | P4 | run_benchmark 产出 layer2.json | `python3 -c "import json; print(json.load(open('results/layer2.json')))"`（需先跑 run_benchmark） |
| 5 | P5 | run_eval --tool all 生成 comparison_report.md；CI 上传 | 本地 run_eval --tool all 后检查 results/comparison_report.md |
| 6 | P6 | save_baseline 脚本 + CI baseline artifact | 运行 save_avb_baseline 后检查 results/baseline.json |

---

## 第四部分：Claude Code 使用建议

1. **一次只执行一个 Prompt**：粘贴整段 markdown（含代码块），让 Claude Code 按“先读后写、再运行验收”执行。
2. **路径与仓库根**：所有路径以项目根为基准（如 `agent-security-suite`）；必要时在 Prompt 中写明 `cd /Users/heady/Documents/agent-audit/agent-security-suite`。
3. **失败时**：若某步失败，根据报错修正后再执行下一 Prompt；P2 依赖 P1 的样本数，P3 依赖 P2 的 per_asi 输出，P4 与 P5、P6 相对独立。
4. **版本与分支**：在 main 上做 baseline 上传时，确保 workflow 中分支条件与 artifact 名称与本文档一致，便于后续扩展。

---

*文档结束。按 P1→P2→P3→P4→P5→P6 顺序执行即可完成 v2 遗留的 6 项工业级补齐。*

---

## 附录：Prompt 快速拷贝顺序

| 顺序 | 标题 | 拷贝内容 |
|------|------|----------|
| 1 | P1 | 从「## Prompt P1: Layer 1 样本补齐…」到该 Prompt 的「交付清单」结束（含代码块） |
| 2 | P2 | 从「## Prompt P2: precision_recall.py 输出 per-ASI…」到该 Prompt 的「交付清单」结束 |
| 3 | P3 | 从「## Prompt P3: quality_gate_check.py…」到该 Prompt 的「交付清单」结束 |
| 4 | P4 | 从「## Prompt P4: run_benchmark.py 输出 layer2.json…」到该 Prompt 的「交付清单」结束 |
| 5 | P5 | 从「## Prompt P5: compare_tools 集成…」到该 Prompt 的「交付清单」结束 |
| 6 | P6 | 从「## Prompt P6: Baseline 生成脚本…」到该 Prompt 的「交付清单」结束 |

**建议**：每次只向 Claude Code 发送一个完整 Prompt（含其内所有代码块与清单），待执行并验收通过后再发下一个。
