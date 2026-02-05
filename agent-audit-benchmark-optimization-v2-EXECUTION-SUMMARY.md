# Agent-Audit Benchmark 优化 v2 — 执行 Summary

**文档**: `agent-audit-benchmark-optimization-v2.md`  
**执行日期**: 2026-02-04  
**执行范围**: Prompt B1 → B2 → B3 → B4（按文档顺序）

---

## 一、已完成项 (Completed)

### Prompt B1: Layer 1 样本扩充 + Confidence 分层测试

| 项 | 状态 | 说明 |
|----|------|------|
| Gap-1 定向样本 (eval/exec) | ✅ | 新增 `eval_bare_no_decorator.py`, `exec_dynamic_code.py`, `compile_exec_indirect.py` 于 `tests/fixtures/asi-02-tool-misuse/` |
| Gap-2 定向样本 (MCP JSON) | ✅ | 新增 `mcp_standalone_json.json`, `mcp_excessive_permissions.json` 于 `tests/fixtures/asi-04-supply-chain/direct/` |
| Gap-3 定向样本 (新凭证格式) | ✅ | 新增 `credential_new_formats.py`, `credential_connection_strings.py` 于 `tests/fixtures/asi-05-rce/direct/` |
| Gap-4 定向样本 (SSRF) | ✅ | 新增 `ssrf_bare_requests.py`, `ssrf_urllib.py` 于 `tests/fixtures/asi-02-tool-misuse/` |
| v0.5.0 新规则样本 | ✅ | 新增 `daemon_systemctl.sh`, `sudoers_config.sh`, `browser_cdp.py`, `keychain_access.py`, `subprocess_unsandboxed.py` 于对应 ASI 目录 |
| 良性对照样本 | ✅ | 新增 `eval_safe_literal.py`, `mcp_restricted.json`, `credential_placeholder.py` 于 `tests/fixtures/benign/validated/` |
| 更新 labeled_samples.yaml | ✅ | 所有新样本已加入 `tests/ground_truth/labeled_samples.yaml`（含 rule_id、owasp_id、is_true_positive、notes） |
| 未改现有样本与 precision_recall 核心逻辑 | ✅ | 仅新增文件与标注，未删改既有逻辑 |

**说明**: 文档中部分路径写的是 `tests/benchmark/fixtures/`，实际代码中 Layer 1 使用的 fixtures 路径为 `tests/fixtures/`（`precision_recall.py` 的 `--fixtures` 默认值），因此所有新样本均放在 **`tests/fixtures/`** 下，与现有评估脚本一致。

---

### Prompt B2: Agent-Vuln-Bench 数据集扩展

| 项 | 状态 | 说明 |
|----|------|------|
| KNOWN-006 (eval in Calculator) | ✅ | `datasets/knowns/KNOWN-006/`：vuln + fixed + oracle.yaml，Set A，AGENT-034 |
| KNOWN-007 (MCP allowAll) | ✅ | `datasets/knowns/KNOWN-007/`：vuln/fixed mcp_config.json + oracle，Set B |
| KNOWN-008 (MCP 无输入校验 SQL) | ✅ | `datasets/knowns/KNOWN-008/`：sql_tool.py vuln/fixed + oracle，Set B |
| KNOWN-009 (JWT 硬编码) | ✅ | `datasets/knowns/KNOWN-009/`：jwt_hardcoded.py vuln/fixed + oracle，Set C |
| KNOWN-010 (SSRF requests) | ✅ | `datasets/knowns/KNOWN-010/`：ssrf_requests.py vuln/fixed + oracle，Set A |
| KNOWN-011 (subprocess shell=True) | ✅ | `datasets/knowns/KNOWN-011/`：shell_popen.py vuln/fixed + oracle，Set A |
| KNOWN-012 (日志敏感数据) | ✅ | `datasets/knowns/KNOWN-012/`：log_sensitive.py vuln/fixed + oracle，Set C |
| WILD-003 (Agent 自修改) | ✅ | `datasets/wilds/WILD-003/`：vuln + oracle，Set A |
| WILD-004 (多平台 token) | ✅ | `datasets/wilds/WILD-004/`：vuln + oracle，Set C |
| WILD-005 (MCP stdio 全权限) | ✅ | `datasets/wilds/WILD-005/`：vuln + oracle，Set B |
| WILD-006 (Prompt injection) | ✅ | `datasets/wilds/WILD-006/`：vuln + oracle，Set A |
| 更新 catalog.yaml | ✅ | 已知/野生样本统计与条目已更新（Knowns 12，Wilds 6） |

**Oracle 数量**: 共 **20** 个 oracle（5 原有 Knowns + 7 新 Knowns + 2 原有 Wilds + 4 新 Wilds + 2 Noise），Set A/B/C 均有覆盖。

---

### Prompt B3: Harness 引擎增强

| 项 | 状态 | 说明 |
|----|------|------|
| oracle_eval.py 增强 | ✅ | 新增 `evaluate_taint_overlap()`、`evaluate_finding_enhanced()`（confidence/tier、taint 重叠） |
| compute_metrics 增强 | ✅ | `metrics/compute_metrics.py` 新增 `compute_metrics_enhanced()`，返回 overall + set_A/B/C 嵌套结构，供 CI 使用 |
| agent_audit_adapter / ToolFinding | ✅ | `ToolFinding` 增加可选字段 `tier`；adapter 解析并填充 `confidence`、`tier` |
| run_eval.py 增强 | ✅ | 支持 `--output results/avb_results.json`（单文件 CI 输出）、`--report`、`--baseline`；写入 CI 友好 JSON（overall, set_A, set_B, set_C, regression） |
| 回归检查 | ✅ | `check_regression()` 对比当前通过样本与 baseline 的 passing_samples，输出 newly_passing/newly_failing |

---

### Prompt B4: CI 集成 + 质量门限

| 项 | 状态 | 说明 |
|----|------|------|
| quality_gates_v2.yaml | ✅ | `tests/benchmark/quality_gates_v2.yaml`：Layer 1、Agent-Vuln-Bench、Layer 2 门限与 blocking 配置 |
| quality_gate_check.py | ✅ | `tests/benchmark/quality_gate_check.py`：读取门限配置与 results 目录，检查 layer1.json、avb_results.json，退出码 0/1/2 |
| GitHub Actions | ✅ | `.github/workflows/benchmark.yml` 新增 job：**agent-vuln-bench**（跑 run_eval，上传 results）、**quality-gate**（下载 layer1 + avb 产物，跑 quality_gate_check）；Layer 1 改为输出 `results/layer1.json` 并上传 |
| run_all.sh | ✅ | `tests/benchmark/run_all.sh`：本地一键执行 Layer 1 → Agent-Vuln-Bench → quality_gate_check |
| BENCHMARK_STATUS.md | ✅ | 更新当前指标表（Layer 1 / Agent-Vuln-Bench / Dataset Size）及运行说明（含 run_all.sh、run_eval --output/--report） |

---

## 二、未完成 / 部分完成 (Not Done / Partial)

| 项 | 说明 |
|----|------|
| Layer 1 样本数 ≥80 | 文档目标为 ≥80；当前为在原有 42 条样本基础上**新增**约 26 条标注（新 fixture + labeled_samples 条目），总样本数约 **68**。若需严格达到 ≥80，需再补约 12+ 条样本并同步更新 labeled_samples.yaml。 |
| precision_recall 与 quality_gates 的 “per-ASI” 检查 | `quality_gates_v2.yaml` 中已定义 `per_asi_recall_min`，但 **quality_gate_check.py** 目前仅做 Layer 1 的 overall precision/recall/f1 与 AVB 的 overall/set_A/B/C recall，**未**实现按 ASI-01～ASI-10 的逐项 recall 检查。若要完全对齐文档，需在 quality_gate_check 中增加对 layer1 结果按 ASI 分组的校验（并依赖 precision_recall 输出 per-ASI 指标）。 |
| precision_recall 输出 --output-json 结构 | 当前 `precision_recall.py` 的 `--output-json` 写入的字段为 true_positives、false_positives、false_negatives、precision、recall、f1_score 等，与 **quality_gate_check** 的期望一致。若将来在 quality_gate_check 中启用 per_asi 检查，需 precision_recall 同时输出 per-ASI 指标或单独文件。 |
| 跨工具对比 (compare_tools) | 文档 B3 提到 “compare_tools.py 增强” 与 “≥2 工具 (Bandit+Semgrep)”；本次仅完成 run_eval、oracle_eval、compute_metrics、adapter 的增强，**未**对 `compare_tools.py` 做修改，也未在 CI 中增加多工具对比报告。 |
| Agent-Vuln-Bench 基线 (baseline) 生成与门限 | `run_eval.py` 已支持 `--baseline` 做回归对比；**未**在仓库中提供预生成的 `results/baseline.json`，也未在 CI 中自动保存/更新 baseline。若需 “不允许已通过样本回退”，需在 release 或 main 上生成并提交 baseline，并在 CI 中传入 `--baseline`。 |
| Layer 2 质量门限 | `quality_gates_v2.yaml` 中已包含 layer2 的 owasp_coverage_min、max_scan_time_seconds；**quality_gate_check.py** 未实现 Layer 2 的检查逻辑（未读 Layer 2 结果文件）。 |
| 文档中的 “schema.yaml” 与 labeled_samples v2.2 字段 | 文档 3.3 节给出的 labeled_samples 扩展格式包含 `expected_confidence_min`、`expected_tier`、`benchmark_gap`、`agent_vuln_bench_link` 等；当前 **labeled_samples.yaml** 仅增加了与现有 loader 兼容的字段（如 rule_id、owasp_id、is_true_positive、confidence、notes），**未**批量添加上述 v2.2 扩展字段。若 precision_recall 或后续脚本要使用这些字段，需再补全标注并视情况扩展 loader。 |

---

## 三、验收与自检命令（建议本地执行）

```bash
# 1. Layer 1 样本数
python3 -c "
import yaml
with open('tests/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
print('Layer 1 samples:', len(data.get('samples', [])))
"

# 2. Agent-Vuln-Bench oracle 数量与 Set 分布
find tests/benchmark/agent-vuln-bench/datasets -name oracle.yaml | wc -l

# 3. 质量门限脚本（无结果文件时应为 SKIP，不阻塞）
python3 tests/benchmark/quality_gate_check.py \
  --config tests/benchmark/quality_gates_v2.yaml \
  --results results/

# 4. 本地全量 benchmark（需已安装 agent-audit）
chmod +x tests/benchmark/run_all.sh
./tests/benchmark/run_all.sh
```

---

## 四、总结表

| Prompt | 完成度 | 备注 |
|--------|--------|------|
| B1 | 高 | 所有 Gap 1–4 及 v0.5.0 规则样本、良性样本与 labeled_samples 已加；样本总数约 68，未到文档 80 目标 |
| B2 | 完成 | 7 个新 Knowns + 4 个新 Wilds + catalog 更新；20 个 oracle，Set A/B/C 均衡 |
| B3 | 高 | oracle_eval、compute_metrics、run_eval、adapter 增强与 CI 输出已完成；compare_tools 未动 |
| B4 | 高 | quality_gates_v2、quality_gate_check、workflow 新增 job、run_all.sh、BENCHMARK_STATUS 已就绪；per-ASI 与 Layer 2 检查未实现 |

**整体**: 文档中四个 Prompt 的主要交付物均已完成或大部分完成；未完成部分集中在“样本数 80+”、“per-ASI / Layer 2 门限”、“compare_tools”、“labeled_samples v2.2 扩展字段”和“baseline 自动化”，可作为后续迭代项。
