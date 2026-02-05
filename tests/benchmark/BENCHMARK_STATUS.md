# Agent-Audit Benchmark Status

**Version:** v0.4.1 → v0.5.0 Planning
**Date:** 2026-02-04

## Overview

agent-audit uses a three-layer benchmark system to validate detection capabilities:

| Layer | Purpose | Status |
|-------|---------|--------|
| Layer 1 | Synthetic samples (unit tests) | ✅ 381 tests passing |
| Layer 2 | Real-world frameworks | ✅ T1-T11 configured |
| **Agent-Vuln-Bench** | CVE + Wild + Noise (v1.0) | 🆕 New in v0.5.0 |

## Agent-Vuln-Bench (New)

Agent-Vuln-Bench is a standardized benchmark following the 5 Pillars framework:

### Architecture

```
tests/benchmark/agent-vuln-bench/
├── taxonomy/           # OWASP Agentic Top 10 mapping
│   ├── owasp_agentic_mapping.yaml
│   └── impact_taxonomy.yaml
├── datasets/
│   ├── knowns/        # CVE reproductions (5 samples)
│   ├── wilds/         # Real-world patterns (2 samples)
│   └── noise/         # FP testing (T12, T13)
├── harness/           # SWE-bench style evaluation
│   ├── adapters/      # Tool-agnostic adapters
│   ├── oracle_eval.py
│   └── run_eval.py
└── metrics/           # Recall, FPR, per-Set breakdown
```

### Dataset Summary

| Dataset | Count | Description |
|---------|-------|-------------|
| Knowns | 5 | CVE reproductions (CVE-2023-29374, CVE-2023-36258, etc.) |
| Wilds | 2 | Real patterns from GitHub |
| Noise | 2 | T12 (openclaw), T13 (langchain-core) |

### Current Metrics (v2 quality gates)

#### Layer 1
| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Precision | TBD | ≥90% | ⏳ |
| Recall | TBD | ≥85% | ⏳ |
| F1 | TBD | ≥0.87 | ⏳ |
| FP Rate | TBD | ≤5% | ⏳ |

#### Agent-Vuln-Bench
| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Overall Recall | 17.6% | ≥60% | ❌ |
| Set A Recall | 33.3% | ≥70% | ❌ |
| Set B Recall | 0.0% | ≥60% | ❌ |
| Set C Recall | 0.0% | ≥50% | ❌ |
| Precision | 100% | ≥80% | ✅ |

#### Dataset Size
| Dataset | Samples | Target |
|---------|---------|--------|
| Layer 1 Fixtures | ~80 | ≥80 |
| AVB Knowns | 12 | ≥12 |
| AVB Wilds | 6 | ≥6 |
| AVB Noise | 2 | 2 |

### v0.4.1 Baseline Results (historical)

| Metric | Value | Target (v0.5.0) |
|--------|-------|-----------------|
| Overall Recall | 17.6% | 80% |
| Set A Recall (Injection) | 33.3% | 90% |
| Set B Recall (MCP) | 0.0% | 90% |
| Set C Recall (Data) | 0.0% | 70% |
| Taint Accuracy | 0.0% | 30% |
| Precision | 100% | 85%+ |

### Identified Gaps

1. **eval/exec detection** - Only in @tool context, not general functions
2. **MCP JSON scanning** - Isolated JSON files not scanned
3. **Credential patterns** - API key patterns need expansion
4. **SSRF detection** - Not implemented

## Running Benchmarks

```bash
# One-command full suite (Layer 1 + Agent-Vuln-Bench + quality gate)
./tests/benchmark/run_all.sh

# Or step by step:
python tests/benchmark/precision_recall.py --output-json results/layer1.json
python tests/benchmark/agent-vuln-bench/harness/run_eval.py --tool agent-audit --output results/avb_results.json --report results/avb_report.md
python tests/benchmark/quality_gate_check.py --config tests/benchmark/quality_gates_v2.yaml --results results/

# Run existing Layer 1/2 tests
cd packages/audit && poetry run pytest ../../tests/ -v

# Agent-Vuln-Bench only
cd tests/benchmark/agent-vuln-bench
python harness/run_eval.py --tool agent-audit --dataset knowns --output results/avb_results.json

# Full comparison (requires bandit/semgrep)
python harness/run_eval.py --tool all
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v0.4.1 | 2026-02-04 | Baseline established, Agent-Vuln-Bench v1.0 created |
| v0.5.0 | TBD | Target: 80% recall, close critical gaps |

## Related Documents

- `agent-vuln-bench/results/v041_baseline/report.md` - Detailed baseline report
- `agent-vuln-bench/results/v041_baseline/metadata.yaml` - Baseline metrics
- `agent-vuln-bench/taxonomy/owasp_agentic_mapping.yaml` - Set A/B/C definitions
