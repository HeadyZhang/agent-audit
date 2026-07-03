# Competitive Comparison: agent-audit vs Bandit vs Semgrep

> **⚠️ The original table below was measured on Agent-Vuln-Bench v1.0 (19 samples) on 2026-02-19 against v0.15.1/v0.16.0.** Those numbers are kept for the audit trail and remain the per-sample comparison record. For the **current** v0.19.0 benchmark on the broader 81-sample labeled GT v2.2, see the **Current Snapshot** block below and the [README](../README.md). Reproduce with: `python tests/benchmark/precision_recall.py`.

## Current Snapshot (v0.19.0, 2026-05-30, GT v2.2, 81 samples / 218 labels)

| Tool | Recall | Precision | F1 |
|------|-------:|----------:|---:|
| **agent-audit** (v0.19.0, raw, reproducible) | **82.63%** | **73.58%** | **0.778** |
| Bandit 1.8 (injection/RCE subset) | 29.7% | 100% | 0.458 |
| Semgrep 1.x (injection/RCE subset) | 27.0% | 100% | 0.426 |

The agent-audit row reports the raw F1 directly produced by `precision_recall.py` (TP 195 / FP 70 / FN 41). A post-hoc adjusted F1 of 0.84 — computed by excluding FPs from rules added after v0.16 that are not yet labeled in GT — is documented as a footnote in [`docs/F1_REPRODUCTION.md`](F1_REPRODUCTION.md) but is not used as a headline figure because it is not directly reproducible by the included script. The Bandit/Semgrep numbers are reproduced from the AVB-19 measurement below since those tools' rule sets have not materially changed since 2026-02; a re-measurement against the 81-sample GT is on the docket alongside the GT label refresh (target: June 2026).

---

## Historical: Agent-Vuln-Bench v1.0 (19 samples, 2026-02-19, v0.15.1/v0.16.0)

Evaluated on [Agent-Vuln-Bench v1.0](../tests/benchmark/agent-vuln-bench/) — 19 samples across 3 vulnerability categories with oracle ground truth.

| Metric | agent-audit | Bandit 1.8.6 | Semgrep 1.136.0 |
|--------|------------|-------------|-----------------|
| Recall (historical AVB-19) | 94.6% | 29.7% | 27.0% |
| Precision (historical AVB-19) | 87.5% | 100.0% | 100.0% |
| F1 Score (historical AVB-19) | 0.909 | 0.458 | 0.426 |
| True Positives | 35 | 11 | 10 |
| False Negatives | 2 | 26 | 27 |
| False Positives | 5 | 0 | 0 |
| Scan time | 2.9s | 1.7s | 55.4s |

## Per-Set Recall

| Set | Description | agent-audit | Bandit | Semgrep |
|-----|-------------|------------|--------|---------|
| **A** | Injection & RCE | **100.0%** | 68.8% | 56.2% |
| **B** | MCP & Component | **100.0%** | 0.0% | 0.0% |
| **C** | Data & Auth | **84.6%** | 0.0% | 7.7% |

## Per-Sample Detail

| Sample | agent-audit | Bandit | Semgrep |
|--------|------------|--------|---------|
| KNOWN-001 (eval CVE) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-002 (exec CVE) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-003 (MCP config) | 3/0/2 | 0/3/0 | 0/3/0 |
| KNOWN-004 (hardcoded creds) | 5/0/0 | 0/5/0 | 0/5/0 |
| KNOWN-005 (shell exec) | 3/0/0 | 3/0/0 | 2/1/0 |
| KNOWN-006 (eval injection) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-007 (MCP multi-vuln) | 2/0/1 | 0/2/0 | 0/2/0 |
| KNOWN-008 (SQL injection) | 1/0/0 | 0/1/0 | 0/1/0 |
| KNOWN-009 (JWT hardcoded) | 2/0/0 | 0/2/0 | 1/1/0 |
| KNOWN-010 (SSRF) | 1/0/0 | 1/0/0 | 0/1/0 |
| KNOWN-011 (shell Popen) | 1/0/0 | 1/0/0 | 1/0/0 |
| KNOWN-012 (sensitive log) | 1/0/0 | 0/1/0 | 0/1/0 |
| WILD-001 (eval calculator) | 2/0/1 | 2/0/0 | 2/0/0 |
| WILD-002 (SSRF fetcher) | 3/0/0 | 1/2/0 | 1/2/0 |
| WILD-003 (self-modify) | 1/0/0 | 0/1/0 | 0/1/0 |
| WILD-004 (token collector) | 3/0/0 | 0/3/0 | 0/3/0 |
| WILD-005 (MCP wildcard) | 2/0/1 | 0/2/0 | 0/2/0 |
| WILD-006 (prompt inject) | 2/0/0 | 0/2/0 | 0/2/0 |

*Format: TP/FN/FP*

## Key Differentiators

### Set B: MCP Configuration (agent-audit exclusive)

Bandit and Semgrep cannot parse MCP JSON configurations. They have **0% recall** on KNOWN-003, KNOWN-007, and WILD-005. agent-audit's MCPConfigScanner is the only tool that detects:

- Overly broad filesystem access (`"args": ["/"]`)
- Wildcard command grants
- Unpinned NPX packages (`npx -y @some/package` without version lock)
- Hardcoded credentials in MCP server configs
- Missing authentication on MCP transports

### Set A: Injection / RCE (@tool context awareness)

Bandit detects basic `eval()`/`exec()`/`subprocess` calls but lacks `@tool` decorator context awareness. agent-audit's tool-boundary-aware taint analysis identifies LLM-controllable input flowing to dangerous sinks, enabling detection of:

- SQL injection via f-string in tool functions (KNOWN-008)
- SSRF through unvalidated URL parameters (WILD-002)
- Prompt injection via user input in system messages (WILD-006)
- Agent self-modification through dynamic code execution (WILD-003)

### Set C: Data & Auth (semantic credential analysis)

agent-audit's three-stage semantic analyzer detects hardcoded credentials in complex formats that simple pattern matching misses:

- JWT tokens embedded in configuration
- Database connection strings with inline passwords
- Multi-field credential configurations (API key + secret pairs)
- Framework schema definitions correctly suppressed (Pydantic `Field`, type annotations)

## Methodology

- **Oracle-based evaluation**: Each sample has a hand-labeled `oracle.yaml` defining expected vulnerability locations (file + line within 5-line tolerance)
- **File + line matching**: True positives require the finding to match the oracle's file path and line number (no rule_id matching required, allowing cross-tool comparison)
- **Three dataset categories**: Set A (injection/RCE), Set B (MCP/component), Set C (data/auth)
- **Noise dataset (T12)**: Validates that tools do not over-report on benign patterns

## Complementary Use

agent-audit is designed to complement, not replace, general-purpose SAST tools:

| Use Case | Recommended Tool |
|----------|-----------------|
| AI agent code, `@tool` functions, MCP configs | **agent-audit** |
| General Python security (non-agent code) | Bandit, Semgrep |
| Multi-language security scanning | Semgrep |
| Supply chain vulnerability scanning | Trivy, Snyk |

For comprehensive coverage, run agent-audit alongside your existing SAST pipeline.
