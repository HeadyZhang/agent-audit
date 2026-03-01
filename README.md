# Agent Audit

**Find security vulnerabilities in your AI agent code before they reach production.**

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-1142%20passed-brightgreen)]()

---

## Why Agent Security Fails in Production

AI agents are not just chatbots. They execute code, call tools, and touch real systems, so one unsafe input path can become a production incident.

- Prompt injection rewrites agent intent through user-controlled context
- Unsafe tool inputs can reach `subprocess`/`eval` and become command execution
- MCP configuration mistakes can leak credentials and expand access unintentionally

If your team ships agent features, owns CI security gates, or operates MCP servers and tool integrations, this is a high-probability risk surface rather than an edge case.
You likely need this before every merge if agent code can trigger tools, commands, or external systems.

**Agent Audit** catches these issues before deployment with an analysis core designed for agent workflows today: tool-boundary taint tracking, MCP configuration auditing, and semantic secret detection, with room to extend into learning-assisted detection over time.

Think of it as **security linting for AI agents**, with 40+ rules mapped to the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

---

## Quick Start in 6 Lines

1. Install

```bash
pip install agent-audit
```

2. Scan your project

```bash
agent-audit scan ./your-agent-project
```

3. Interpret and gate in CI

```bash
# Show only high+ findings
agent-audit scan . --severity high

# Fail CI when high+ findings exist
agent-audit scan . --fail-on high
```

`--severity` controls what is reported. `--fail-on` controls when the command exits with code `1`.

Sample report output:

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

Validation snapshot (as of **2026-02-19**, v0.16 benchmark set): **94.6% recall**, **87.5% precision**, **0.91 F1**, with **10/10 OWASP Agentic Top 10** coverage across **9 open-source targets**.  
Details: [Benchmark Results](docs/BENCHMARK-RESULTS.md) | [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md)

---

## What It Detects

| Category | What goes wrong | Example rule |
|----------|----------------|--------------|
| **Injection attacks** | User input flows to `exec()`, `subprocess`, SQL | AGENT-001, AGENT-041 |
| **Prompt injection** | User input concatenated into system prompts | AGENT-010 |
| **Leaked secrets** | API keys hardcoded in source or MCP config | AGENT-004, AGENT-031 |
| **Missing input validation** | `@tool` functions accept raw strings without checks | AGENT-034 |
| **Unsafe MCP servers** | No auth, no version pinning, overly broad permissions | AGENT-005, AGENT-029, AGENT-030, AGENT-033 |
| **No guardrails** | Agent runs without iteration limits or human approval | AGENT-028, AGENT-037 |
| **Unrestricted code execution** | Tools run `eval()` or `shell=True` without sandboxing | AGENT-035 |

Full coverage of all 10 OWASP Agentic Security categories. Framework-specific detection for **LangChain**, **CrewAI**, **AutoGen**, and **AgentScope**. [See all rules ->](docs/RULES.md)

---

## Who Is This For

- **Agent developers** building with LangChain, CrewAI, AutoGen, OpenAI Agents SDK, or raw function-calling -- run it before every deploy
- **Security engineers** reviewing agent codebases -- get a structured report in SARIF for GitHub Security tab
- **Teams shipping MCP servers** -- validate your `mcp.json` / `claude_desktop_config.json` for secrets, auth gaps, and supply chain risks

---

## Usage

```bash
# Scan a project
agent-audit scan ./my-agent

# JSON output for scripting
agent-audit scan ./my-agent --format json

# SARIF output for GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif

# Only fail CI on critical findings
agent-audit scan . --fail-on critical

# Inspect a live MCP server (read-only, never calls tools)
agent-audit inspect stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Baseline Scanning

Track only *new* findings across commits:

```bash
# Save current state as baseline
agent-audit scan . --save-baseline baseline.json

# Only report new findings not in baseline
agent-audit scan . --baseline baseline.json --fail-on-new
```

### GitHub Actions

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

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format: `terminal`, `json`, `sarif`, `markdown` | `sarif` |
| `severity` | Minimum severity to report | `low` |
| `fail-on` | Exit with error at this severity | `high` |
| `baseline` | Baseline file for incremental scanning | - |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |

---

## Evaluation Results

Evaluated on [**Agent-Vuln-Bench**](tests/benchmark/agent-vuln-bench/) (19 samples across 3 vulnerability categories), compared against Bandit and Semgrep:

| Tool | Recall | Precision | F1 |
|------|-------:|----------:|---:|
| **agent-audit** | **94.6%** | **87.5%** | **0.91** |
| Bandit 1.8 | 29.7% | 100% | 0.46 |
| Semgrep 1.x | 27.0% | 100% | 0.43 |

| Category | agent-audit | Bandit | Semgrep |
|----------|:-----------:|:-----:|:-------:|
| Set A -- Injection / RCE | **100%** | 68.8% | 56.2% |
| Set B -- MCP Configuration | **100%** | 0% | 0% |
| Set C -- Data / Auth | **84.6%** | 0% | 7.7% |

> Neither Bandit nor Semgrep can parse MCP configuration files -- they achieve **0% recall** on agent-specific configuration vulnerabilities (Set B).

Full evaluation details: [Benchmark Results](docs/BENCHMARK-RESULTS.md) | [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md)

## How It Works

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

**Key technical contributions:**

- **Tool-boundary-aware taint analysis** -- Tracks data flow from `@tool` function parameters to dangerous sinks (`eval`, `subprocess.run`, `cursor.execute`), with sanitization detection. Only triggers when a confirmed tool entry point has unsanitized parameters flowing to dangerous operations.

- **MCP configuration auditing** -- Parses `claude_desktop_config.json` and MCP gateway configs to detect unverified server sources, overly broad filesystem permissions, missing authentication, and unpinned package versions -- a category entirely missed by existing SAST tools.

- **Three-stage semantic credential detection** -- (1) Regex candidate discovery with priority tiers, (2) value analysis with known-format matching, entropy scoring, and placeholder/UUID exclusion, (3) context adjustment by file type, test patterns, and framework schema detection.

## Threat Coverage

40+ detection rules covering all 10 categories of the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| OWASP Category | Rules | Example Detections |
|----------------|------:|-------------------|
| ASI-01 Agent Goal Hijack | 4 | Prompt injection via f-string in `SystemMessage` |
| ASI-02 Tool Misuse | 9 | `@tool` input to `subprocess` without validation |
| ASI-03 Identity & Privilege | 4 | Daemon privilege escalation, >10 MCP servers |
| ASI-04 Supply Chain | 5 | Unverified MCP source, unpinned `npx` packages |
| ASI-05 Code Execution | 3 | `eval`/`exec` in tool without sandbox |
| ASI-06 Memory Poisoning | 2 | Unsanitized input to vector store `upsert` |
| ASI-07 Inter-Agent Comm | 1 | Multi-agent over HTTP without TLS |
| ASI-08 Cascading Failures | 3 | `AgentExecutor` without `max_iterations` |
| ASI-09 Trust Exploitation | 6 | Critical ops without `human_in_the_loop` |
| ASI-10 Rogue Agents | 3 | No kill switch, no behavior monitoring |

## Real-World Validation

Scanned 9 open-source projects to validate detection quality:

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

**10/10 OWASP Agentic Top 10 categories detected** across targets. Quality gate: **PASS**.

## Comparison with Existing Tools

| Capability | agent-audit | Bandit | Semgrep |
|-----------|:-----------:|:-----:|:-------:|
| Agent-specific threat model (OWASP Agentic Top 10) | Yes | No | No |
| MCP configuration auditing | Yes | No | No |
| Tool-boundary taint analysis | Yes | No | No |
| `@tool` decorator awareness | Yes | No | No |
| Semantic credential detection | Yes | Basic | Basic |
| General Python security | Partial | Yes | Yes |
| Multi-language support | Python-focused | Python | Multi |

agent-audit is **complementary** to general-purpose SAST tools. It targets the security gap specific to AI agent applications that existing tools cannot address.

## Configuration

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

## Current Scope

- **Current core is static analysis**: Does not execute code and may miss runtime-only logic vulnerabilities.
- **Intra-procedural taint analysis**: Tracks data flow within functions; no cross-function or cross-module tracking yet.
- **Python-focused**: Primary support for Python source and MCP JSON configs. Limited pattern matching for other languages.
- **Framework coverage**: Deep support for LangChain, CrewAI, AutoGen, AgentScope. Other frameworks use generic `@tool` detection rules.
- **False positives**: Mitigated through semantic analysis, framework detection, and allowlists; ongoing optimization (79% FP reduction in v0.16).

## Documentation

- [Technical Specification](docs/SECURITY-ANALYSIS-SPECIFICATION.md) -- Detection methodology and analysis pipeline
- [Benchmark Results](docs/BENCHMARK-RESULTS.md) -- Detailed Agent-Vuln-Bench evaluation
- [Competitive Comparison](docs/COMPETITIVE-COMPARISON.md) -- Three-tool analysis vs Bandit and Semgrep
- [Rule Reference](docs/RULES.md) -- Complete rule catalog with CWE mappings and remediation
- [Architecture](docs/ARCHITECTURE.md) -- Internal design and extension points
- [CI/CD Integration](docs/CI-INTEGRATION.md) -- GitHub Actions, GitLab CI, Jenkins, Azure DevOps

## Development

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest ../../tests/ -v  # 1142 tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development setup and PR guidelines.

## Citation

If you use agent-audit in your research, please cite:

```bibtex
@software{agent_audit_2026,
  author = {Zhang, Haiyue},
  title = {Agent Audit: Static Security Analysis for AI Agent Applications},
  year = {2026},
  url = {https://github.com/HeadyZhang/agent-audit},
  note = {Based on OWASP Agentic Top 10 (2026) threat model}
}
```

## Acknowledgments

- [OWASP Agentic Top 10 for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## License

MIT -- see [LICENSE](LICENSE).
