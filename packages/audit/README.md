# Agent Audit

**Find security vulnerabilities in your AI agent code before they reach production.**

[![PyPI version](https://img.shields.io/pypi/v/agent-audit?color=blue)](https://pypi.org/project/agent-audit/)
[![Python](https://img.shields.io/pypi/pyversions/agent-audit.svg)](https://pypi.org/project/agent-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/HeadyZhang/agent-audit/actions/workflows/ci.yml)

---

## Why?

LLM agents can call tools, execute code, and access external systems. One missing validation and an attacker can:

- **Hijack your agent via prompt injection** -- user input flows into system prompts, letting attackers override instructions
- **Execute arbitrary commands** -- a `@tool` function passes unvalidated strings to `subprocess` or `eval`
- **Leak secrets through MCP configs** -- API keys hardcoded in `mcp.json`, servers running without auth, packages pulled without version pinning

Agent Audit catches these before deployment. Think of it as **ESLint for AI agent security**, based on the [OWASP Agentic Top 10 (2025)](https://owasp.org/www-project-agentic-security/).

---

## Quick Start

```bash
pip install agent-audit
agent-audit scan ./your-agent-project
```

That's it. Here's what the output looks like on a vulnerable agent:

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

Full coverage of all 10 OWASP Agentic Security categories. [See all rules ->](#detected-rules)

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

---

## GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  agent-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Agent Audit
        uses: HeadyZhang/agent-audit@v1
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

## Configuration

Create `.agent-audit.yaml` in your project root:

```yaml
# Ignore specific rules for certain paths
ignore:
  - rule_id: AGENT-003
    paths:
      - "auth/**"
    reason: "Auth module legitimately communicates externally"

# Scan settings
scan:
  exclude:
    - "tests/**"
    - "venv/**"
  min_severity: low
  fail_on: high
```

---

## Detected Rules

| Rule ID | Title | Severity |
|---------|-------|----------|
| AGENT-001 | Command Injection via Unsanitized Input | Critical |
| AGENT-002 | Excessive Agent Permissions | Medium |
| AGENT-003 | Potential Data Exfiltration Chain | High |
| AGENT-004 | Hardcoded Credentials | Critical |
| AGENT-005 | Unverified MCP Server | High |
| AGENT-010 | System Prompt Injection | Critical |
| AGENT-022 | No Error Handling in Tool Execution | High |
| AGENT-026 | Tool Input Not Sanitized | Critical |
| AGENT-028 | Agent Without Iteration Limit | High |
| AGENT-029 | Overly Broad MCP Filesystem Access | High |
| AGENT-030 | Unpinned MCP Server Package | Critical |
| AGENT-031 | Hardcoded Secrets in MCP Config | High |
| AGENT-032 | MCP Server Without Sandbox | Medium |
| AGENT-033 | MCP Server Without Authentication | High |
| AGENT-034 | Tool Function Without Input Validation | High |
| AGENT-035 | Unrestricted Code Execution in Tool | Critical |
| AGENT-037 | Missing Human-in-the-Loop | High |
| AGENT-040 | Insecure MCP Tool Schema | Medium |
| AGENT-041 | SQL Injection via String Interpolation | Critical |
| AGENT-042 | Excessive MCP Servers | Medium |
| AGENT-050 | AgentExecutor Without Safety Parameters | High |

---

## How It Works

Agent Audit combines three analysis engines:

1. **Python AST Scanner** -- walks the abstract syntax tree to trace data flow from `@tool` parameters to dangerous sinks (`subprocess`, `eval`, `cursor.execute`), with intra-procedural taint tracking and sanitization detection
2. **MCP Config Scanner** -- parses `mcp.json` / `claude_desktop_config.json` / YAML configs to check filesystem permissions, supply chain integrity, credential exposure, and auth gaps
3. **Secret Detector** -- pattern-matches hardcoded API keys (AWS, OpenAI, Anthropic, GitHub, etc.) with framework-aware suppression to reduce false positives from Pydantic schema definitions

For technical details on detection methodology and benchmark results, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Development

```bash
git clone https://github.com/HeadyZhang/agent-audit
cd agent-audit/packages/audit
poetry install
poetry run pytest tests/ -v
poetry run agent-audit scan .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Based on the [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-security/)
- Inspired by the need for better AI agent security tooling
