# Vulnerable Agent Example

> **WARNING: This is intentionally vulnerable code for testing agent-audit.**
> **DO NOT use any of this code in production.**

This directory contains example files with deliberate security flaws to demonstrate agent-audit's detection capabilities.

## Quick Start

```bash
# From repository root
agent-audit scan examples/vulnerable-agent/

# With JSON output
agent-audit scan examples/vulnerable-agent/ --format json

# With SARIF output (for GitHub Code Scanning)
agent-audit scan examples/vulnerable-agent/ --format sarif -o results.sarif
```

## Files

| File | Description |
|------|-------------|
| `agent.py` | Main agent with hardcoded credentials, command injection, prompt injection |
| `tools.py` | Tool functions with code execution, file traversal, insecure deserialization |
| `mcp_config.json` | MCP configuration with overly broad permissions, exposed secrets |

## Expected Findings

Running `agent-audit scan examples/vulnerable-agent/` detects **43 security issues** across 3 files:

### Critical Findings (21)

| Rule | Location | Issue |
|------|----------|-------|
| AGENT-001 | agent.py:31 | `eval()` with user input allows arbitrary code execution |
| AGENT-001 | agent.py:42 | `subprocess.run(shell=True)` with user input |
| AGENT-001 | tools.py:20 | `exec()` with user input |
| AGENT-004 | mcp_config.json | Hardcoded AWS credentials in config |
| AGENT-010 | agent.py:69 | User input in f-string system prompt |
| AGENT-017 | agent.py:31 | Unsandboxed eval() execution |
| AGENT-017 | tools.py:20,63 | Unsandboxed exec() execution |
| AGENT-035 | agent.py:31,42 | Unrestricted code execution in tools |
| AGENT-050 | agent.py:84 | AgentExecutor without max_iterations |

### High Findings (14)

| Rule | Location | Issue |
|------|----------|-------|
| AGENT-005 | mcp_config.json | Unverified remote MCP server |
| AGENT-026 | agent.py, tools.py | Tool inputs flow to dangerous operations |
| AGENT-028 | agent.py:84 | No iteration limit on agent |
| AGENT-029 | mcp_config.json | Root filesystem access (`/`) |
| AGENT-030 | mcp_config.json | Unpinned MCP package version |
| AGENT-031 | mcp_config.json | Secrets exposed in MCP env vars |
| AGENT-033 | mcp_config.json | HTTP endpoint without authentication |
| AGENT-034 | agent.py, tools.py | Tool functions without input validation |

### Medium Findings (8)

| Rule | Location | Issue |
|------|----------|-------|
| AGENT-022 | agent.py, tools.py | Tools lack try/except error handling |
| AGENT-032 | mcp_config.json | stdio transport without sandboxing |

## Sample Output

See `../sample-output/` for:
- `terminal.txt` — Terminal output with colored formatting
- `results.json` — Structured JSON output with full details

## OWASP Agentic Coverage

This example demonstrates detection across multiple OWASP Agentic Top 10 categories:

| Category | Rules Triggered |
|----------|-----------------|
| ASI-01 Goal Hijacking | AGENT-010 |
| ASI-02 Tool Misuse | AGENT-001, AGENT-026, AGENT-034, AGENT-035 |
| ASI-03 Privilege Abuse | — |
| ASI-04 Supply Chain | AGENT-004, AGENT-005, AGENT-030 |
| ASI-05 Code Execution | AGENT-017 |
| ASI-06 Memory Poisoning | — |
| ASI-07 Inter-Agent | — |
| ASI-08 Cascading Failures | AGENT-022, AGENT-028 |
| ASI-09 Trust Exploitation | AGENT-033 |
| ASI-10 Rogue Agents | — |

## Learning Resources

- [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Rule Reference](../../docs/RULES.md)
- [CI Integration Guide](../../docs/CI-INTEGRATION.md)
