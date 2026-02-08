# Introducing Agent Audit: The First Open-Source Security Scanner for AI Agents

**TL;DR:** AI agents can execute code, access files, and make API calls — but most security tools weren't built to understand them. Agent Audit is a free, open-source static analyzer that catches vulnerabilities specific to AI agents, mapped to the OWASP Agentic Top 10.

---

## The New Attack Surface You're Not Scanning For

Remember when we thought SQL injection was bad? Welcome to the age of **prompt injection** — where a single malicious input can hijack an AI agent's goals, exfiltrate your data, or execute arbitrary code on your servers.

Consider this innocent-looking LangChain tool:

```python
@tool
def run_query(query: str) -> str:
    """Execute a database query."""
    return cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
```

Traditional SAST tools see a function. They might flag the SQL injection. But they completely miss the bigger picture: this is a **tool** that an LLM can invoke with **any input it wants**.

An attacker doesn't need to find your API endpoint. They just need to craft a prompt that convinces your agent to call this tool with `'; DROP TABLE users; --`.

This is the reality of **agentic applications** in 2026:
- 🤖 Agents have access to tools that read files, execute code, and make network requests
- 🔗 MCP servers expose capabilities to Claude, GPT, and other AI assistants
- 🧠 RAG pipelines can be poisoned to influence agent behavior across sessions
- ⛓️ Multi-agent systems trust each other without authentication

**Your existing security tools weren't built for this.**

---

## OWASP Says It's Time to Pay Attention

The security community has noticed. In early 2026, OWASP released the **[Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)** — a definitive list of the most critical security risks in AI agent applications:

| ID | Category | What Goes Wrong |
|----|----------|-----------------|
| ASI-01 | Goal Hijacking | Agent objectives manipulated via prompt injection |
| ASI-02 | Tool Misuse | Agent tricked into executing malicious tool calls |
| ASI-03 | Privilege Abuse | Agent uses excessive permissions or escalates access |
| ASI-04 | Supply Chain | Malicious MCP servers, poisoned RAG data |
| ASI-05 | Code Execution | Unsandboxed eval/exec in agent tools |
| ASI-06 | Memory Poisoning | Persistent context manipulation |
| ASI-07 | Inter-Agent Comms | Unencrypted/unauthenticated agent messaging |
| ASI-08 | Cascading Failures | No circuit breakers, infinite agent loops |
| ASI-09 | Trust Exploitation | Agent impersonation, opaque decision-making |
| ASI-10 | Rogue Agents | Agents without kill switches or monitoring |

If you're building with LangChain, CrewAI, AutoGen, or exposing tools via MCP — **these risks apply to you**.

---

## Meet Agent Audit

**[Agent Audit](https://github.com/HeadyZhang/agent-audit)** is the first open-source static analyzer built specifically for AI agent code. Think of it as "ESLint for AI agents."

### What It Scans

- **Python agent code** — Deep AST analysis for LangChain, CrewAI, AutoGen patterns
- **MCP configurations** — `claude_desktop_config.json`, MCP Gateway configs
- **Hardcoded credentials** — 3-stage semantic analysis to minimize false positives
- **Tool definitions** — Detects dangerous `@tool` functions with unvalidated inputs

### How It Works

```bash
# Install
pip install agent-audit

# Scan your project
agent-audit scan ./my-agent-project

# Output SARIF for GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif
```

![Agent Audit Terminal Output](docs/demo.png)
*↑ Real scan output showing findings by severity and OWASP category*

### Key Features

✅ **40+ detection rules** mapped to all 10 OWASP Agentic categories
✅ **Taint analysis** — Tracks data flow from user input to dangerous sinks
✅ **Confidence scoring** — Every finding rated 0.0-1.0 to reduce noise
✅ **GitHub Action** — Native CI/CD integration with SARIF upload
✅ **Baseline scanning** — Only alert on *new* findings in PRs
✅ **MCP Inspector** — Probe live MCP servers without executing tools

---

## Real-World Example: Scanning a Vulnerable Agent

Let's scan a realistic (intentionally vulnerable) agent project:

```bash
agent-audit scan examples/vulnerable-agent/
```

**Results:**

```
🔍 Scanned 3 files

📊 Summary
   Total: 43 findings
   Critical: 21 | High: 14 | Medium: 8

🚨 CRITICAL  AGENT-001: Command Injection via Unsanitized Input
   → tools.py:31 — eval(expression)
   → User input passed directly to eval()

🚨 CRITICAL  AGENT-041: SQL Injection via String Interpolation
   → agent.py:58 — f"SELECT * FROM users WHERE name = '{name}'"
   → Tool parameter interpolated into SQL query

⚠️  HIGH     AGENT-021: Missing Circuit Breaker
   → agent.py:84 — AgentExecutor without max_iterations
   → Agent could loop indefinitely

⚠️  HIGH     AGENT-004: Hardcoded Credentials
   → agent.py:20 — OPENAI_API_KEY = "sk-proj-..."
   → API key should use environment variables
```

Each finding includes:
- **Rule ID** linked to documentation
- **OWASP mapping** (ASI-01 through ASI-10)
- **CWE reference** for compliance teams
- **Exact file location** with code snippet
- **Remediation guidance** with fixed code examples

---

## Integrate in 5 Minutes

### GitHub Actions

```yaml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HeadyZhang/agent-audit@v1
        with:
          fail-on: high
          upload-sarif: true
```

Findings appear directly in your **Security tab** and as PR annotations.

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agent-audit
        name: Agent Security Scan
        entry: agent-audit scan . --fail-on high
        language: system
        pass_filenames: false
```

---

## Why Open Source?

AI agent security is too important to be locked behind enterprise paywalls. The community needs:

- **Visibility** into what risks exist
- **Tools** that integrate with existing workflows
- **Standards** that everyone can build on

Agent Audit is MIT licensed. Use it, fork it, contribute rules, report false positives — let's build this together.

---

## Get Started

```bash
pip install agent-audit
agent-audit scan .
```

**🌟 Star us on GitHub:** [github.com/HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit)

**📖 Read the docs:** [Rule Reference](https://github.com/HeadyZhang/agent-audit/blob/master/docs/RULES.md) | [CI Integration](https://github.com/HeadyZhang/agent-audit/blob/master/docs/CI-INTEGRATION.md)

**🐛 Found a false positive?** [Open an issue](https://github.com/HeadyZhang/agent-audit/issues/new?template=false_positive.yml) — we take accuracy seriously.

---

*Agent Audit is not affiliated with OWASP. OWASP Agentic Top 10 is a trademark of the OWASP Foundation.*

---

**Tags:** #security #ai #llm #python #opensource #langchain #devsecops
