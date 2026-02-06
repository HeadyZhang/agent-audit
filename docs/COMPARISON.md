# How agent-audit Compares

> **TL;DR:** agent-audit doesn't replace your existing SAST tools — it complements them with AI agent-specific detection that general-purpose scanners miss.

---

## The Gap

Traditional security scanners are designed for conventional applications. They excel at finding SQL injection, XSS, and hardcoded secrets. But they don't understand:

- `@tool` decorators and what makes a tool dangerous
- `AgentExecutor` missing iteration limits (infinite loop risk)
- MCP server configurations with overly broad filesystem access
- Prompt injection via `SystemMessage(content=f"{user_input}")`
- Memory poisoning through unvalidated `add_documents()` calls
- Trust boundaries between agents in multi-agent systems

**agent-audit fills this gap.**

---

## Comparison Table

| Capability | agent-audit | Semgrep | Bandit | Snyk Code | Trivy |
|------------|-------------|---------|--------|-----------|-------|
| **AI Agent Rules** | ✅ 40+ rules | ❌ | ❌ | ❌ | ❌ |
| **OWASP Agentic Top 10** | ✅ 10/10 | ❌ | ❌ | ❌ | ❌ |
| **MCP Config Audit** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Tool Decorator Analysis** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Prompt Injection Detection** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Framework-Aware** | ✅ LangChain, CrewAI, AutoGen | Generic | Generic | Generic | N/A |
| **Taint Analysis** | ✅ Intra-proc | ✅ Cross-file | ❌ | ✅ | N/A |
| **General SAST** | ⚠️ Limited | ✅ | ✅ | ✅ | ❌ |
| **Dependency Scanning** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Container Scanning** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **License Compliance** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Secrets Detection** | ✅ Semantic | ✅ | ⚠️ Basic | ✅ | ✅ |
| **SARIF Output** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **GitHub Action** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **License** | MIT | LGPL | Apache 2.0 | Proprietary | Apache 2.0 |
| **Pricing** | Free | Free (OSS rules) | Free | Freemium | Free |

---

## When to Use agent-audit

### 1. Building LLM-Powered Agents

You're using LangChain, CrewAI, AutoGen, or similar frameworks to build autonomous agents.

```bash
# Catches: missing max_iterations, unbounded tool access, prompt injection
agent-audit scan ./my-agent-project
```

### 2. Exposing Tools via MCP

You're configuring MCP servers in Claude Desktop or building MCP tool servers.

```bash
# Catches: overly broad filesystem, unverified sources, env leakage
agent-audit scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### 3. Deploying RAG Applications

You're building retrieval-augmented generation with vector stores.

```bash
# Catches: memory poisoning, unvalidated document ingestion
agent-audit scan ./rag-pipeline/
```

### 4. Pre-Production Security Review

Adding agent-audit to CI/CD before deploying agent-based features.

```yaml
# .github/workflows/security.yml
- uses: HeadyZhang/agent-audit@v1
  with:
    path: ./src/agents
    fail-on: high
```

---

## When NOT to Use agent-audit

### Use Semgrep or Bandit Instead For:

- **General Python security** — XSS, CSRF, path traversal in web apps
- **Custom rule authoring** — Semgrep's rule syntax is more mature
- **Cross-file taint analysis** — Semgrep Pro tracks data flow across modules
- **Multi-language monorepos** — Semgrep supports 30+ languages

### Use Snyk or Trivy Instead For:

- **Dependency vulnerabilities** — CVE scanning in requirements.txt, package.json
- **Container image scanning** — Base image CVEs, misconfigurations
- **License compliance** — OSS license risk assessment
- **Infrastructure as Code** — Terraform, CloudFormation misconfigurations

### Use Dedicated Tools For:

- **Dynamic testing** — DAST tools like OWASP ZAP, Burp Suite
- **Penetration testing** — Manual red team assessments
- **Runtime protection** — WAF, RASP solutions

---

## Recommended Security Stack

For comprehensive coverage of AI agent applications:

```
┌─────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  agent-audit    │  │    Semgrep      │                   │
│  │  AI Agent SAST  │  │  General SAST   │   Code Analysis   │
│  └─────────────────┘  └─────────────────┘                   │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │     Trivy       │  │   Gitleaks /    │                   │
│  │  Container/Deps │  │   TruffleHog    │   Supply Chain    │
│  └─────────────────┘  └─────────────────┘                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Example GitHub Actions Workflow

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      # AI Agent-specific vulnerabilities
      - uses: HeadyZhang/agent-audit@v1
        with:
          fail-on: high

      # General Python security
      - uses: returntocorp/semgrep-action@v1
        with:
          config: p/python

      # Dependency vulnerabilities
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scanners: vuln
```

---

## Summary

| Tool | Primary Focus | Use Together With agent-audit? |
|------|---------------|-------------------------------|
| **Semgrep** | General SAST, custom rules | ✅ Yes — covers non-agent code |
| **Bandit** | Python security basics | ✅ Yes — lightweight baseline |
| **Snyk** | Dependencies, containers, IaC | ✅ Yes — supply chain coverage |
| **Trivy** | Container/dependency scanning | ✅ Yes — runtime environment |
| **Gitleaks** | Secrets in git history | ✅ Yes — historical exposure |

**agent-audit + general SAST + dependency scanner = comprehensive AI agent security.**
