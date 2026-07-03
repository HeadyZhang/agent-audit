# Agent Audit — Public Audit Examples

Real-world security audit examples produced by [agent-audit](https://github.com/HeadyZhang/agent-audit). Each folder contains complete, unredacted audit artifacts from scanning real open-source agent projects.

## Examples

### 01 — MiroFish Agent Audit
Full security scan of a MiroFish agent project.
- `mirofish_scan.json` — Raw SARIF-style scan output (30 findings: 14 critical, 14 high, 2 low)
- `mirofish_audit_report.pdf` — Branded PDF audit report with remediation guidance

### 02 — CrewAI Audit Report
- `crewai-report.pdf` — Complete PDF audit report for a CrewAI-based project

### 03 — ClawSkills Deep Scan
In-depth security analysis of OpenClaw Skills with false-positive triage.
- `clawskills_security_report.md` — Full analysis: 680 raw findings → 65 actionable (90.4% auto-triaged)
- `clawskills_owasp_report.md` — OWASP ASI compliance mapping
- `clawskills_report.sarif` — SARIF output for CI/CD integration

### 04 — SQL Injection PoC (AWS postgres-mcp-server)
Proof-of-concept vulnerability discovered by agent-audit in AWS Labs' postgres-mcp-server.
- `poc_report.md` — Full vulnerability report (HackerOne #3665191, CVSS 6.5)
- `exploit_demo.py` — Demonstration exploit script

### 05 — Sample Branded Report
Template-generated professional audit report for "MedAgent Pro" (fictional).
- `sample_report.pdf` — Branded PDF report with executive summary, OWASP matrix, remediation roadmap
- `sample_data.json` — Input data schema used to generate the report

### 06 — Vulnerable Agent Demo
Intentionally vulnerable agent code for testing and demonstration.
- `agent.py` — Sample agent with security issues
- `mcp_config.json` — Misconfigured MCP server setup

## Quick Start

Scan any agent project yourself:

```bash
pip install agent-audit
agent-audit scan <path-to-project>
```

## OWASP ASI Coverage

All examples demonstrate detection across the OWASP Agentic Security Initiative Top 10:

| ASI # | Category | Detected in Examples |
|-------|----------|---------------------|
| ASI-01 | Prompt Injection | 01, 03 |
| ASI-02 | Broken Access Control | 03, 06 |
| ASI-03 | Supply Chain Vulnerabilities | 01, 03 |
| ASI-04 | Improper Output Handling | 01, 03 |
| ASI-05 | Broken Tool/Agent Auth | 01, 06 |
| ASI-06 | Excessive Agency | 03 |
| ASI-07 | Logging & Monitoring Gaps | 01, 03 |
| ASI-08 | Resource Management | 03 |
| ASI-09 | Insecure Communication | 06 |
| ASI-10 | Kill Switch Absence | 03 |
