# Agent Audit Roadmap

> **Status:** Living document — updated as priorities evolve
> **Last updated:** 2026-02

---

## Current (v0.15)

Core capabilities shipped and stable:

- [x] **Python AST Scanner** — Deep static analysis with pattern matching and data flow
- [x] **Framework Support** — LangChain, CrewAI, AutoGen (deep); other frameworks (generic patterns)
- [x] **MCP Config Scanner** — Filesystem permissions, server sources, env exposure, transport security
- [x] **Credential Detection** — 3-stage semantic analysis (regex + value analysis + context adjustment)
- [x] **Privilege Scanner** — Escalation patterns, unsandboxed execution, credential store access
- [x] **Taint Analysis** — Intra-procedural data flow tracking (Source → Sink)
- [x] **OWASP Coverage** — 10/10 ASI categories, 40+ detection rules
- [x] **Output Formats** — SARIF, JSON, Markdown, Terminal
- [x] **CI/CD Integration** — GitHub Action, GitLab CI, Jenkins, Azure DevOps
- [x] **Baseline Scanning** — Incremental mode, suppression management
- [x] **MCP Runtime Inspect** — Live tool enumeration ("Agent Nmap")

---

## Next (Q1-Q2 2026)

High-value improvements, 1-3 months horizon:

### Analysis Depth

- [ ] **Inter-procedural Taint Analysis** — Track data flow across function calls within the same module
- [ ] **Cross-file Analysis** — Follow imports to detect vulnerabilities spanning multiple files
- [ ] **Call Graph Construction** — Build project-wide call graphs for deeper analysis

### Framework & Language Support

- [ ] **OpenAI Assistants/Agents SDK** — Detection rules for OpenAI's agent patterns
- [ ] **Anthropic Claude SDK** — Tool use, prompt caching, batch API patterns
- [ ] **Semantic Kernel** — Microsoft's AI orchestration framework
- [ ] **DSPy** — Stanford's declarative language model programming

### Developer Experience

- [ ] **Pre-commit Hook** — `agent-audit` as a pre-commit hook for instant feedback
- [ ] **Watch Mode** — Continuous scanning during development (`--watch`)
- [ ] **Inline Suppression** — `# agent-audit: ignore[AGENT-XXX]` comments
- [ ] **Auto-fix (Safe Rules)** — Automatic remediation for select low-risk issues

### Integration

- [ ] **VS Code Extension** — Real-time diagnostics in editor
- [ ] **GitHub App** — PR comments with findings, check status integration
- [ ] **Slack/Discord Notifications** — Alert channels on new findings

---

## Future (2026+)

Medium-term vision:

### Multi-Language Support

- [ ] **TypeScript/JavaScript Scanner** — MCP servers, Node.js agents, LangChain.js
- [ ] **Go Scanner** — Go-based agent frameworks
- [ ] **Rust Scanner** — Emerging Rust agent ecosystem

### Advanced Analysis

- [ ] **Symbolic Execution (Lightweight)** — Reason about conditional branches
- [ ] **LLM-Assisted Triage** — Use LLM to classify ambiguous findings
- [ ] **Custom Rule SDK** — Python API for writing detection rules
- [ ] **YAML Rule DSL** — Declarative custom rules without Python code

### Enterprise Features

- [ ] **Dashboard / Web UI** — Centralized findings management
- [ ] **Trend Analysis** — Security posture over time
- [ ] **Compliance Reports** — SOC 2, ISO 27001 mapping
- [ ] **Team Annotations** — Collaborative review workflow

### Ecosystem

- [ ] **Remediation Suggestions** — Actionable fix recommendations with code snippets
- [ ] **Benchmark Suite** — Public agent vulnerability benchmark (AgentVulnBench)
- [ ] **Rule Marketplace** — Community-contributed detection rules

---

## Community Wishlist

We welcome contributions in these areas:

- [ ] **New Framework Detectors** — Haystack, LlamaIndex, Instructor, Marvin, etc.
- [ ] **Additional Credential Patterns** — Cloud provider keys, SaaS tokens
- [ ] **Localization** — CLI output in other languages
- [ ] **Documentation** — Tutorials, best practices guides
- [ ] **Test Fixtures** — Real-world vulnerable agent examples
- [ ] **Performance Optimization** — Faster scanning for large codebases

---

## How to Contribute

1. Check [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines
2. Browse [issues labeled `good first issue`](https://github.com/HeadyZhang/agent-audit/labels/good%20first%20issue)
3. Discuss major features in GitHub Discussions before implementing
4. All contributions require signed CLA

---

## Feedback

Have a feature request or priority suggestion?

- Open an issue with the `enhancement` label
- Join the discussion in GitHub Discussions
- Security issues: see [SECURITY.md](../SECURITY.md)
