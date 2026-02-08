# Agent Audit Documentation

> **Version:** v0.15.1
> **CLI static analysis tool for AI agent security — "ESLint for AI agents"**

---

## For Users

| Document | Description |
|----------|-------------|
| [Rule Reference](RULES.md) | Complete list of 40+ detection rules with OWASP mapping |
| [CI/CD Integration](CI-INTEGRATION.md) | GitHub Actions, GitLab CI, Jenkins, Azure DevOps setup |
| [API Stability](STABILITY.md) | Public interface stability guarantees |

### Quick Start

```bash
# Install
pip install agent-audit

# Scan your project
agent-audit scan ./my-agent-project

# Output SARIF for GitHub Code Scanning
agent-audit scan . --format sarif --output results.sarif
```

---

## For Contributors

| Document | Description |
|----------|-------------|
| [Architecture](ARCHITECTURE.md) | System design, module dependencies, extension points |
| [Contributing](../CONTRIBUTING.md) | How to contribute rules, scanners, and fixes |

### Development Setup

```bash
cd packages/audit
poetry install
poetry run pytest ../../tests/ -v
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLI Layer                                │
│    scan.py  │  inspect_cmd.py  │  formatters/*.py                │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────┐
│                        Scanner Layer                              │
│  ┌────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │ PythonScanner  │  │ MCPConfigScanner│  │  SecretScanner  │    │
│  │   (AST-based)  │  │  (JSON/YAML)    │  │ (regex+semantic)│    │
│  └────────────────┘  └─────────────────┘  └─────────────────┘    │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────┐
│                       Analysis Layer                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐  │
│  │SemanticAnalyzer │  │  TaintTracker   │  │FrameworkDetector │  │
│  │ (3-stage cred)  │  │  (data flow)    │  │  (FP reduction)  │  │
│  └─────────────────┘  └─────────────────┘  └──────────────────┘  │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────┐
│                        Rules Engine                               │
│              engine.py  +  rules/builtin/*.yaml                   │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────┐
│                         Data Models                               │
│            Finding  │  Severity  │  Location  │  Category         │
└──────────────────────────────────────────────────────────────────┘
```

---

## Scanners

### PythonScanner
**Input:** `.py` files
**Method:** Python AST parsing
**Detects:**
- Dangerous function calls (`eval`, `exec`, `subprocess.run(shell=True)`)
- `@tool` decorated functions and their permissions
- SQL injection via string interpolation
- Framework-specific patterns (LangChain, CrewAI, AutoGen)

### SecretScanner
**Input:** All text files
**Method:** Regex patterns + Semantic analysis + Entropy calculation
**Detects:**
- Hardcoded API keys (AWS, OpenAI, Anthropic, etc.)
- Database connection strings
- Private keys and tokens

### MCPConfigScanner
**Input:** `claude_desktop_config.json`, MCP YAML configs
**Method:** JSON/YAML parsing + Policy validation
**Detects:**
- Overly broad filesystem access
- Unverified MCP server sources
- Sensitive environment variable exposure
- Missing authentication

### PrivilegeScanner
**Input:** Python files
**Method:** AST pattern matching
**Detects:**
- Privilege escalation patterns
- Unsandboxed subprocess execution
- Credential store access

---

## Taint Analysis

The `TaintTracker` module performs intra-procedural data flow analysis:

### Components

1. **TaintSource** — Entry points (function parameters, `os.getenv()`, `request.json()`)
2. **TaintSink** — Dangerous operations (`subprocess.run`, `eval`, `cursor.execute`)
3. **TaintFlow** — Tracks data propagation through assignments and operations
4. **Sanitization Detection** — Identifies validation/sanitization nodes

### Strategy

- **Conservative:** If uncertain, assume tainted (minimize false negatives)
- **Intra-procedural:** Analysis within single functions (no cross-function tracking yet)
- **Contextual:** Adjusts confidence based on decorator context (`@tool` = higher confidence)

---

## Confidence Scoring

All findings include a confidence score (0.0-1.0) and are assigned to tiers:

| Tier | Confidence | Action |
|------|------------|--------|
| **BLOCK** | >= 0.90 | Fix immediately — very high confidence |
| **WARN** | >= 0.60 | Should fix — high confidence |
| **INFO** | >= 0.30 | Review recommended |
| **SUPPRESSED** | < 0.30 | Likely false positive — auto-suppressed |

### Confidence Factors

- **Context:** Tool decorator (+), class method (neutral), standalone function (-)
- **Value analysis:** High entropy (+), placeholder patterns (-)
- **Framework detection:** Pydantic Field definitions (-), LangChain internals (-)
- **File path:** Test files (-), example code (-)

---

## Limitations

1. **Intra-procedural only** — Taint analysis does not track data flow across functions or files
2. **Python only** — TypeScript/JavaScript MCP servers require separate tooling
3. **Static analysis** — Cannot detect runtime-only vulnerabilities
4. **Pattern-based** — Novel attack patterns may not be detected until rules are added
5. **No symbolic execution** — Cannot reason about complex conditional logic

---

## Technical Specifications

For detailed technical specifications (internal use):

- [Security Analysis Specification](SECURITY-ANALYSIS-SPECIFICATION.md) — Detection methodology and threat mapping
- [specs/technical-spec.md](../specs/technical-spec.md) — Full system architecture and implementation details
- [specs/delta-spec.md](../specs/delta-spec.md) — Design decisions and refinements

---

## OWASP Agentic Top 10 Coverage

Agent Audit covers all 10 categories of the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/):

| ASI | Category | Rules |
|-----|----------|-------|
| ASI-01 | Agent Goal Hijacking | AGENT-010, 011, 027, 050 |
| ASI-02 | Tool Misuse | AGENT-001, 026, 029, 032, 034-036, 040, 041 |
| ASI-03 | Privilege Abuse | AGENT-002, 013, 014, 042 |
| ASI-04 | Supply Chain | AGENT-004, 005, 015, 016, 030 |
| ASI-05 | Code Execution | AGENT-003, 017, 031 |
| ASI-06 | Memory Poisoning | AGENT-018, 019 |
| ASI-07 | Inter-Agent Comms | AGENT-020 |
| ASI-08 | Cascading Failures | AGENT-021, 022, 028 |
| ASI-09 | Trust Exploitation | AGENT-023, 033, 037-039, 052 |
| ASI-10 | Rogue Agents | AGENT-024, 025, 053 |

**Coverage: 10/10 ASI categories, 40+ rules**
