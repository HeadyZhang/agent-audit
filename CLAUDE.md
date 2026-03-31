# Agent Audit (Argus) — Project Context for Claude Code

## Overview

Agent Audit is a security scanner for AI agent code, MCP configurations, and DeFi contracts. It detects agent-specific vulnerabilities that traditional SAST tools miss, mapped to the OWASP Agentic Top 10 (2026) with 10/10 coverage.

- **Version**: 0.18.2
- **Python**: 3.9-3.12
- **License**: MIT
- **Entry point**: `agent-audit = "agent_audit.cli.main:cli"`
- **Metrics**: 94.6% recall, 87.5% precision, F1=0.91, 1239+ tests

## Repository Structure

```
agent-security-suite/
├── packages/audit/                    # Main Python package
│   ├── agent_audit/
│   │   ├── __init__.py
│   │   ├── version.py                # __version__ = "0.18.2"
│   │   ├── analysis/                 # 21 analyzer modules (confidence scoring, taint, context)
│   │   │   ├── semantic_analyzer.py  # 3-stage credential detection (regex → value → context)
│   │   │   ├── taint_tracker.py      # Data flow: source → sanitizer → sink
│   │   │   ├── tool_boundary_detector.py  # @tool entry point gate for AGENT-034
│   │   │   ├── ts_tool_boundary_detector.py
│   │   │   ├── confidence_matrix.py  # Tier computation and adjustment rules
│   │   │   ├── context_classifier.py # File type detection (test/example/infra)
│   │   │   ├── dangerous_operation_analyzer.py
│   │   │   ├── framework_detector.py # Pydantic/LangChain/CrewAI internal suppression
│   │   │   ├── placeholder_detector.py
│   │   │   ├── value_analyzer.py
│   │   │   ├── identifier_analyzer.py
│   │   │   ├── tool_description_analyzer.py
│   │   │   ├── memory_method_detector.py
│   │   │   ├── env_tracer.py
│   │   │   ├── entropy.py
│   │   │   └── rule_context_config.py
│   │   ├── analyzers/
│   │   │   └── memory_context.py
│   │   ├── scanners/                 # 14 scanner modules
│   │   │   ├── base.py              # BaseScanner ABC
│   │   │   ├── python_scanner.py    # 4017 LOC — AST-based Python analysis
│   │   │   ├── typescript_scanner.py # 952 LOC — TS/JS via tree-sitter
│   │   │   ├── go_scanner.py        # 296 LOC — Go patterns
│   │   │   ├── solidity_scanner.py  # 411 LOC — Solidity contracts
│   │   │   ├── secret_scanner.py    # 855 LOC — Regex + semantic secret detection
│   │   │   ├── config_scanner.py    # 390 LOC — YAML/JSON/ENV files
│   │   │   ├── mcp_config_scanner.py # 1369 LOC — MCP config auditing
│   │   │   ├── mcp_baseline.py      # 530 LOC — MCP baseline drift (rug pull)
│   │   │   ├── mcp_inspector.py     # 607 LOC — Live MCP server introspection
│   │   │   ├── privilege_scanner.py # 1138 LOC — OS privilege escalation
│   │   │   ├── skill_body_scanner.py # 402 LOC — OpenClaw skill instructions
│   │   │   ├── skill_meta_scanner.py # 352 LOC — OpenClaw skill metadata
│   │   │   └── __init__.py
│   │   ├── rules/
│   │   │   ├── engine.py            # RULE_CWE_MAPPING (109 rules), PATTERN_TYPE_TO_RULE_MAP (55+ patterns)
│   │   │   ├── loader.py            # YAML rule loader
│   │   │   └── builtin/             # YAML rule definitions (mirrored from monorepo)
│   │   │       ├── owasp_agentic_v2.yaml
│   │   │       ├── owasp_agentic.yaml
│   │   │       ├── asi_coverage_v030.yaml
│   │   │       ├── mcp_security_v030.yaml
│   │   │       └── langchain_security_v030.yaml
│   │   ├── models/
│   │   │   ├── finding.py           # Finding dataclass, confidence_to_tier(), TIER_THRESHOLDS
│   │   │   ├── risk.py              # Severity/Category enums, Location, RiskScore
│   │   │   ├── suppression.py       # Suppression/ignore model
│   │   │   └── tool.py              # ToolDefinition, PermissionType
│   │   ├── cli/
│   │   │   ├── main.py              # @click group
│   │   │   ├── commands/
│   │   │   │   ├── scan.py          # Main scan orchestration
│   │   │   │   ├── inspect.py       # Live MCP inspection
│   │   │   │   └── init.py          # Config init
│   │   │   └── formatters/
│   │   │       ├── terminal.py      # Rich terminal output + calculate_risk_score()
│   │   │       ├── json.py          # JSON output
│   │   │       └── sarif.py         # SARIF v2.1.0 output
│   │   ├── profiles/
│   │   │   └── defi/                # DeFi profile (AGENT-090 to AGENT-109)
│   │   │       ├── rules.py
│   │   │       ├── scanners/        # solidity, js_ts, defi_secret, agent_payment
│   │   │       ├── analysis/        # llm_analyzer, rpc_analyzer, defi_taint
│   │   │       └── constants/       # defi_protocols, web3_apis, rpc_endpoints
│   │   ├── config/
│   │   │   └── ignore.py            # .agent-audit.yaml loader
│   │   ├── utils/
│   │   │   ├── mcp_client.py
│   │   │   └── compat.py
│   │   └── parsers/
│   │       └── treesitter_parser.py
│   ├── tests/                        # 1239+ tests
│   │   ├── test_agent004_semantic.py
│   │   ├── test_expanded_rules.py
│   │   ├── test_privilege_rules.py
│   │   ├── test_defi_profile.py
│   │   ├── test_go_scanner.py
│   │   ├── test_analysis/            # 17 analyzer test modules
│   │   ├── test_cli/                 # 5 CLI test modules
│   │   ├── test_formatters/          # 4 formatter test modules
│   │   ├── test_config/              # 3 config test modules
│   │   ├── fixtures/                 # Test fixture code
│   │   ├── benchmark/                # Layer 2 benchmark (91 projects)
│   │   ├── ground_truth/             # AVB oracle baseline
│   │   └── e2e/                      # End-to-end tests
│   └── pyproject.toml                # Poetry config, version = "0.18.2"
├── rules/builtin/                    # Monorepo YAML rules (sync to packages/audit before publish)
│   ├── owasp_agentic_v2.yaml
│   ├── owasp_agentic.yaml
│   ├── asi_coverage_v030.yaml
│   ├── mcp_security_v030.yaml
│   └── langchain_security_v030.yaml
├── docs/
│   ├── RULES.md                      # Rule documentation
│   └── reports/                      # Published scan reports
├── CHANGELOG.md
├── README.md / README_CN.md
└── CONTRIBUTING.md
```

## Rule System

### Rule ID Ranges

| Range | Category | Count |
|-------|----------|-------|
| AGENT-001 to AGENT-005 | Core injection/privilege/SSRF/credentials/supply chain | 5 |
| AGENT-010 to AGENT-011 | Prompt injection / goal hijack | 2 |
| AGENT-013 to AGENT-020 | Identity, supply chain, RCE, memory, inter-agent | 8 |
| AGENT-021 to AGENT-025 | Cascading failures, trust exploitation | 5 |
| AGENT-026 to AGENT-028 | LangChain-specific (SSRF, XSS, resource) | 3 |
| AGENT-029 to AGENT-033 | MCP configuration security | 5 |
| AGENT-034 to AGENT-042 | Tool misuse, expanded detection | 9 |
| AGENT-043 to AGENT-047 | OS privilege escalation | 5 |
| AGENT-049 to AGENT-053 | Supply chain, logging, rogue agents | 5 |
| AGENT-054 to AGENT-057 | MCP enhanced (drift, shadowing, poisoning) | 4 |
| AGENT-058 to AGENT-064 | OpenClaw skill security | 7 |
| AGENT-083 to AGENT-085 | Solidity/Go specific | 3 |
| AGENT-090 to AGENT-109 | DeFi profile (28 rules) | 20 |
| AGENT-110 to AGENT-119 | Agent architecture security (v0.19.0) | 10 |

### Adding a New Rule (Checklist)

1. **YAML definition**: Create/update `rules/builtin/<category>_v0XX.yaml`
   - Required fields: id, title, description, severity, category, owasp_agentic_id, cwe_id, detection (type + patterns), remediation (description + code_example)
2. **Mirror YAML**: Copy to `packages/audit/agent_audit/rules/builtin/`
3. **engine.py**: Add entry to `RULE_CWE_MAPPING` dict and `PATTERN_TYPE_TO_RULE_MAP` dict
4. **Scanner**: Add detection logic to appropriate scanner (python_scanner.py, typescript_scanner.py, config_scanner.py, etc.) — or create new scanner inheriting from `BaseScanner`
5. **Tests**: Create fixture files in `tests/fixtures/<category>/` and test functions in `tests/test_<category>.py`
6. **Docs**: Update `docs/RULES.md`, `CHANGELOG.md`, `README.md`/`README_CN.md`

### Confidence Tiers

| Tier | Threshold | Meaning |
|------|-----------|---------|
| BLOCK | >= 0.92 | High confidence — fail CI |
| WARN | >= 0.60 | Medium — warn user |
| INFO | >= 0.30 | Low — informational |
| SUPPRESSED | < 0.30 | Very low — hidden by default |

### Risk Score Formula

```
raw = sum(confidence * severity_weight * context_weight) for BLOCK+WARN findings
base_score = 1.8 * ln(1 + raw)
block_bonus = min(2.0, block_count * 0.3)
score = min(9.8, base_score + block_bonus)
```

Severity weights: critical=3.0, high=1.5, medium=0.5, low=0.2, info=0.1

## Scanners

| Scanner | LOC | Method | Detects |
|---------|-----|--------|---------|
| python_scanner.py | 4017 | AST + taint | AGENT-001/010/017/018/026/034/041 + more |
| mcp_config_scanner.py | 1369 | Config parse | AGENT-029-033, AGENT-054-057 |
| privilege_scanner.py | 1138 | Regex + config | AGENT-043-047 |
| typescript_scanner.py | 952 | Tree-sitter | AGENT-010/026/034/041/049 |
| secret_scanner.py | 855 | Regex + semantic | AGENT-004 |
| mcp_inspector.py | 607 | Live introspection | MCP server audit |
| mcp_baseline.py | 530 | Drift detection | AGENT-054/055 |
| solidity_scanner.py | 411 | Regex | AGENT-083/084 |
| skill_body_scanner.py | 402 | Regex | AGENT-058/059/061/062 |
| config_scanner.py | 390 | Config parse | YAML/JSON/ENV patterns |
| skill_meta_scanner.py | 352 | YAML parse | AGENT-063/064 |
| go_scanner.py | 296 | Regex | AGENT-034/041/085 |

## Build & Test Commands

```bash
cd packages/audit
poetry install                          # Install dependencies
poetry run pytest tests/ -x -q          # Run tests (stop on first failure)
poetry run pytest tests/ -v --tb=short  # Verbose with short traceback
poetry run agent-audit scan <path>      # Run scanner
poetry run python ../../tests/benchmark/run_benchmark.py  # Layer 2 benchmark
```

## Critical Implementation Notes

1. **THREE pattern types map to AGENT-034**: `tool_no_input_validation`, `eval_exec_expanded`, `subprocess_expanded` — all must be handled when modifying AGENT-034 behavior
2. **Tool boundary gate**: `is_tool_entry_point()` in `tool_boundary_detector.py` — AGENT-034 only fires within @tool functions
3. **YAML rule sync**: Rules in `rules/builtin/` must be copied to `packages/audit/agent_audit/rules/builtin/` before publishing to PyPI
4. **Version tracked in 3 files**: `pyproject.toml`, `version.py`, `__init__.py`
5. **Framework path suppression** must apply to ALL code paths producing a rule, not just one
6. **AVB oracle** uses FILE + LINE matching (5-line tolerance), no rule_id check
