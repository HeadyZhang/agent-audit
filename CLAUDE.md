# Agent Audit

## Identity

CLI static analysis tool for AI agent security — "ESLint for AI agents".
Detects vulnerabilities mapped to the OWASP Agentic Top 10 (2026).
Source in `packages/audit/`. Tests at project root `tests/`. Rules in `rules/builtin/`.

## Current Status (v0.4.0)

✅ **Full OWASP Agentic Top 10 coverage achieved (10/10 ASI categories)**

- v0.1.0: 5 original rules (AGENT-001~005)
- v0.2.0: 8/10 ASI coverage
- v0.3.0: 10/10 ASI coverage with reduced false positives
- v0.4.0: Standardized benchmark infrastructure + AGENT-041 precision improvements

## Architecture Constraints (Do Not Violate)

- **AST only** → Use Python `ast` module for all code analysis. NEVER introduce Semgrep (40MB, license risk).
- **Single package** → All source in `packages/audit/agent_audit/`. No separate `packages/core/`.
- **Cross-platform** → `pathlib` everywhere. No hardcoded `/` separators. No Unix-only APIs.
- **Python 3.9+** → Use `from __future__ import annotations` or `Optional[X]` syntax, not `X | None`.
- **Zero heavy deps** → Core scanning depends only on stdlib (`ast`, `json`, `re`, `pathlib`) + `click` + `rich` + `pyyaml`.
- **YAML rules are declarative** → Detection logic lives in Python scanners, not in YAML. YAML defines metadata + pattern hints; scanners implement the actual detection.

## Code Standards

- Type hints on all functions. `Sequence[ScanResult]` for scanner base return type (not `List` — invariance issue).
- Google-style docstrings on public methods.
- `logging` module only, never `print`.
- `dataclass` for models. No Pydantic in core (optional for config validation).
- Black line-length=100. Ruff for linting. mypy must pass.
- Every new rule needs: YAML definition + scanner detection logic + test fixture + test case.

## Rule ID Scheme

| Range | Category | ASI Mapping | Status |
|-------|----------|-------------|--------|
| AGENT-001~005 | v0.1.0 original rules | Various | ✅ Stable |
| AGENT-010~011 | Goal Hijack | ASI-01 | ✅ Stable |
| AGENT-013~014 | Identity/Privilege | ASI-03 | ✅ Stable |
| AGENT-015~016 | Supply Chain | ASI-04 | ✅ Stable |
| AGENT-017 | Code Execution | ASI-05 | ✅ Stable |
| AGENT-018~019 | Memory Poisoning | ASI-06 | ✅ Enhanced (FP suppression) |
| AGENT-020 | Inter-Agent Comm | ASI-07 | ✅ Stable |
| AGENT-021~022 | Cascading Failures | ASI-08 | ✅ Stable |
| AGENT-023 | Trust Exploitation | ASI-09 | ✅ Stable |
| AGENT-024~025 | Rogue Agents | ASI-10 | ✅ Stable |
| **AGENT-025~028** | **LangChain Security** | **ASI-01/02/08** | ✅ v0.3.0 |
| **AGENT-029~033** | **MCP Config Security** | **ASI-02/04/05/09** | ✅ v0.3.0 |
| **AGENT-034~039** | **Tool Misuse / Trust** | **ASI-02/09** | ✅ v0.3.0 |

Rule YAML files:
- `rules/builtin/owasp_agentic_v2.yaml` — Core OWASP rules
- `rules/builtin/langchain_security_v030.yaml` — LangChain framework detection
- `rules/builtin/mcp_security_v030.yaml` — MCP configuration security
- `rules/builtin/asi_coverage_v030.yaml` — Tool misuse and trust rules

## Known Pitfalls (Hard-Won — Read Before Coding)

### Type System (mypy)

- Scanner base return type → `Sequence[ScanResult]` not `List[ScanResult]` → List is invariant, subclasses break.
- Loop variables → Use DIFFERENT names per loop (`for py_result in ...` / `for mcp_result in ...`) → Same name across loops causes mypy type conflict.
- Dict with List value → Extract to typed variable first, then append → `result["items"].append(x)` fails mypy because inferred as `object`.
- Class-level dicts → Must have explicit annotation `PATTERNS: Dict[str, Dict[str, Any]] = {...}` → Otherwise mypy infers `object`.

### CI/CD

- Tests live at project root → `poetry run pytest ../../tests/` from `packages/audit/`, or `pytest tests/` from root.
- Never use `continue-on-error: true` in CI → Masks real failures as green.
- mypy needs `types-PyYAML` installed → Add to CI lint job deps.
- Pin Poetry to `1.8.5` → Poetry 2.x drops Python 3.9 support.

### AST Scanner Patterns

- `_get_call_name()` can return None → Always guard: `if func_name:` before using.
- f-string detection → `ast.JoinedStr` node type. Check both positional args and keyword args.
- `@tool` decorator can be `@tool`, `@tool()`, or `@langchain.tools.tool` → Match with `any(t in dec_name for t in TOOL_DECORATORS)`.
- Fixture `.py` files are parsed by AST → Do NOT add real `import langchain` at top (CI has no langchain). Use function-local or string-based patterns.
- **Fully qualified names** → `func_name.split('.')[-1]` to extract simple name for set membership checks. E.g., `langchain.agents.AgentExecutor` → `AgentExecutor`.
- **Validation detection** → Check for `ast.Raise`, `isinstance`, `re.match`, `startswith`, `endswith`, `in`, `NotIn` comparisons.
- **Callback handlers** → Can be `ast.Call` nodes (instantiated) or `ast.Name` nodes (class reference). Check both.

### Config Scanner

- MCP config `args` field → Can be `str` or `list` → Normalize: `args if isinstance(args, list) else shlex.split(args)`.
- `mcpServers` key (Claude Desktop) vs `servers` key (Docker MCP Gateway) → Check both.

### YAML Rule Loading

- `owasp_agentic_id` field may be None → All downstream code must guard with `if rule.owasp_agentic_id:`.
- Support both single-rule dict and multi-rule list formats in YAML.
- Custom rules via `--rules-dir` merge with (not replace) built-in rules.

### SARIF Output

- SARIF `ruleId` must exactly match `Finding.rule_id` → No prefix/suffix transformation.
- Add `properties.tags` array with `OWASP-Agentic-{ASI-XX}` for each rule that has an owasp_agentic_id.

### v0.3.0 Memory Context Analyzer

- Framework allowlist at `rules/allowlists/framework_memory.yaml` → Loaded by `MemoryContextAnalyzer`.
- Three-level filtering: (1) allowlist check, (2) context analysis, (3) confidence threshold.
- Standard framework patterns (LangChain `ConversationBufferMemory`, etc.) → Suppressed automatically.
- `needs_review: True` flag added when confidence is marginal (0.3-0.7).
- JSON output includes `confidence`, `needs_review`, and optional `context` fields.

### v0.3.0 LangChain Detection

- `AgentExecutor` is the ONLY class checked for `max_iterations` → NOT `create_react_agent`.
- Import resolution: `from langchain.agents import AgentExecutor` → resolved to `langchain.agents.AgentExecutor`.
- Always extract simple name: `func_name.split('.')[-1]` before comparing to set of known classes.

### README / Release

- Python version badge → Use static shields.io badge, not dynamic PyPI lookup (often fails).
- `@v1` tag in GitHub Action usage example → Must exist as a git tag pointing to latest release.

## Project Layout

```
agent-security-suite/
├── packages/audit/
│   └── agent_audit/
│       ├── cli/commands/       # scan.py, inspect_cmd.py, init.py
│       ├── cli/formatters/     # terminal.py, json.py, sarif.py, markdown.py
│       ├── scanners/           # python_scanner.py, mcp_scanner.py, config_scanner.py, secret_scanner.py
│       ├── analyzers/          # memory_context.py (v0.3.0 context analysis)
│       ├── rules/              # engine.py, loader.py
│       ├── models/             # finding.py (Category enum, Finding dataclass, OperationContext), tool.py
│       └── config/             # ignore.py (IgnoreManager)
├── rules/
│   ├── builtin/               # YAML rule definitions
│   └── allowlists/            # Framework whitelists (v0.3.0)
│       └── framework_memory.yaml
├── tests/                     # pytest suite (run from root!)
│   ├── fixtures/vulnerable_agents/
│   ├── fixtures/mcp_configs/
│   └── benchmark/             # v0.3.0 benchmark test files
└── .github/workflows/ci.yml
```

## Verification Commands

```bash
# From project root:
cd packages/audit && poetry install

# Unit tests (MUST pass before any commit)
poetry run pytest ../../tests/ -v --cov=agent_audit --cov-report=term-missing

# Type checking
poetry run mypy agent_audit/

# Linting
poetry run ruff check .

# Smoke test — scan vulnerable fixtures
poetry run agent-audit scan ../../tests/fixtures/vulnerable_agents/

# SARIF output test
poetry run agent-audit scan ../../tests/fixtures/vulnerable_agents/ --format sarif -o /tmp/test.sarif

# v0.3.0 benchmark tests
poetry run agent-audit scan ../../tests/benchmark/t1_langchain_agent.py  # Should find CRITICAL
poetry run agent-audit scan ../../tests/benchmark/t3_langchain_memory.py # Should find 0 (FP suppression)
poetry run agent-audit scan ../../tests/benchmark/t10_mcp_config.json    # Should find MCP issues

# OWASP 10/10 coverage validation
poetry run pytest ../../tests/test_scanners/test_langchain_rules_v030.py -v
poetry run pytest ../../tests/test_scanners/test_memory_poisoning_v030.py -v
poetry run pytest ../../tests/test_scanners/test_asi_coverage_v030.py -v
```

## Commit Convention

```
feat: description     # New rules, new detection logic
fix: description      # Bug fixes
test: description     # Test additions
docs: description     # README, CHANGELOG
refactor: description # Internal restructure, no behavior change
```

Branch: `feat/owasp-full-coverage` → PR to `master` when all 10 ASI categories pass tests.

## v0.3.0 Changelog Summary

### New Features
- **Full OWASP Agentic Top 10 Coverage** (10/10 ASI categories)
- **LangChain Framework Detection** (AGENT-025~028): AgentExecutor risk, tool input sanitization, prompt injection, iteration limits
- **MCP Config Security** (AGENT-029~033): Overly broad filesystem, unverified servers, sensitive env exposure, insecure transport
- **Tool Misuse & Trust Rules** (AGENT-034~039): Input validation, unrestricted execution, missing human approval, impersonation

### Improvements
- **Memory Poisoning FP Suppression**: Framework allowlist + context analysis reduces AGENT-018 false positives by 60%+
- **Confidence Scoring**: All findings include `confidence` field (0.0-1.0)
- **Enhanced JSON Output**: Includes `needs_review` and `context` fields for marginal findings

### Tests
- 381 tests passing (up from ~350 in v0.2.0)
- New test suites: `test_langchain_rules_v030.py`, `test_memory_poisoning_v030.py`, `test_asi_coverage_v030.py`
- Benchmark test files in `tests/benchmark/`
