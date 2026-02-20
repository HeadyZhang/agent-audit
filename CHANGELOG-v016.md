# Changelog v0.16.0

## Changes

### Bug Fixes — AGENT-034 False Positive Reduction

- **Qualified name matching for expanded detection** (Critical fix)
  - `_check_expanded_eval_exec`: Only allow simple_name match for unambiguous builtins (`eval`, `exec`, `__import__`). `re.compile()`, `ast.compile()` no longer falsely trigger
  - `_check_expanded_subprocess`: Require module-qualified names (`subprocess.run`, `os.system`). `asyncio.run()`, `llm.call()`, `platform.system()`, `app.run()` no longer falsely trigger
  - Impact: 79% AGENT-034 FP reduction across benchmark targets (140 → 29)

- **Framework internal path suppression** for `_check_tool_no_input_validation`
  - Files in `crewai/`, `langchain_core/`, `autogen/`, `agentscope/`, `openai_agents/`, `site-packages/` suppress AGENT-034
  - Impact: 0 `tool_no_input_validation` FPs from framework code

- **Extended SAFE_TOOL_PATTERNS** in `dangerous_operation_analyzer.py`
  - Added 31 safe function name patterns: `retrieve_*`, `view_*`, `inspect_*`, `is_*`, `has_*`, `can_*`, `verify_*`, `extract_*`, `analyze_*`, etc.
  - Impact: Additional FP reduction for read-only tool functions

- **Boundary confidence multiplier**
  - Finding confidence = `taint_result.confidence * boundary.confidence` (was `taint_result.confidence` only)
  - Impact: More accurate confidence scoring for tool boundary findings

### Infrastructure

- **Semgrep adapter fix**: Updated `SemgrepAdapter.scan()` to enumerate files explicitly for directory targets, bypassing Semgrep's git-tracking limitation
- **3-tool AVB evaluation**: Full Bandit/Semgrep comparison report generated via existing harness

### Performance Metrics

| Metric | v0.4.1 | v0.15.1 | v0.16.0 |
|--------|--------|---------|---------|
| AVB Recall | 58.3% | 94.6% | **94.6%** |
| AVB Precision | 80.8% | 87.5% | **87.5%** |
| AVB F1 | 0.700 | 0.909 | **0.909** |
| Set A Recall | 56.2% | 100% | **100%** |
| Set B Recall | 62.5% | 100% | **100%** |
| Set C Recall | 58.3% | 84.6% | **84.6%** |
| T6 findings | — | 39 | **25** (-36%) |
| T7 findings | — | 55 | **39** (-29%) |
| T8 findings | — | 20 | **10** (-50%) |
| T9 findings | — | 226 | **155** (-31%) |
| OWASP coverage | 10/10 | 10/10 | **10/10** |
| Unit tests | — | 1142 | **1142** (0 regressions) |

### Files Modified

- `packages/audit/agent_audit/scanners/python_scanner.py` — Framework path suppression, qualified name matching, boundary confidence
- `packages/audit/agent_audit/analysis/dangerous_operation_analyzer.py` — Extended safe patterns
- `tests/benchmark/agent-vuln-bench/harness/adapters/semgrep_adapter.py` — Directory scanning fix
