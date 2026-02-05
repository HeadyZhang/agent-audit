# v0.5.0 Validation Report

**Date**: 2026-02-04
**Validator**: Claude Opus 4.5 (Automated C5 Validation)

## Test Suite Results

| Metric | Value |
|--------|-------|
| Tests Passed | 656 |
| Tests Skipped | 1 (Windows-specific) |
| Tests Failed | 0 |
| Pass Rate | 100% |

All 656 tests passed successfully. The single skipped test (`test_windows_sets_selector_policy`) is Windows-specific and expected to skip on macOS/Linux.

## Benchmark Sample Verification

| Sample ID | Description | Expected Rule | Detected | Confidence | Status |
|-----------|-------------|---------------|----------|------------|--------|
| KNOWN-001 | eval outside @tool (LLMMathChain pattern) | AGENT-034 | Yes | 0.85 | PASS |
| KNOWN-002 | exec in PythonREPLTool | AGENT-034 | Yes | 0.95 | PASS |
| KNOWN-003 | MCP config overly broad filesystem | AGENT-029 | Yes | 1.00 | PASS |
| KNOWN-004 | Hardcoded Anthropic API key | AGENT-004 | Yes | 1.00 | PASS |
| WILD-001 | Calculator class with eval | AGENT-034 | Yes | 0.70 | PASS |
| WILD-002 | Web fetcher SSRF | AGENT-026 | Yes | 0.65 | PASS |

**All 6 benchmark samples detected with appropriate confidence levels.**

### Detection Details

- **KNOWN-001/002**: Expanded AGENT-034 correctly detects eval/exec in non-@tool contexts
- **KNOWN-003**: MCP config scanner correctly routes `.json` files and detects overly broad `/` path
- **KNOWN-004**: Semantic analyzer recognizes `sk-ant-api03-*` pattern with high confidence
- **WILD-001/002**: Context-aware detection assigns appropriate confidence based on class method context

## New Rules Verification (AGENT-043~048)

| Rule ID | Description | File Type | Status |
|---------|-------------|-----------|--------|
| AGENT-043 | Daemon privilege escalation | py/js/sh | VERIFIED |
| AGENT-044 | Sudoers NOPASSWD config | sh/md | VERIFIED |
| AGENT-045 | Browser automation without sandbox | py/js/ts | VERIFIED |
| AGENT-046 | System credential store access | py/js/sh | VERIFIED |
| AGENT-047 | Subprocess execution without sandbox | py/js | VERIFIED |
| AGENT-048 | Extension/plugin permission boundaries | py/js/ts | VERIFIED |

All 6 new privilege detection rules are implemented in `/packages/audit/agent_audit/scanners/privilege_scanner.py` with comprehensive test coverage in `/tests/test_privilege_rules.py`.

## Performance

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Fixtures scan time | <60s | 0.61s | PASS |
| Memory usage | <200MB | <50MB | PASS |
| Throughput | >10 files/s | ~350 files/s | PASS |

Performance significantly exceeds targets.

## Component Verification

### C1: JSON Scan Entry + tree-sitter preparation
- JSON files correctly routed to MCP config scanner
- No tree-sitter dependency introduced (AST-only maintained)

### C2a: AGENT-004 Semantic Refactor
- High entropy detection working
- Placeholder detection working
- Context-based confidence adjustment working
- Known format recognition (sk-ant-*, sk-proj-*, etc.) working

### C2b: AGENT-034/026/037 Range Expansion
- eval/exec detection expanded beyond @tool context
- SSRF detection expanded with taint tracking
- Context confidence levels implemented
- No duplicate findings for @tool context

### C3: Privilege Detection (AGENT-043~048)
- All 6 rules implemented and tested
- Multi-language support (Python, JavaScript, TypeScript, Shell, Markdown)
- ASI category mappings correct

### C4: Tiered Reporting + Risk Score
- Four tiers: BLOCK (>=0.75), WARN (0.45-0.75), INFO (0.25-0.45), SUPPRESSED (<0.25)
- Confidence-weighted risk score (0.0-10.0)
- JSON output includes confidence, tier, and reason fields
- Terminal output respects tier filtering

## Summary

| Category | Status |
|----------|--------|
| Test Suite | PASS (656/657, 1 skipped) |
| Benchmark Samples | PASS (6/6 detected) |
| New Rules | PASS (AGENT-043~048 verified) |
| Performance | PASS (<1s scan time) |
| Architecture | PASS (AST-only, no heavy deps) |

**v0.5.0 Validation Status: PASS**

All C1-C4 implementations verified. Ready for C6 (Documentation + Release prep).
