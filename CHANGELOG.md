# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-02-05

### Micro-Patch: False Positive Reduction

#### AGENT-043 Tightened Daemon Detection
- Now distinguishes daemon registration from process management
- Excludes pkill, kill, nohup, &, tmux, and screen from daemon detection
- Only triggers on true daemon registration: launchctl bootstrap/load/enable, systemctl enable, pm2 startup/save

#### AGENT-046 Credential Store Deduplication
- Cross-file deduplication by credential store type (macOS Keychain, Linux keyring, Bitwarden, 1Password, etc.)
- Multiple calls to the same credential store type → single finding with highest confidence
- Reduces noise when same credential pattern appears multiple times

#### AGENT-047 Extended Safe Command List
- Added macOS-specific commands: open, pbcopy, pbpaste, say, osascript, defaults
- Added system info commands: which, where, whoami, uname, hostname, date
- Added text processing: wc, head, tail, grep, sed, awk, sort, uniq, cut, tr
- Added file utilities: ls, pwd, echo, cat, touch, mkdir, cp, mv, test
- Added archive/network: tar, gzip, zip, curl, wget, ping, dig, nslookup

#### Risk Score v2 Formula
- Switched from log2 to natural log (ln) for smoother scaling
- New formula: `1.8 * ln(1 + raw_score)` + BLOCK bonus
- BLOCK bonus: +0.3 per BLOCK finding, capped at 2.0
- Score capped at 9.8 (10.0 reserved for theoretical extremes)
- Calibration: 3 WARN → ~2.7, 10 WARN → ~5.0, 20 WARN → ~5.8, 50 WARN + 5 BLOCK → ~9.3

### Tests
- 716 tests passing (up from 715 in v0.5.1)
- New test suite: `test_micropatch_v052.py` with 21 tests

## [0.5.0] - 2026-02-04

### Major Changes

#### Multi-Language AST Support
- tree-sitter based parsing for TypeScript, JavaScript (optional dependency)
- Unified AST query interface with `find_assignments()`, `find_function_calls()`
- Graceful fallback to regex-based parsing when tree-sitter not installed

#### AGENT-004 Semantic Overhaul
- 3-stage analysis: candidate discovery -> value analysis -> context scoring
- Shannon entropy + placeholder detection for false positive reduction
- New credential formats: sk-proj-*, sk-ant-*, co-*, and more
- Confidence-based tiering: BLOCK(>=0.90), WARN(>=0.60), INFO(>=0.30), SUPPRESSED

#### Detection Range Expansion (AGENT-034/026/037)
- eval/exec detection beyond @tool context (addresses CVE-2023-29374, CVE-2023-36258)
- SSRF detection beyond @tool context
- Context-aware confidence scoring (tool_decorator=0.90, class_method=0.60, standalone=0.55)

#### New Privilege Detection Rules (AGENT-043~048)
- AGENT-043: Daemon privilege escalation (launchctl, systemctl, pm2)
- AGENT-044: Sudoers NOPASSWD configuration
- AGENT-045: Browser automation without sandbox
- AGENT-046: System credential store access (Keychain, gnome-keyring, pass)
- AGENT-047: Subprocess execution without sandbox
- AGENT-048: Extension/plugin permission boundaries

#### Confidence-Based Tiered Reporting
- Risk score calculation: logarithmic formula with severity weighting
- Terminal output grouped by tier (BLOCK -> WARN -> INFO -> SUPPRESSED)
- --verbose, --min-tier, --no-color CLI options
- JSON output includes confidence, tier, and reason fields

### Benchmark Results
- 656 tests passing
- All 6 benchmark samples (KNOWN-001~004, WILD-001~002) detected correctly
- Fixtures scan: 0.61 seconds

### Dependencies
- Optional: tree-sitter >= 0.22.0 (install with `pip install agent-audit[tree-sitter]`)

## [0.4.1] - 2026-02-04

### Fixed

- **AGENT-026: URL Allowlist Validation Detection** - Recognizes URL allowlist validation as SSRF mitigation:
  - Detects `urlparse()` + `netloc/hostname` + `in/not in` + `raise/return` patterns
  - Safe URL fetch patterns now receive `confidence=0.20` and `tier=SUPPRESSED`
  - Reduces false positives on properly validated network requests

- **AGENT-034: Safe AST Evaluation Detection** - Recognizes `ast.literal_eval()` and `ast.parse()` as safe:
  - `ast.literal_eval()` is recognized as a safe alternative to `eval()`
  - `ast.parse()` without `eval()/exec()` is recognized as safe AST-based validation
  - Safe AST patterns receive `confidence=0.10` and `tier=SUPPRESSED`

- **AGENT-034: Parameterized SQL Query Detection** - Recognizes parameterized queries as injection-safe:
  - Detects `cursor.execute(sql, params)` with 2+ arguments
  - Verifies first argument is not f-string, `.format()`, `%` formatting, or concatenation
  - Parameterized queries receive `confidence=0.10` and `tier=SUPPRESSED`

### Added

- **Finding Model: `tier` Field** - New field for confidence-based reporting tiers:
  - `BLOCK`: confidence >= 0.90 (high confidence, should fail CI)
  - `WARN`: confidence >= 0.60 (medium confidence)
  - `INFO`: confidence >= 0.30 (low confidence)
  - `SUPPRESSED`: confidence < 0.30 (very low, filtered by default)
  - Foundation for v0.5.0 tiered reporting architecture

- **`confidence_to_tier()` Helper** - Utility function to convert confidence scores to tiers

### Changed

- **`is_actionable()` Threshold** - Changed default from 0.50 to 0.30 to align with SUPPRESSED tier
- **JSON Output** - Now includes `tier` field in all findings

### Quality Metrics

- All 393 tests passing
- 3 false positives eliminated (Precision: 98.51% → 100%)
- Recall maintained at 100%
- F1 Score: 100%

## [0.4.0] - 2026-02-04

### Added

- **Standardized Benchmark Infrastructure** - New reproducible benchmark system:
  - `tests/benchmark/benchmark_config.yaml` - Configuration with locked scan paths for all 11 benchmark targets
  - `tests/benchmark/run_benchmark.py` - Automated runner with unified ASI extraction
  - Comparison with previous results and quality assessment
  - Report generation (Markdown + JSON)

- **Unified ASI Extraction** - Backward compatible ASI category handling:
  - Primary field: `owasp_id` in findings
  - Added `asi_categories` list to JSON output for compatibility
  - Supports both old (`owasp_agentic_id`) and new field names

### Changed

- **AGENT-018 Framework Path Filtering** - Extended path patterns for framework source code:
  - Added `langchain_core`, `langchain_community` patterns
  - Added OpenAI Agents SDK and Google ADK patterns
  - T3 (langchain-core) reduced from 44 to 3 findings
  - T6 (openai-agents) reduced from 47 to 28 findings
  - T7 (adk-python) reduced from 64 to 33 findings

- **AGENT-041 Precision Improvements** - Reduced SQL injection false positives:
  - Now requires SQL keyword prefix (SELECT, INSERT, UPDATE, DELETE, etc.)
  - Removed `sql_percent_injection` pattern (too many FP with parameterized queries)
  - Improved `.format()` detection logic
  - Only triggers for database-like callers (cursor, conn, db, etc.)

- **AGENT-004/005 ASI Mapping** - Fixed missing OWASP ID:
  - AGENT-004 (Hardcoded Credentials) now correctly maps to ASI-04
  - AGENT-005 (Unverified MCP Server) now correctly maps to ASI-04

- **MCP Config Scanner** - Handle non-dict values gracefully:
  - Skip comments and metadata fields in mcpServers
  - Prevents `'str' object has no attribute 'get'` errors

### Fixed

- MCP config scanning error when config contains comment fields
- Missing `owasp_id` in AGENT-004/005 findings
- `.format()` SQL injection detection not triggering correctly

### Technical Debt Addressed

- Four iterations of benchmark inconsistency resolved
- ASI field naming unified across codebase
- Scan path standardization for framework projects (T3, T6-T9)

### Quality Metrics

- All 385 tests passing
- mypy: 0 errors
- OWASP Coverage: 10/10 ASI categories
- Full backward compatibility maintained

## [0.3.2] - 2026-02-04

### Added

- **AGENT-041: SQL Injection Detection** - Detects SQL queries constructed with:
  - f-string interpolation (`f"SELECT * FROM users WHERE id = {user_id}"`)
  - `.format()` method
  - `%` formatting
  - String concatenation
  - Maps to ASI-02 (Tool Misuse)
- **AGENT-042: Excessive MCP Server Detection** - Warns when MCP configuration exceeds 10 servers
  - Maps to ASI-03 (Excessive Agency)
  - Enforces principle of least privilege
- **Extended Prompt/PromptTemplate Detection (AGENT-027)** - Now detects:
  - `Prompt()`, `PromptTemplate()`, `ChatPromptTemplate()` with variable templates
  - Risky `input_variables` configurations

### Changed

- **Improved Framework Allowlist (v0.3.2)** - Enhanced false positive suppression:
  - Added `/autogen/python/packages/` pattern for autogen monorepo
  - Added generic `/repos/{framework}/tests/` pattern detection
  - AGENT-018 (Memory Poisoning) now uses framework allowlist
  - AGENT-039 (Trust Boundary Violation) now uses framework allowlist
  - T9 (AutoGen) findings reduced from 449 to 70

### Fixed

- T1 (DVLLM) low detection - SQL injection now properly detected (3 findings, ASI-01/ASI-02)
- T2 (LangChain) narrow OWASP coverage - extended prompt detection adds ASI-01 coverage
- T9 (AutoGen) excessive false positives - framework test files now filtered
- ASI-03 coverage gap - now triggered via AGENT-042 on T10

### Benchmark Results (v0.3.2)

| Project | Findings | Change |
|---------|----------|--------|
| T1 - DVLLM | 3 | +2 (SQL injection) |
| T9 - AutoGen | 70 | -179 (framework filter) |
| T10 - MCP Config | 19 | +1 (ASI-03) |

**OWASP Coverage: 10/10 categories across all benchmark projects**

## [0.3.1] - 2026-02-04

### Added

- **LangChain Legacy API Detection (H1)** - Support for legacy LangChain patterns:
  - `ConversationalChatAgent`, `ConversationalAgent`, `ZeroShotAgent`, etc.
  - `AgentExecutor.from_agent_and_tools()` factory method
  - `initialize_agent()` function
- **Framework Allowlist for AGENT-028 (H2)** - Suppress false positives for framework internal code:
  - Added `rules/allowlists/framework_iteration.yaml`
  - Filters crewAI, LangChain, AutoGen, AgentScope framework source directories
  - Reduces T9 (crewAI) findings from 739 to 250 (AGENT-028: 489→0)
- AGENT-038 now maps to ASI-03 as secondary OWASP category
- New LangChain rules:
  - AGENT-040: LangChain AgentExecutor Without Safety Parameters (ASI-01)
  - AGENT-026: LangChain Tool Input Not Sanitized (ASI-02)
  - AGENT-027: Injectable System Prompt in LangChain Messages (ASI-01)
  - AGENT-028: Agent Without Iteration Limit (ASI-08)

### Changed

- **ASI ID Format Migration (H3)** - Unified OWASP ID format from `OWASP-AGENT-XX` to `ASI-XX`
- Rule ID conflict resolved: AGENT-025 in langchain_security_v030.yaml renamed to AGENT-040
- OWASP Agentic coverage remains 10/10 (100%)

### Fixed

- T1 (damn-vulnerable-llm-agent) zero detection issue - now detects legacy LangChain patterns
- T9 (crewAI) high false positive rate for AGENT-028 - framework paths now filtered
- ASI-03 coverage gap - restored via AGENT-002 + AGENT-038 secondary mapping
- `create_react_agent` incorrectly flagged for missing `max_iterations` - only check executors now

## [0.2.0] - 2026-02-03

### Added

- **Full OWASP Agentic Top 10 Coverage** - Expanded from 5 rules to complete coverage of all 10 ASI categories
- Custom rules support via `--rules-dir` option
- New detection rules:
  - AGENT-010: System Prompt Injection Vector (ASI-01)
  - AGENT-011: Missing Goal Validation (ASI-01)
  - AGENT-013: Long-Lived/Shared Credentials (ASI-03)
  - AGENT-014: Overly Permissive Agent Role (ASI-03)
  - AGENT-015: Untrusted MCP Server Source (ASI-04)
  - AGENT-016: Unvalidated RAG Data Source (ASI-04)
  - AGENT-017: Unsandboxed Code Execution (ASI-05)
  - AGENT-018: Unsanitized Memory Write (ASI-06)
  - AGENT-019: Unbounded Memory (ASI-06)
  - AGENT-020: Insecure Inter-Agent Communication (ASI-07)
  - AGENT-021: Missing Circuit Breaker (ASI-08)
  - AGENT-022: Tool Without Error Handling (ASI-08)
  - AGENT-023: Opaque Agent Output (ASI-09)
  - AGENT-024: No Kill Switch (ASI-10)
  - AGENT-025: No Observability (ASI-10)
- SARIF output now includes `OWASP-Agentic-{ASI-XX}` tags in `properties.tags`
- Extended Category enum with all OWASP Agentic categories
- OWASP Agentic ID mapping in Finding model

### Changed

- Improved Python AST scanner with additional detection patterns
- Enhanced rule engine to support OWASP Agentic ID mapping
- Updated SARIF formatter to include OWASP Agentic tags

### Fixed

- mypy type errors with class-level dict annotations
- Loop variable naming conflicts in scan command
- Cross-platform path normalization

## [0.1.0] - 2025-01-XX

### Added

- Initial release
- Python AST scanning for dangerous patterns
- MCP configuration scanning
- Secret detection (AWS keys, API tokens, etc.)
- Runtime MCP server inspection
- Output formats: terminal, JSON, SARIF, Markdown
- GitHub Action for CI/CD integration
- Baseline scanning for incremental analysis
- Configuration via `.agent-audit.yaml`
- Original 5 rules:
  - AGENT-001: Command Injection
  - AGENT-002: Excessive Permissions
  - AGENT-003: Data Exfiltration Chain
  - AGENT-004: Hardcoded Credentials
  - AGENT-005: Unverified MCP Server
