# Agent-Vuln-Bench Evaluation Report

**Date:** 2026-02-04
**Benchmark Version:** 1.0
**Tool Version:** agent-audit v0.4.1

## Overview

### agent-audit

- Samples evaluated: 5 (Knowns) + 2 (Wilds)
- Total TP: 3 (all from KNOWN-005)
- Total FN: 14
- Total FP: 0
- **Recall:** 17.6%
- **Precision:** 100%
- **F1:** 0.30
- Scan time: ~5s

## Per-Set Recall

| Tool | Set A (Injection) | Set B (MCP) | Set C (Data) |
|------|-------------------|-------------|--------------|
| agent-audit | 33.3% | 0.0% | 0.0% |

## Taint Analysis Depth

| Tool | Taint Accuracy | Note |
|------|----------------|------|
| agent-audit | 0.0% | v0.4.x baseline - no taint output |

## Per-Sample Results

### agent-audit

- ⚠️ **KNOWN-001** (LLMMathChain eval): TP=0, FN=1, FP=0
  - Gap: eval() not in @tool context
- ⚠️ **KNOWN-002** (PythonREPLTool exec): TP=0, FN=1, FP=0
  - Gap: exec() not in @tool context
- ⚠️ **KNOWN-003** (MCP Config): TP=0, FN=3, FP=0
  - Gap: Isolated JSON not scanned
- ⚠️ **KNOWN-004** (Hardcoded API Keys): TP=0, FN=5, FP=0
  - Gap: Credential pattern not matched
- ✅ **KNOWN-005** (Shell Execution): TP=3, FN=0, FP=0
  - Detected: subprocess.run, os.system, subprocess.Popen
- ⚠️ **WILD-001** (Calculator Tool eval): TP=0, FN=2, FP=0
  - Gap: @tool decorator present but eval not detected
- ⚠️ **WILD-002** (Web Fetcher SSRF): TP=0, FN=3, FP=0
  - Gap: SSRF patterns not detected

## Key Findings

1. **Shell injection detection is solid** - KNOWN-005 fully detected
2. **eval/exec detection limited** - Only in specific contexts
3. **MCP config detection needs work** - Isolated JSON files not scanned
4. **Credential detection gaps** - API key patterns not matched
5. **SSRF not detected** - Network request validation not checked

## Gap Analysis

### Critical Gaps (v0.5.0 Priority)

| Gap | Samples Affected | Proposed Fix |
|-----|------------------|--------------|
| eval/exec outside @tool | KNOWN-001, KNOWN-002, WILD-001 | Extend detection to any function context |
| Isolated JSON scanning | KNOWN-003 | Add JSON file scanning to scan command |
| Credential patterns | KNOWN-004 | Expand regex patterns for sk-*, co-*, etc. |
| SSRF detection | WILD-002 | Add network request validation rules |

### Observations

1. **Set B (MCP) at 0%** - Need to ensure MCP config files are scanned
2. **Taint tracking absent** - Expected for v0.4.x, improvement target for v0.5.0
3. **Precision is 100%** - No false positives, which is good

## Recommendations for v0.5.0

1. **High Priority:**
   - Extend eval/exec detection to all function contexts
   - Add explicit JSON file scanning support
   - Expand credential detection patterns

2. **Medium Priority:**
   - Add SSRF detection for requests/urllib calls
   - Improve MCP config detection

3. **Lower Priority:**
   - Implement basic taint tracking
   - Add source→sink annotations in output
