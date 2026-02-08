# Sample Output

This directory contains sample output from running agent-audit on the `vulnerable-agent/` example.

## Files

| File | Format | Description |
|------|--------|-------------|
| `terminal.txt` | Plain text | Terminal output (ANSI colors stripped) |
| `results.json` | JSON | Structured output with full finding details |

## Regenerating

To regenerate these files:

```bash
# Terminal output
agent-audit scan examples/vulnerable-agent/ > examples/sample-output/terminal.txt 2>&1

# JSON output
agent-audit scan examples/vulnerable-agent/ --format json > examples/sample-output/results.json 2>/dev/null
```

## JSON Schema

The JSON output includes:

```json
{
  "version": "0.15.1",
  "scan_timestamp": "2026-02-06T...",
  "scan_path": "examples/vulnerable-agent",
  "scanned_files": 3,
  "summary": {
    "total": 43,
    "by_severity": {"critical": 21, "high": 14, "medium": 8},
    "by_tier": {"BLOCK": 33, "WARN": 7, "INFO": 3},
    "risk_score": 9.8
  },
  "findings": [
    {
      "rule_id": "AGENT-001",
      "title": "Command Injection via Unsanitized Input",
      "severity": "critical",
      "category": "command_injection",
      "location": {
        "file_path": "...",
        "start_line": 31,
        "snippet": "result = eval(expression)"
      },
      "confidence": 1.0,
      "tier": "BLOCK",
      "cwe_id": "CWE-78",
      "owasp_id": "ASI-02",
      "remediation": {...}
    }
  ]
}
```

## Tier System

| Tier | Confidence | Meaning |
|------|------------|---------|
| BLOCK | >= 90% | Fix immediately |
| WARN | >= 60% | Should fix |
| INFO | >= 30% | Review recommended |
| SUPPRESSED | < 30% | Likely false positive |
