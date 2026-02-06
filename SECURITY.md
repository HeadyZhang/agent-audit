# Security Policy

## Supported Versions

We provide security updates for the following versions of agent-audit:

| Version | Supported          |
| ------- | ------------------ |
| 0.15.x  | :white_check_mark: |
| 0.14.x  | :white_check_mark: |
| < 0.14  | :x:                |

We recommend always using the latest version to benefit from the most recent security improvements and vulnerability detection rules.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in agent-audit itself, please report it through GitHub's Private Vulnerability Reporting feature:

1. Go to the [Security tab](../../security) of this repository
2. Click "Report a vulnerability"
3. Fill out the vulnerability report form

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Initial acknowledgment | Within 48 hours |
| Vulnerability assessment | Within 7 days |
| Fix development (if confirmed) | Depends on severity |
| Public disclosure | After fix is released |

### Severity Classification

We use CVSS v3.1 to assess vulnerability severity:

- **Critical (9.0-10.0)**: Immediate priority, patch within 24-48 hours
- **High (7.0-8.9)**: High priority, patch within 7 days
- **Medium (4.0-6.9)**: Normal priority, patch in next release
- **Low (0.1-3.9)**: Low priority, patch as resources allow

## Security Design Principles

agent-audit is designed with security as a core principle. Here's how we ensure the tool itself is safe to use:

### 1. Pure Static Analysis

agent-audit performs **static analysis only**. It never executes, imports, or runs any code from the files being scanned. All analysis is performed by parsing source code as text and analyzing the Abstract Syntax Tree (AST).

```
Scanned Code → Text Parsing → AST Analysis → Findings
              (never executed)
```

### 2. No External Communication

agent-audit does **not** send any data to external services:

- No telemetry or usage tracking
- No code snippets sent to cloud APIs
- No network requests during scanning
- All processing happens locally on your machine

### 3. No Network Access Required

The tool operates entirely offline:

- All detection rules are bundled locally
- No external rule downloads
- No license validation calls
- Works in air-gapped environments

### 4. No Privileged Execution

agent-audit requires **no special permissions**:

- Runs as a normal user process
- Only needs read access to files being scanned
- Does not modify any scanned files
- Does not require root/administrator privileges

### 5. Minimal Dependencies

We minimize the attack surface by limiting dependencies:

- Core scanning uses only Python standard library (`ast`, `re`, `json`, `pathlib`)
- CLI depends only on well-audited packages (`click`, `rich`, `pyyaml`)
- No native code compilation required
- No system-level integrations

### 6. Input Validation

agent-audit validates all inputs:

- File paths are sanitized to prevent path traversal
- Configuration files are schema-validated
- Rule definitions are validated before loading
- Malformed input files are gracefully handled without crashes

## Security Hardening Recommendations

When integrating agent-audit into your CI/CD pipeline:

1. **Pin to specific versions** rather than using `latest`
2. **Run in isolated environments** (containers, sandboxed runners)
3. **Limit file system access** to only the directories being scanned
4. **Review SARIF output** before uploading to external services

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged in our release notes (unless they prefer to remain anonymous).

---

*This security policy was last updated for agent-audit v0.15.x*
