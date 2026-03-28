# OpenClaw Security Scan Report

## Agent Security Assessment Using Agent Audit

**Published:** March 2026
**Methodology:** Static analysis using [Agent Audit v0.18.2](https://github.com/HeadyZhang/agent-audit)
**Target:** [openclaw/openclaw](https://github.com/openclaw/openclaw) (main branch)

---

## Executive Summary

We scanned **OpenClaw**, a full-featured open-source AI assistant platform with gateway, extensions, and a skills marketplace. OpenClaw is primarily a TypeScript project (~8,500 TS/JS files) with a small Python component, featuring a plugin architecture, daemon services, and browser automation capabilities. The scan produced **680 raw findings**, of which **615 (90.4%) were auto-classified as likely false positives** — predominantly AGENT-048 (Extension Privilege) findings that reflect OpenClaw's intentional plugin trust model rather than security defects. After automated triage, **65 findings remain active**: 31 confirmed and 34 requiring manual review, concentrated in credential handling and privilege escalation patterns.

### Key Statistics

| Metric | Value |
|--------|-------|
| **Total Raw Findings** | 680 |
| **After Auto-Triage** | 65 (31 confirmed + 34 review) |
| **Likely False Positives** | 615 (90.4%) |
| **BLOCK Tier (confidence >= 0.90)** | 14 |
| **WARN Tier (confidence >= 0.60)** | 296 |
| **Risk Score** | 9.8/10 (HIGH) |
| **OWASP ASI Categories Hit** | 2 of 10 |
| **Most Common Rule** | AGENT-048: Extension Privilege (515) |
| **Most Confirmed Rule** | AGENT-046: Credential Store Access (16) |

---

## Findings by OWASP Agentic Category

```
┌─────────────────────────────────────────────────────────────────────────┐
│               OWASP ASI Coverage (active findings only)                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ASI-03: Credential Exposure    ████████████████████████████████  58   │
│  ASI-05: Code Execution         ████                              7   │
│                                                                        │
│  ASI-01: Goal Hijacking         (none)                            0   │
│  ASI-02: Tool Misuse            (none)                            0   │
│  ASI-04: Supply Chain           (none)                            0   │
│  ASI-06: Excessive Agency       (none)                            0   │
│  ASI-07: Logging Gaps           (none)                            0   │
│  ASI-08: Resource Mgmt          (none)                            0   │
│  ASI-09: Insecure Comms         (none)                            0   │
│  ASI-10: Kill Switch            (none)                            0   │
│                                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Analysis

**Credential Exposure (ASI-03)** accounts for 89% of active findings. This reflects OpenClaw's architecture: as a personal AI assistant that integrates with macOS Keychain, system daemons, and multiple third-party services, credential handling paths are numerous and surface-heavy.

**Code Execution (ASI-05)** findings are concentrated in extension subprocess calls and skill-level `curl | bash` patterns — areas where untrusted input could reach shell execution.

The narrow ASI coverage (2/10) is notable: OpenClaw's codebase shows maturity in areas like tool validation (no AGENT-034 triggers), inter-agent communication, and resource management. The security surface is concentrated, not diffuse.

---

## Top Rules Triggered

| Rank | Rule | Count | Severity | Description |
|------|------|-------|----------|-------------|
| 1 | **AGENT-048** | 515 | HIGH | Extension imports from core without permission boundary |
| 2 | **AGENT-004** | 87 | HIGH | Hardcoded credentials / secrets in source |
| 3 | **AGENT-047** | 37 | HIGH | Subprocess execution without sandbox isolation |
| 4 | **AGENT-046** | 17 | HIGH | Credential store access (Keychain, env vars) |
| 5 | **AGENT-043** | 11 | CRITICAL | System daemon/service registration |
| 6 | **AGENT-045** | 8 | HIGH | Browser automation without sandbox restrictions |
| 7 | **AGENT-044** | 2 | CRITICAL | NOPASSWD sudoers configuration |
| 8 | **AGENT-034** | 1 | HIGH | Tool function without input validation |
| 9 | **AGENT-059** | 1 | CRITICAL | Critical file modification instruction |
| 10 | **AGENT-058** | 1 | CRITICAL | Obfuscated shell command (curl pipe to shell) |

**Note:** AGENT-048 (515 findings) was almost entirely auto-filtered — 514/515 are likely false positives per OpenClaw's documented plugin trust model where extensions are part of the trusted computing base.

---

## Deep Dive: Critical Findings

### 1. NOPASSWD Sudoers Configuration

**Location:** `scripts/clawlog.sh:29`
**Rule:** AGENT-044 (Sudoers NOPASSWD)

```bash
echo -e "Quick fix:"
echo -e "  1. Run: ${GREEN}sudo visudo${NC}"
echo -e "  2. Add: ${GREEN}$(whoami) ALL=(ALL) NOPASSWD: /usr/bin/log${NC}"
echo -e "  3. Save and exit (:wq)\n"
```

**Risk:** Script instructs users to add NOPASSWD sudoers entries. While scoped to `/usr/bin/log`, this pattern weakens the host security boundary and could be expanded by subsequent modifications.

**OWASP Mapping:** ASI-03 (Credential Exposure / Privilege Escalation)

---

### 2. macOS Keychain Credential Extraction

**Location:** `src/agents/cli-credentials.ts:219`
**Rule:** AGENT-046 (Credential Store Access)

```typescript
const secret = execSyncImpl(
  `security find-generic-password -s "Codex Auth" -a "${account}" -w`,
  {
    encoding: "utf8",
    timeout: 5000,
    stdio: ["pipe", "pipe", "pipe"],
  },
).trim();
```

**Risk:** Direct macOS Keychain access via `security` CLI to extract stored credentials. The `account` variable is derived from a computed path — if an attacker can influence the codex home directory, they could redirect credential lookups. This pattern repeats at lines 310 and 380 for different credential types.

**OWASP Mapping:** ASI-03 (Credential Exposure)

---

### 3. Curl Piped to Shell in Skill Definition

**Location:** `skills/xurl/SKILL.md:54`
**Rule:** AGENT-058 (Obfuscated Shell Command)

```bash
curl -fsSL https://raw.githubusercontent.com/xdevplatform/xurl/main/install.sh | bash
```

**Risk:** Classic `curl | bash` anti-pattern in a skill definition. If the agent executes this instruction, it downloads and runs arbitrary code from an external URL without verification. A compromised upstream or MITM attack would lead to arbitrary code execution on the host.

**OWASP Mapping:** ASI-05 (Code Execution)

---

### 4. Critical File Modification in Skill Instructions

**Location:** `skills/healthcheck/SKILL.md:242`
**Rule:** AGENT-059 (Critical File Modification)

```markdown
also update `MEMORY.md` (long-term memory is optional and only used in private sessions).

If the session cannot write to the workspace, ask for permission or provide exact entries
the user can paste into the memory files.
```

**Risk:** Skill instructs the agent to modify `MEMORY.md`, a file that influences the agent's long-term behavior and context. While OpenClaw's trust model treats workspace files as operator-controlled, a compromised skill or prompt injection could use this as a persistence mechanism — poisoning the agent's memory to influence future sessions.

**OWASP Mapping:** ASI-05 (Code Execution / Persistence)

---

### 5. Unsandboxed Subprocess in Extension

**Location:** `extensions/tlon/index.ts:93`
**Rule:** AGENT-047 (Unsandboxed Subprocess)

```typescript
function runTlonCommand(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env: process.env });
```

**Risk:** Extension spawns an external binary with the full process environment (including secrets in env vars) and no sandbox isolation. The `binary` parameter is a string — if it can be influenced by agent decisions or untrusted input, this is a direct path to arbitrary command execution.

**OWASP Mapping:** ASI-05 (Code Execution)

---

## Triage Summary

| Classification | Count | Action |
|---------------|-------|--------|
| **Confirmed** | 31 | Auto-verified, high-confidence true positives |
| **Needs Review** | 34 | Require manual context evaluation |
| **Likely FP** | 615 | Auto-filtered by path/confidence heuristics |

### Confirmed Breakdown by Rule

| Rule | Count | Category |
|------|-------|----------|
| AGENT-046 | 16 | Credential Store Access |
| AGENT-004 | 14 | Hardcoded Credentials |
| AGENT-044 | 1 | NOPASSWD Sudoers |

### Needs Review Breakdown by Rule

| Rule | Count | Category |
|------|-------|----------|
| AGENT-004 | 15 | Hardcoded Credentials |
| AGENT-043 | 7 | Daemon/Service Registration |
| AGENT-047 | 5 | Unsandboxed Subprocess |
| AGENT-045 | 3 | Browser Without Sandbox |
| AGENT-044 | 1 | NOPASSWD Sudoers |
| AGENT-048 | 1 | Extension Privilege |
| AGENT-059 | 1 | Critical File Modification |
| AGENT-058 | 1 | Obfuscated Shell Command |

---

## Notes: OpenClaw Trust Model

OpenClaw's [SECURITY.md](https://github.com/openclaw/openclaw/blob/main/SECURITY.md) defines a comprehensive operator trust model that affects how findings should be interpreted:

1. **One-User Trust Model:** OpenClaw is designed as a personal assistant (one trusted operator per gateway), not a multi-tenant platform. Authenticated gateway callers are treated as trusted operators.

2. **Plugin Trust Boundary:** Plugins and extensions are part of the trusted computing base. Installing a plugin grants it the same trust level as local code. This means most AGENT-048 findings (514/515) are by-design, not vulnerabilities.

3. **Exec Behavior:** Execution is host-first by default (`sandbox.mode` defaults to `off`). Subprocess calls running on the host are expected behavior in the trusted-operator model.

4. **Prompt Injection Out of Scope:** Prompt injection without a boundary bypass (auth/policy/sandbox) is explicitly out of scope.

5. **Workspace Files are Trusted State:** `MEMORY.md` and workspace files are treated as operator-controlled. Reports requiring write access to these paths are out of scope unless a separate untrusted boundary bypass is demonstrated.

**Implication for this report:** Many findings that would be critical in a multi-tenant SaaS context are by-design in OpenClaw's trust model. The most actionable findings are those in **skills** (which may come from untrusted community sources) and **credential handling paths** (where defense-in-depth matters regardless of trust model).

---

## Methodology

### Scanning Configuration

```bash
agent-audit scan /tmp/clawskills --format sarif -o clawskills_report.sarif
```

### Confidence Tiering

| Tier | Confidence | Count | Interpretation |
|------|------------|-------|----------------|
| BLOCK | >= 0.90 | 14 | Very high confidence — likely true positive |
| WARN | >= 0.60 | 296 | High confidence — should investigate |
| INFO | >= 0.30 | 181 | Medium confidence — review in context |
| SUPPRESSED | < 0.30 | 189 | Low confidence — likely false positive |

### Auto-Triage Classification

Findings were automatically classified using:
- **Rule precision tables** — historical true positive rates per rule
- **Path-based filtering** — test fixtures, examples, node_modules, vendor code
- **Message-based filtering** — placeholder values, mock data, example keys
- **Confidence x precision thresholds** — confirmed requires both >= 0.80/0.90

### Limitations

- **Static analysis only** — Cannot detect runtime-only vulnerabilities or actual exploitation
- **TypeScript/JS heuristic** — agent-audit's core engine is optimized for Python; TypeScript analysis uses pattern matching rather than full AST parsing
- **Trust model context** — Automated triage cannot fully account for OpenClaw's nuanced operator trust model; manual review is recommended for all "needs review" items
- **Skill content** — Skills (markdown instruction files) are analyzed for dangerous patterns but the analysis cannot determine if a skill is community-sourced or first-party

---

## Resources

- **Agent Audit:** [github.com/HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit)
- **OWASP Agentic Top 10:** [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- **OpenClaw Security Policy:** [SECURITY.md](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
- **OpenClaw Trust Model:** [trust.openclaw.ai](https://trust.openclaw.ai)

---

*This report was generated using Agent Audit v0.18.2. The project was scanned from the public GitHub repository as of March 2026. Findings represent potential security concerns identified through static analysis and should be validated in context against OpenClaw's documented trust model. This analysis is for research purposes — we acknowledge OpenClaw's mature security posture and detailed threat model documentation.*
