# State of AI Agent Security 2026

## Scanning Open-Source Agent Projects with Agent Audit

**Published:** February 2026
**Methodology:** Static analysis using [Agent Audit v0.15.1](https://github.com/HeadyZhang/agent-audit)
**Projects Scanned:** 6 open-source AI agent repositories

---

## Executive Summary

We scanned **6 prominent open-source AI agent projects** representing the current state of agentic AI development. The results reveal a concerning pattern: **617 security findings** across projects, with **269 classified as CRITICAL** severity.

The most common vulnerability? **Tool functions that accept unvalidated input** — a pattern that enables prompt injection, command injection, and data exfiltration attacks.

### Key Statistics

| Metric | Value |
|--------|-------|
| **Total Projects Scanned** | 6 |
| **Total Findings** | 617 |
| **Critical Severity** | 269 (44%) |
| **High Severity** | 348 (56%) |
| **High-Confidence (BLOCK tier)** | 134 |
| **Most Common Vulnerability** | AGENT-034: Tool Without Input Validation |

---

## Projects Analyzed

| Project | Description | Stars | Findings | Risk |
|---------|-------------|-------|----------|------|
| **OpenHands** | Autonomous coding agent (formerly OpenDevin) | 38k+ | 347 | HIGH |
| **Gorilla** | Berkeley's LLM-powered API agent | 11k+ | 78 | HIGH |
| **SWE-agent** | Software engineering agent from Princeton | 14k+ | 60 | HIGH |
| **MLAgentBench** | ML research agent benchmark | 1k+ | 61 | HIGH |
| **CodeAct** | Code-as-action agent framework | 500+ | 63 | HIGH |
| **Generative Agents** | Stanford's "Smallville" simulation | 16k+ | 8 | MEDIUM-HIGH |

---

## Findings by OWASP Agentic Category

The findings map to the [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    OWASP Agentic Top 10 Coverage                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ASI-02: Tool Misuse             ████████████████████████████████ 397    │
│  ASI-01: Goal Hijacking          ███████████                      72     │
│  ASI-07: Inter-Agent Comms       █████████                        66     │
│  ASI-05: Code Execution          █████                            37     │
│  ASI-04: Credential Exposure     ███                              27     │
│  ASI-10: Rogue Agents            ██                               12     │
│  ASI-08: Cascading Failures      █                                 4     │
│  ASI-09: Trust Exploitation      █                                 2     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Analysis

**Tool Misuse (ASI-02)** dominates with 64% of all findings. This reflects a fundamental pattern in agent development: developers create tool functions that accept string parameters from LLMs without considering that those inputs are **attacker-controlled**.

**Goal Hijacking (ASI-01)** appears in 12% of findings, primarily through system prompts constructed with f-strings that interpolate user input.

---

## Top 10 Rules Triggered

| Rank | Rule | Count | Severity | Description |
|------|------|-------|----------|-------------|
| 1 | **AGENT-034** | 203 | HIGH | Tool function without input validation |
| 2 | **AGENT-026** | 142 | CRITICAL | LangChain tool input not sanitized |
| 3 | **AGENT-010** | 69 | CRITICAL | System prompt injection vector |
| 4 | **AGENT-020** | 66 | HIGH | Insecure inter-agent communication |
| 5 | **AGENT-047** | 41 | HIGH | Unsandboxed subprocess execution |
| 6 | **AGENT-001** | 37 | CRITICAL | Command injection via unsanitized input |
| 7 | **AGENT-004** | 27 | HIGH | Hardcoded credentials |
| 8 | **AGENT-053** | 11 | CRITICAL | Agent self-modification risk |
| 9 | **AGENT-041** | 6 | CRITICAL | SQL injection via string interpolation |
| 10 | **AGENT-045** | 5 | HIGH | Browser automation without sandbox |

---

## Deep Dive: Critical Findings

### 1. Command Injection in OpenHands

**Location:** `openhands/runtime/utils/git_diff.py:26`

```python
result = subprocess.run(
    f"git diff {base_commit}..{head_commit}",
    shell=True,  # ← Dangerous: shell=True with variable input
    capture_output=True,
    ...
)
```

**Risk:** An attacker who controls commit references (via a malicious repository or crafted input) can execute arbitrary shell commands.

**OWASP Mapping:** ASI-02 (Tool Misuse), ASI-05 (Code Execution)

---

### 2. Eval of LLM Output in Gorilla

**Location:** `gorilla/local_inference/llama_3_1.py:205`

```python
function_calls = eval(result)  # ← Direct eval of LLM output
```

**Risk:** If the LLM is manipulated via prompt injection, it can return malicious Python code that executes with full system access.

**OWASP Mapping:** ASI-02 (Tool Misuse), ASI-05 (Code Execution)

---

### 3. Shell Execution with User Input in MLAgentBench

**Location:** `MLAgentBench/low_level_actions.py:181`

```python
process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    shell=True  # ← shell=True on agent-constructed command
)
```

**Risk:** The ML research agent can execute arbitrary commands based on its understanding of tasks — a compromised prompt leads to RCE.

**OWASP Mapping:** ASI-02 (Tool Misuse), ASI-10 (Rogue Agents)

---

### 4. System Prompt Injection in Generative Agents

**Location:** `generative_agents/reverie/backend_server/persona/cognitive_modules/`

```python
prompt = f"""
You are {persona.name}. {persona.description}
The user says: {user_input}  # ← User input in system context
"""
```

**Risk:** User-controlled input mixed into system instructions enables goal hijacking — the agent's persona and objectives can be overwritten.

**OWASP Mapping:** ASI-01 (Goal Hijacking)

---

### 5. Agent Self-Modification in SWE-agent

**Location:** Multiple files with `importlib.reload()` patterns

```python
# Pattern detected: writing to .py files + reloading modules
with open("config.py", "w") as f:
    f.write(new_config)
importlib.reload(config)
```

**Risk:** An agent that can modify and reload its own code can bypass safety constraints and become a "rogue agent."

**OWASP Mapping:** ASI-10 (Rogue Agents)

---

## Findings by Project

### OpenHands (347 findings)

The largest and most complex project shows the most findings, reflecting its extensive capability surface:

| Category | Count | Key Concern |
|----------|-------|-------------|
| Tool Misuse | 226 | Many action functions lack input validation |
| Inter-Agent Comms | 61 | WebSocket/HTTP communication without auth |
| Credential Exposure | 22 | API keys in config patterns |
| Command Injection | 17 | subprocess calls in runtime utilities |
| Goal Hijacking | 14 | Prompt construction patterns |

**Notable:** OpenHands has 61 findings related to insecure inter-agent communication — the runtime architecture involves multiple communicating components that would benefit from mutual authentication.

---

### Gorilla (78 findings)

Berkeley's API-calling agent shows a high ratio of critical findings:

| Metric | Value |
|--------|-------|
| Critical | 47 (60%) |
| BLOCK tier | 42 (54%) |
| Primary Issue | `eval()` of LLM-generated code |

**Notable:** Gorilla's approach of parsing LLM output as executable Python creates a direct code injection pathway.

---

### SWE-agent (60 findings)

Princeton's software engineering agent has concerning self-modification patterns:

| Finding | Count | Concern |
|---------|-------|---------|
| AGENT-053 (Self-modification) | 4 | Agent can modify its own code |
| AGENT-034 (No validation) | 40 | Tool inputs not validated |
| AGENT-047 (Unsandboxed) | 11 | Subprocess without isolation |

---

### MLAgentBench (61 findings)

The ML research benchmark has high-risk execution patterns:

| Finding | Concern |
|---------|---------|
| `exec(command, globals())` | Direct execution of agent-generated code |
| `subprocess.Popen(..., shell=True)` | Shell injection vector |
| `os.system(f'say "{text}"')` | OS command with interpolated text |

---

### CodeAct (63 findings)

The code-as-action framework shows expected patterns for its architecture:

| Category | Count |
|----------|-------|
| Tool Misuse | 44 |
| Goal Hijacking | 12 |
| Inter-Agent Comms | 3 |
| Command Injection | 3 |

---

### Generative Agents (8 findings)

Stanford's simulation project has the fewest findings but all are CRITICAL:

- 6× AGENT-010 (System prompt injection)
- 2× AGENT-041 (SQL injection)

The SQL injection findings relate to the simulation's SQLite-based memory system.

---

## Recommendations

### For Agent Developers

1. **Validate all tool inputs** — Never pass LLM-provided strings directly to `subprocess`, `eval`, `exec`, or SQL queries

2. **Use structured outputs** — Prefer JSON schemas over free-form text parsing

3. **Sandbox code execution** — Use Docker, gVisor, or similar isolation for any code the agent runs

4. **Set iteration limits** — Always configure `max_iterations` on agent loops

5. **Authenticate inter-agent communication** — Use mTLS or signed messages between agent components

### For Organizations Deploying Agents

1. **Scan before deployment** — Integrate agent-audit into CI/CD pipelines

2. **Create baselines** — Track security posture over time

3. **Review high-confidence findings first** — Focus on BLOCK tier results

4. **Consider the threat model** — Agent security depends on trust boundaries

---

## Methodology

### Scanning Configuration

```bash
agent-audit scan <project> --format json --severity low
```

### Confidence Tiering

| Tier | Confidence | Interpretation |
|------|------------|----------------|
| BLOCK | ≥ 0.90 | Very high confidence — likely exploitable |
| WARN | ≥ 0.60 | High confidence — should investigate |
| INFO | ≥ 0.30 | Medium confidence — review context |
| SUPPRESSED | < 0.30 | Low confidence — likely false positive |

### Limitations

- **Static analysis only** — Cannot detect runtime-only vulnerabilities
- **Python focus** — TypeScript/JavaScript components not fully analyzed
- **No exploit validation** — Findings are potential vulnerabilities, not confirmed exploits
- **Framework heuristics** — Some patterns may be intentional (e.g., research code)

---

## Conclusion

The AI agent ecosystem is moving fast — but security practices haven't kept pace. Even the most prominent open-source projects contain patterns that would be flagged immediately in traditional web applications.

The good news: most issues are **fixable with straightforward changes**:
- Input validation
- Sandboxed execution
- Proper authentication
- Iteration limits

**Agent Audit** provides visibility into these risks. We encourage all agent developers to:

1. **Scan your projects** — `pip install agent-audit && agent-audit scan .`
2. **Fix high-confidence findings** — Focus on BLOCK tier first
3. **Contribute rules** — Help us catch more patterns

---

## Resources

- **Agent Audit:** [github.com/HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit)
- **OWASP Agentic Top 10:** [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- **Rule Reference:** [docs/RULES.md](https://github.com/HeadyZhang/agent-audit/blob/master/docs/RULES.md)

---

*This report was generated using Agent Audit v0.15.1. Projects were scanned from public GitHub repositories as of February 2026. Findings represent potential security concerns and should be validated in context.*

*Disclaimer: This analysis is for educational purposes. We have not contacted project maintainers and make no claims about exploitability. All projects analyzed are open-source research tools not necessarily intended for production deployment.*
