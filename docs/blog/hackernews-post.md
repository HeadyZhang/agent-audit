# Hacker News Submission

## Title

```
Show HN: Agent Audit – Open-source security scanner for AI agents (OWASP Agentic Top 10)
```

## URL

```
https://github.com/HeadyZhang/agent-audit
```

---

## First Comment (Post immediately after submitting)

Hey HN,

I built Agent Audit because I kept seeing the same security anti-patterns in AI agent code — `eval()` on LLM outputs, `subprocess.run(shell=True)` with unvalidated tool inputs, system prompts constructed with f-strings. Traditional SAST tools flag some of these, but they don't understand the agent context.

**What it does:**

- Static analysis for Python agent code (LangChain, CrewAI, AutoGen, etc.)
- Scans MCP server configurations (Claude Desktop, etc.)
- 40+ rules mapped to the OWASP Agentic Top 10 [1]
- Outputs SARIF for GitHub Code Scanning integration

**Example of what it catches:**

```python
@tool
def search(query: str) -> str:
    # AGENT-041: SQL injection via f-string
    return db.execute(f"SELECT * FROM docs WHERE content LIKE '%{query}%'")
```

Traditional scanners might flag the SQL injection. Agent Audit also flags that this is a `@tool` function — meaning an LLM chooses what `query` contains, not a user form. The attack surface is different.

**What it doesn't do:**

- No cross-file taint analysis (yet) — currently intra-procedural only
- Python only — TypeScript MCP servers need separate tooling
- Static analysis limitations apply — can't catch runtime-only issues

**Some numbers from scanning open-source projects:**

I scanned 6 popular agent repos (OpenHands, SWE-agent, Gorilla, etc.). Found 617 findings total, 269 critical. Most common issue: tool functions that pass LLM-provided strings directly to dangerous sinks without validation.

Full report: https://github.com/HeadyZhang/agent-audit/blob/master/docs/reports/state-of-ai-agent-security-2026.md

**Install:**

```
pip install agent-audit
agent-audit scan .
```

MIT licensed. Happy to answer questions about the detection approach or agent security patterns in general.

[1] https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

---

## Backup Comments (for responding to likely questions)

### Q: "How does this compare to Semgrep?"

Semgrep is great for general SAST and I'd recommend using both. The difference:

- Semgrep: "Is this a SQL injection?" (pattern-based)
- Agent Audit: "Is this a tool function where an LLM controls the input, and does that input flow to a SQL query without validation?" (context-aware)

We also scan MCP configs, which is a JSON/YAML format Semgrep doesn't have rules for.

Think of it as: Semgrep for your web app, Agent Audit for your agent layer.

### Q: "Aren't these just regular vulnerabilities?"

Yes and no. The vulnerabilities themselves (SQLi, command injection) are classic. What's new is:

1. **The attack surface** — You're not validating user form input; you're trusting LLM output
2. **The trigger** — Prompt injection can cause an agent to call tools maliciously
3. **The context** — Agent-specific patterns like missing `max_iterations`, memory poisoning, inter-agent auth

A function with `eval()` is always risky. But `eval()` inside a `@tool` decorator is a different threat model.

### Q: "False positive rate?"

We use confidence scoring (0.0-1.0) and tier findings as BLOCK/WARN/INFO. High-confidence (BLOCK tier) findings have low FP rate in our benchmarks. Lower tiers need human review.

You can also use baseline mode to only see new findings in PRs.

### Q: "Why not just sandbox everything?"

You should! But defense in depth matters. Agent Audit catches issues before runtime. Sandboxing catches issues at runtime. Both are valuable.

Also, many agent deployments don't use proper sandboxing — that's one of the things we flag (AGENT-047: unsandboxed subprocess).

### Q: "What about JavaScript/TypeScript agents?"

Not yet, but it's on the roadmap. Python is where most of the agent frameworks are today (LangChain, CrewAI, AutoGen, DSPy). Happy to accept contributions for TS support.

---

## Timing Notes

Best times to post on HN (PST):
- Tuesday-Thursday
- 8-10 AM PST (catches US morning + EU afternoon)
- Avoid weekends and Monday mornings
