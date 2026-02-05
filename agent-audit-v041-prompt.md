# agent-audit v0.4.1: 3 FP 修复 + confidence 字段引入

## Claude Code Prompt (单个 Prompt，预计 30-60 分钟)

```
# 角色与目标

你是 agent-audit 的核心开发者。你正在完成一个精确的小版本更新 (v0.4.0 → v0.4.1)，
目标是：

1. 消除 benchmark 中仅存的 3 个误报，达成 Precision = 100%
2. 为 Finding 数据模型引入 confidence 字段，为 v0.5.0 的分层报告架构打地基

当前 benchmark 指标:
  Precision = 98.51% (3 FP / 201 total)
  Recall    = 100%   (0 FN)
  F1        = 99.25%

目标指标:
  Precision = 100%   (0 FP)
  Recall    = 100%   (0 FN)
  F1        = 100%

这是一个高精度手术——只改必须改的，不引入任何新功能。

---

# 阶段 0: 理解代码结构 (必须先完成)

在写任何代码之前，按顺序执行以下探查命令，每一步都仔细阅读输出：

```bash
# 0-1. 项目总览
find . -name "*.py" -path "*/agent_audit/*" | sort | head -40
cat pyproject.toml | head -30  # 版本号、依赖

# 0-2. Finding 数据模型
grep -rn "class Finding\|class Result\|class Report\|@dataclass\|NamedTuple\|TypedDict" \
    agent_audit/ --include="*.py"
# 然后读取每个命中的文件，重点关注 Finding 类的字段列表

# 0-3. AGENT-026 规则实现
grep -rn "AGENT.026\|026\|ssrf\|SSRF\|url.*fetch\|request.*get\|network.*request" \
    agent_audit/ --include="*.py" -l
# 逐个读取，理解:
#   a) 匹配逻辑 (AST pattern? 正则?)
#   b) 如何判定 requests.get/urllib 是漏洞
#   c) 是否已有任何白名单/安全检查识别逻辑

# 0-4. AGENT-034 规则实现
grep -rn "AGENT.034\|034\|input.*valid\|unsafe.*tool\|eval\|exec\|literal_eval\|sql.*inject\|parameteriz" \
    agent_audit/ --include="*.py" -l
# 逐个读取，理解:
#   a) 这条规则到底检测什么 (名称是 input validation / unsafe tool construction?)
#   b) eval/exec 检测逻辑
#   c) SQL 相关检测逻辑
#   d) 是否已区分 ast.literal_eval vs eval

# 0-5. 三个误报样本文件
find . -path "*/benign/*" -name "*.py" | sort
cat tests/benchmark/benign/validated/safe_url_fetch.py 2>/dev/null || \
    find . -name "safe_url_fetch.py" -exec cat {} \;
cat tests/benchmark/benign/sandboxed/restricted_python.py 2>/dev/null || \
    find . -name "restricted_python.py" -exec cat {} \;
cat tests/benchmark/benign/hardened/parameterized_sql.py 2>/dev/null || \
    find . -name "parameterized_sql.py" -exec cat {} \;

# 0-6. Ground truth 文件
find . -name "labeled_samples.yaml" -o -name "ground_truth.yaml" | head -3
# 读取找到的文件，理解标注格式

# 0-7. Benchmark 运行脚本
find . -name "run_benchmark*" -o -name "evaluate*" | head -5
# 读取，理解如何运行 benchmark 和计算指标

# 0-8. 现有测试
find . -name "test_*.py" -path "*/tests/*" | sort
pytest tests/ --collect-only 2>/dev/null | tail -20  # 看有多少测试
```

当你完成了所有 0-x 步骤的阅读后，在心里回答以下问题（写到注释中）：
- Finding 模型在哪个文件、有哪些字段？
- AGENT-026 的检测逻辑是怎样的？它在哪个 scanner 里？
- AGENT-034 的检测逻辑是怎样的？它是一条规则还是多条？
- 三个 benign 文件各自用了什么安全缓解措施？
- benchmark 指标是如何计算的？

然后才进入下一阶段。

---

# 阶段 1: 为 Finding 数据模型添加 confidence 字段

## 1-1. 修改 Finding 类

在 Finding 类（或等价的数据模型）中添加两个新字段：

```python
confidence: float = 1.0
# 取值范围 [0.0, 1.0]
# 默认 1.0 表示"与改动前行为一致"——现有所有规则不受影响
# 只有本次修改的 3 个 case 会设为 <1.0

tier: str = "WARN"
# 取值: "BLOCK" | "WARN" | "INFO" | "SUPPRESSED"
# 默认 "WARN" 保持向后兼容
# v0.5.0 会完整启用分层逻辑，本次只做字段预埋
```

## 1-2. 添加 tier 计算辅助函数

在 Finding 类同文件或 utils 中添加：

```python
def confidence_to_tier(confidence: float) -> str:
    """将 confidence 转换为报告层级"""
    if confidence >= 0.90:
        return "BLOCK"
    elif confidence >= 0.60:
        return "WARN"
    elif confidence >= 0.30:
        return "INFO"
    else:
        return "SUPPRESSED"
```

## 1-3. 确保 JSON 报告输出包含新字段

找到报告输出逻辑（JSON / 终端），确认新字段出现在输出中：

```json
{
    "rule_id": "AGENT-026",
    "severity": "HIGH",
    "confidence": 0.85,
    "tier": "WARN",
    ...
}
```

## 1-4. 关键约束

- 所有现有规则的 Finding 默认 confidence=1.0, tier="BLOCK"
- 这意味着现有行为零变化——只是给 Finding 多了两个字段
- 不修改报告格式（不做分层过滤），只是在输出中多带两个字段
- 报告层的实际分层过滤留给 v0.5.0

---

# 阶段 2: 修复 FP-1 — AGENT-026 识别 URL 白名单

## 问题

`benign/validated/safe_url_fetch.py` 中代码对 URL 做了域名白名单校验后再发起请求，
但 AGENT-026 仍报 SSRF，因为它只看到 `requests.get(url)` 而忽略了前面的白名单检查。

## 修复逻辑

在 AGENT-026 的检测函数中，当发现 `requests.get(var)` / `urllib.request.urlopen(var)` /
`httpx.get(var)` 等模式时，增加一个**向上回溯检查**：

```python
def has_url_validation(func_ast, url_var_name):
    """
    在同一函数体内，检查 url 变量在使用前是否经过了安全校验。

    识别的安全模式 (任一即可)：
    1. 白名单模式:
       parsed = urlparse(url_var)
       if parsed.hostname not in ALLOWED_*:  (或 ... in ALLOWED_*)
           raise ...

    2. 正则校验模式:
       if not re.match(SAFE_PATTERN, url_var):
           raise ...

    3. 域名提取+比对:
       domain = get_domain(url_var)
       if domain not in allowed_domains:
           raise ...

    返回: True 如果找到了可识别的安全检查
    """
```

具体 AST 检查步骤：

```python
# Step 1: 在函数体内查找 urlparse 调用
#   urlparse(var) 或 urllib.parse.urlparse(var)
#   其中 var 与 requests.get(var) 的 var 同名

# Step 2: 查找 hostname/netloc 属性访问
#   parsed.hostname 或 parsed.netloc

# Step 3: 查找包含 "not in" 或 "in" 的 if 语句
#   if xxx not in ALLOWED_HOSTS → 白名单校验
#   if xxx in BLOCKED_HOSTS → 黑名单校验（也算有校验）

# Step 4: 检查 if 分支中是否有 raise/return
#   必须有拒绝路径，否则只是日志记录不算安全检查

# 简化实现（如果完整数据流追踪太复杂）：
# 在同一函数内搜索以下关键词组合：
#   urlparse + (hostname | netloc) + (not in | in) + (raise | return)
# 如果全部存在 → 判定为有 URL 白名单校验
```

当检测到安全校验时的处理：

```python
if has_url_validation(func_node, url_var):
    # 不是完全排除——降低 confidence
    finding.confidence = 0.20  # 降到 INFO/SUPPRESSED 边界
    finding.tier = confidence_to_tier(0.20)  # → "SUPPRESSED"
    # 保留 finding 但标记为已缓解
    finding.metadata["mitigation_detected"] = "url_allowlist_validation"
```

## 测试验证

```python
# 必须通过:
# 1. safe_url_fetch.py → 不再被报为 AGENT-026 (或 confidence < 0.30)
# 2. 真正的 SSRF（无白名单直接 requests.get(user_input)）→ 仍被检出，confidence = 1.0
```

---

# 阶段 3: 修复 FP-2 — AGENT-034 识别 ast.literal_eval 安全模式

## 问题

`benign/sandboxed/restricted_python.py` 使用 `ast.literal_eval()` 安全解析表达式，
但 AGENT-034 将其与 `eval()` 同等对待。

## 关键安全事实

`ast.literal_eval()` 是 Python 标准库函数，**它只接受字面量表达式**
（字符串、数字、元组、列表、字典、布尔值、None），不会执行任何代码。
这是 Python 官方推荐的安全替代 `eval()` 的方式。
因此 `ast.literal_eval(user_input)` 是安全的，不应报为漏洞。

## 修复逻辑

在 AGENT-034 的检测函数中，增加对 `ast.literal_eval` 的识别：

```python
# 在检测 eval/exec 调用的逻辑中:

SAFE_EVAL_FUNCTIONS = {
    # (module_or_object, function_name)
    ("ast", "literal_eval"),
    ("ast", "parse"),  # ast.parse 本身不执行代码，只构建 AST
}

def is_safe_eval(call_node):
    """
    检查 AST 中的函数调用是否是已知安全的评估函数。

    安全的:
      ast.literal_eval(x)      → True
      ast.parse(x, mode="eval") → True (仅解析，不执行)
      json.loads(x)             → True (如果规则也标记了的话)

    不安全的:
      eval(x)                   → False
      exec(x)                   → False
      compile(x, ..., "exec")   → False
    """
    # AST 检查: 调用是 Attribute(value=Name(id="ast"), attr="literal_eval")
    # 或导入了 from ast import literal_eval 后直接 literal_eval(x)
```

当检测到安全 eval 时：

```python
if is_safe_eval(call_node):
    finding.confidence = 0.10  # 几乎确定安全
    finding.tier = confidence_to_tier(0.10)  # → "SUPPRESSED"
    finding.metadata["mitigation_detected"] = "ast_literal_eval_safe_mode"
```

## 扩展: 也识别 AST 白名单校验模式

如果代码中同时有：
```python
tree = ast.parse(user_input, mode="eval")
for node in ast.walk(tree):
    if type(node) not in SAFE_NODES:
        raise ValueError(...)
```

这种 "AST 白名单校验" 模式也应该被识别为安全缓解。
检测逻辑：在同一函数内存在 `ast.parse` + `ast.walk` + `type(node) not in` → 安全模式。

但如果这个太复杂，**只识别 `ast.literal_eval` 就足够通过 benchmark**。
AST 白名单的完整识别可以留给 v0.5.0。

## 测试验证

```python
# 必须通过:
# 1. restricted_python.py (ast.literal_eval) → 不再被报 (confidence < 0.30)
# 2. 真正的 eval(user_input) → 仍被检出，confidence = 1.0
# 3. 真正的 exec(user_code) → 仍被检出，confidence = 1.0
```

---

# 阶段 4: 修复 FP-3 — AGENT-034 识别参数化 SQL 查询

## 问题

`benign/hardened/parameterized_sql.py` 使用参数化查询 `cursor.execute(query, params)`，
但 AGENT-034 将其与字符串拼接 SQL 同等对待。

## 关键安全事实

参数化查询（prepared statements）是防御 SQL 注入的**行业标准方法**。
所有主流数据库驱动的 `.execute(sql, params)` 双参数调用都是安全的：

```python
# 安全 — 参数化查询，数据库驱动自动转义
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# 不安全 — 字符串拼接/格式化
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

## 修复逻辑

在 AGENT-034 检测 SQL 相关模式时，增加参数化查询识别：

```python
def is_parameterized_query(call_node):
    """
    检查 cursor.execute() 调用是否使用参数化查询。

    参数化查询的 AST 特征:
      Call(
        func=Attribute(attr="execute"),
        args=[sql_string, params],  # 有第二个参数
      )
    其中:
      - sql_string 是字面量字符串（含 %s/?/:name 占位符）
      - params 是 Tuple/List/Dict
      - sql_string 不是 f-string / .format() / % 格式化

    关键判定:
      args 数量 >= 2  → 高概率参数化
      args[0] 是 JoinedStr (f-string) → 非参数化
      args[0] 是 BinOp(%, str) → 非参数化 (% formatting)
      args[0] 是 Call(str.format) → 非参数化
    """

    # 最简实现:
    # 如果 .execute() 调用有 >= 2 个位置参数
    # 且第一个参数是普通字符串（不是 f-string/BinOp/%格式化/+拼接）
    # → 判定为参数化查询
```

当检测到参数化查询时：

```python
if is_parameterized_query(call_node):
    finding.confidence = 0.10  # 参数化查询是标准安全实践
    finding.tier = confidence_to_tier(0.10)  # → "SUPPRESSED"
    finding.metadata["mitigation_detected"] = "parameterized_sql_query"
```

## 测试验证

```python
# 必须通过:
# 1. parameterized_sql.py → 不再被报 (confidence < 0.30)
# 2. f"SELECT * FROM users WHERE id = {user_input}" → 仍被检出，confidence = 1.0
# 3. "SELECT ... WHERE id = " + user_input → 仍被检出，confidence = 1.0
```

---

# 阶段 5: Benchmark 更新 (如果需要)

## 5-1. 检查是否需要更新 ground truth

三个 benign 文件在 ground truth 中已经正确标注为 `vulnerabilities: []`。
现在规则不再对它们报 finding（或 confidence < 0.30 被过滤），benchmark 应该自动通过。

但需要检查 benchmark 评估脚本是否理解 confidence 字段：
- 如果评估脚本把所有 Finding 都计为 TP/FP → 需要修改：**confidence < 0.30 的不计入**
- 如果评估脚本已经有过滤逻辑 → 确认阈值匹配

```bash
# 检查评估逻辑
grep -n "confidence\|tier\|threshold\|filter\|suppress" tests/benchmark/run_benchmark.py
grep -n "confidence\|tier\|threshold\|filter\|suppress" tests/benchmark/evaluate*.py
```

如果评估脚本没有 confidence 过滤：

```python
# 添加一行过滤:
# 在计算 TP/FP 之前
findings = [f for f in raw_findings if getattr(f, 'confidence', 1.0) >= 0.30]
# 或者
findings = [f for f in raw_findings if getattr(f, 'tier', 'WARN') != 'SUPPRESSED']
```

## 5-2. 运行 benchmark 验证

```bash
# 完整 benchmark
cd tests/benchmark
python run_benchmark.py --config benchmark_config.yaml

# 预期结果:
# Precision = 100% (0 FP)  ← 从 3 FP 降到 0
# Recall    = 100% (0 FN)  ← 保持不变
# F1        = 100%
```

## 5-3. 三个 FP 的具体验证

```bash
# 单独扫描三个 benign 文件，确认不再报 finding (或 confidence < 0.30):
python -m agent_audit scan tests/benchmark/benign/validated/safe_url_fetch.py 2>&1 | grep -i "finding\|AGENT"
python -m agent_audit scan tests/benchmark/benign/sandboxed/restricted_python.py 2>&1 | grep -i "finding\|AGENT"
python -m agent_audit scan tests/benchmark/benign/hardened/parameterized_sql.py 2>&1 | grep -i "finding\|AGENT"

# 预期: 每个文件 0 findings (tier >= WARN) 或明确标记 SUPPRESSED
```

---

# 阶段 6: 回归测试

## 6-1. 现有测试

```bash
pytest tests/ -v --tb=short 2>&1 | tail -30
```

所有现有测试必须通过。如果有测试因为 Finding 模型变更而失败（比如 assert 检查字段数量），
只做最小修改让它兼容新字段。

## 6-2. 逆向验证 — 确保真正的漏洞仍被检出

```bash
# 找到一个已知包含真正 eval 漏洞的文件
find tests/ -path "*/vulnerable/*" -name "*.py" | head -5
# 扫描它，确认 AGENT-034 仍然触发，confidence = 1.0

# 找到一个已知包含 SSRF 漏洞的文件
find tests/ -path "*/vulnerable/*" -name "*ssrf*" -o -name "*url*" -o -name "*fetch*" | head -5
# 扫描它，确认 AGENT-026 仍然触发，confidence = 1.0

# 找到一个已知包含 SQL 注入的文件
find tests/ -path "*/vulnerable/*" -name "*sql*" | head -5
# 扫描它，确认 AGENT-034 仍然触发，confidence = 1.0
```

## 6-3. 核心不变性检查

```python
# 验证其他规则不受影响
# 扫描一个已知触发多条规则的项目:
python -m agent_audit scan tests/benchmark/T2_DamnVulnerableLLMProject/ 2>&1 | head -20
# findings 数量应与 v0.4.0 相同（±0）
# 所有 finding 的 confidence 应为 1.0（因为我们只改了 AGENT-026 和 AGENT-034 的特定分支）
```

---

# 阶段 7: 版本号更新

```bash
# 更新 pyproject.toml 或 setup.py 中的版本号
# 0.4.0 → 0.4.1

# 更新 CHANGELOG.md:
# ## [0.4.1] - 2026-02-04
#
# ### Fixed
# - AGENT-026: Recognize URL allowlist validation as SSRF mitigation (FP fix)
# - AGENT-034: Recognize `ast.literal_eval()` as safe evaluation (FP fix)
# - AGENT-034: Recognize parameterized SQL queries as injection mitigation (FP fix)
#
# ### Added
# - Finding model: `confidence` field (float, 0.0-1.0, default 1.0)
# - Finding model: `tier` field (BLOCK/WARN/INFO/SUPPRESSED, default BLOCK)
# - Foundation for v0.5.0 confidence-based tiered reporting
```

---

# 验收标准 (硬性，全部必须满足)

□ Finding 模型包含 confidence (float, default 1.0) 和 tier (str, default "BLOCK") 字段
□ JSON 报告输出包含 confidence 和 tier 字段
□ safe_url_fetch.py: AGENT-026 不触发 (或 confidence < 0.30 → SUPPRESSED)
□ restricted_python.py: AGENT-034 不触发 (或 confidence < 0.30 → SUPPRESSED)
□ parameterized_sql.py: AGENT-034 不触发 (或 confidence < 0.30 → SUPPRESSED)
□ 真正的 eval(user_input) 仍触发 AGENT-034, confidence = 1.0
□ 真正的 requests.get(user_input) 无白名单仍触发 AGENT-026, confidence = 1.0
□ 真正的 SQL 字符串拼接仍触发 AGENT-034, confidence = 1.0
□ Benchmark: Precision = 100%, Recall = 100%, F1 = 100%
□ 所有现有测试通过
□ 版本号更新为 0.4.1

# 禁止事项

✗ 不要修改任何非 AGENT-026 / AGENT-034 的规则逻辑
✗ 不要修改报告的输出格式（只添加字段，不改现有字段）
✗ 不要修改 ground truth 标注来"解决"误报
✗ 不要使用硬编码文件名来排除特定 benign 文件
✗ 不要删除或注释掉 AGENT-026 / AGENT-034 规则——是降低 confidence，不是关闭规则
```
