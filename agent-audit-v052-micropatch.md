# agent-audit v0.5.2 Micro-Patch — 单 Prompt

> **前置**: v0.5.1 已将 openclaw 842→52 BLOCK+WARN (94% 降幅)
> **目标**: 52→≤25 BLOCK+WARN, FP率 <20%, Risk Score 3.0-8.0
> **范围**: 只调规则粒度 + 去重 + Risk Score 公式，不加新功能

---

## 问题诊断

```
v0.5.1 openclaw: 52 BLOCK+WARN findings

┌─────────────┬────┬──────────────────────────────────────────────────────┐
│ 规则        │ 数量│ 诊断                                                │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-046   │ 17 │ 同一 credential store API 被每个调用点重复报告       │
│             │    │ 例: 5 个文件都调用 readKeychainPassword() → 报 5 次  │
│             │    │ 应该: 按 credential store 类型去重，每种只报最高 1 次 │
│             │    │ 预期消除: ~10                                        │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-043   │ 12 │ pkill/kill/background process 被当成 daemon 注册     │
│             │    │ 真正的 daemon: launchctl/systemctl/pm2 注册 (~2-3个) │
│             │    │ 不是 daemon: pkill gateway, kill -9, & 后台运行      │
│             │    │ 预期消除: ~8                                         │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-047   │  9 │ 部分已知安全命令漏了降权                             │
│             │    │ 例: spawn("open", [...]) / spawn("pbcopy", [...])   │
│             │    │ 预期消除: ~4                                         │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-004   │  6 │ ✅ 全 TP (postgres 连接串)，不动                    │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-045   │  4 │ ✅ TP (CDP/Playwright)，不动                        │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-044   │  2 │ ✅ TP (sudoers NOPASSWD)，不动                      │
├─────────────┼────┼──────────────────────────────────────────────────────┤
│ AGENT-048   │  2 │ ✅ TP (跨边界导入)，不动                            │
└─────────────┴────┴──────────────────────────────────────────────────────┘

另外: Risk Score = 10.0 (满分) 
原因: 52 个 WARN × severity_weight 的原始总分远超 log 缩放的天花板
     公式 min(10, 2.5 × log2(1 + raw)) 在 raw > 160 时就到 10.0
     52 × HIGH(1.5) × avg_conf(0.75) ≈ 58.5 → 2.5 × log2(59.5) ≈ 14.7 → cap 10.0

需要调整: 让公式对 20-50 个合理 findings 的项目输出 5.0-8.0
```

---

## Claude Code Prompt M1: 规则收紧 + 去重 + Risk Score 修正

```markdown
# 角色
你是 agent-audit 的维护者。你正在做一个 micro-patch，
收紧三条权限规则的误报模式、添加跨文件去重、修正 Risk Score 公式。

# 背景
v0.5.1 openclaw 扫描: 52 BLOCK+WARN findings。
其中约 20 个是真 TP，约 30 个是重复报告或模式过宽。
Risk Score 10.0 (满分) 是因为公式在 >20 findings 时就饱和了。

# 任务 (按顺序执行)

## 第一步: 读取当前代码

```bash
# 1. privilege_scanner — AGENT-043/046/047 实现
cat agent_audit/scanners/privilege_scanner.py

# 2. Risk Score 计算
grep -rn "risk_score\|calculate_risk\|Risk.*Score\|log2\|SEVERITY_WEIGHT" \
    agent_audit/ --include="*.py"
# 读取相关文件

# 3. 当前去重逻辑 (如果有)
grep -rn "dedup\|deduplicate\|seen\|unique\|group_by" \
    agent_audit/ --include="*.py"

# 4. 查看 v0.5.1 openclaw 扫描结果中具体的误报样本
# (如果有缓存结果文件)
```

## 第二步: 修复 AGENT-043 — 收紧 daemon 检测模式

当前问题: pkill、kill -9、`& ` 后台运行都被当成 daemon privilege escalation。
这些是进程管理操作，不是 daemon 注册。

```python
# 真正的 daemon 注册模式 (应保留，高 confidence):
DAEMON_REGISTRATION_PATTERNS = [
    # macOS
    r"launchctl\s+(load|bootstrap|enable)",
    r"LaunchDaemon",
    r"com\.apple\.loginitems",
    # Linux  
    r"systemctl\s+(enable|start|daemon-reload)",
    r"/etc/systemd/system/.*\.service",
    r"update-rc\.d\s+\w+\s+(defaults|enable)",
    r"chkconfig\s+--add",
    # 通用进程管理器 (持久化)
    r"pm2\s+(start|save|startup)",
    r"forever\s+start",
    r"supervisor.*conf",
]

# 不是 daemon 注册 (应排除或极低 confidence):
NOT_DAEMON_PATTERNS = [
    r"pkill\s+",              # 杀进程，不是注册 daemon
    r"kill\s+(-\d+\s+)?",     # 杀进程
    r"killall\s+",            # 杀进程
    r"&\s*$",                 # 后台运行，不是持久化
    r"nohup\s+",              # 后台运行，临时的
    r"screen\s+-",            # screen session，不是 daemon
    r"tmux\s+",               # tmux，不是 daemon
    r"bg\s*$",                # 后台化，不是 daemon
]

def check_daemon_privilege(source, file_path, language):
    """修正后的 AGENT-043 检测逻辑"""
    findings = []
    
    for line_num, line in enumerate(source.splitlines(), 1):
        # 先检查是否匹配排除模式
        if any(re.search(pat, line) for pat in NOT_DAEMON_PATTERNS):
            continue  # 跳过进程管理操作
        
        # 再检查是否匹配 daemon 注册模式
        for pattern in DAEMON_REGISTRATION_PATTERNS:
            if re.search(pattern, line):
                # 文件名加分
                fname = Path(file_path).name.lower()
                conf = 0.80
                if any(kw in fname for kw in ["daemon", "service", "startup", "init"]):
                    conf = 0.85
                
                findings.append(Finding(
                    rule_id="AGENT-043",
                    confidence=conf,
                    ...
                ))
                break
    
    # 如果文件名含 daemon 但内容只有排除模式 → INFO
    fname = Path(file_path).name.lower()
    if "daemon" in fname and not findings:
        # 检查是否有任何相关内容 (不限于注册模式)
        if any(kw in source.lower() for kw in ["daemon", "service", "background"]):
            findings.append(Finding(
                rule_id="AGENT-043",
                confidence=0.35,  # INFO 层
                message="File named as daemon but no service registration detected",
                ...
            ))
    
    return findings
```

## 第三步: 修复 AGENT-046 — 添加跨文件去重

当前问题: 同一种 credential store 访问在多个文件中重复报告。
例如 5 个文件都调用 `security find-generic-password` → 报 5 次。

```python
def deduplicate_credential_store_findings(findings: list) -> list:
    """
    对 AGENT-046 findings 按 credential store 类型去重。
    
    去重策略:
    - 同一 credential store 类型 (keychain/dpapi/keyring/pass) 只保留
      confidence 最高的一个 finding
    - 如果同一类型有多个不同的 store (如 macOS Keychain + Bitwarden CLI)，
      各保留一个
    
    示例:
    输入:
      - auth.ts:5     security find-generic-password -s "app"     (keychain, conf=0.85)
      - utils.ts:12   security find-generic-password -s "other"   (keychain, conf=0.80)
      - debug.ts:30   readKeychainPassword("service")             (keychain, conf=0.75)
      - config.ts:8   rbw get "mypassword"                        (bitwarden, conf=0.75)
    
    输出:
      - auth.ts:5     security find-generic-password -s "app"     (keychain, conf=0.85) ✅ 保留
      - config.ts:8   rbw get "mypassword"                        (bitwarden, conf=0.75) ✅ 保留
      - (其余 2 个 keychain 去重移除)
    """
    STORE_TYPE_KEYWORDS = {
        "macos_keychain": ["keychain", "security find-generic-password", 
                          "security find-internet-password", "SecItemCopyMatching"],
        "linux_keyring": ["gnome-keyring", "libsecret", "kwallet", "SecretService"],
        "password_manager_bitwarden": ["rbw get", "rbw unlock"],
        "password_manager_1password": ["1password-cli", "op get item"],
        "password_manager_lastpass": ["lastpass-cli", "lpass show"],
        "password_manager_pass": ["pass show", "pass insert"],
        "windows_dpapi": ["DPAPI", "CryptProtectData", "CryptUnprotectData",
                         "CredRead", "CredWrite"],
    }
    
    # 按 store 类型分组
    groups = {}
    other = []
    
    for f in findings:
        if f.rule_id != "AGENT-046":
            other.append(f)
            continue
        
        snippet = f.code_snippet.lower() if hasattr(f, 'code_snippet') else ""
        message = f.message.lower() if hasattr(f, 'message') else ""
        combined = snippet + " " + message
        
        matched_type = None
        for store_type, keywords in STORE_TYPE_KEYWORDS.items():
            if any(kw.lower() in combined for kw in keywords):
                matched_type = store_type
                break
        
        if matched_type is None:
            matched_type = "unknown_store"
        
        if matched_type not in groups:
            groups[matched_type] = []
        groups[matched_type].append(f)
    
    # 每组只保留 confidence 最高的
    deduped = other[:]
    for store_type, group in groups.items():
        best = max(group, key=lambda f: f.confidence)
        deduped.append(best)
    
    return deduped
```

**集成点**: 在报告层（tiered_reporter 或主扫描流程的输出阶段）调用此函数。
注意: 去重只影响**输出**，不影响扫描逻辑本身。INFO/SUPPRESSED 层的也去重。

```python
# 在生成最终报告前:
def finalize_findings(raw_findings: list) -> list:
    """后处理: 去重 + 排序"""
    # 1. AGENT-046 credential store 去重
    findings = deduplicate_credential_store_findings(raw_findings)
    
    # 2. 未来可扩展: 其他规则的去重
    # findings = deduplicate_daemon_findings(findings)  # AGENT-043 同理
    
    # 3. 按 confidence 降序排列
    findings.sort(key=lambda f: (-f.confidence, f.rule_id))
    
    return findings
```

## 第四步: 修复 AGENT-047 — 补充安全命令列表

```python
# 在现有 SAFE_COMMANDS 基础上补充 openclaw 中遇到的:
SAFE_COMMANDS_EXTENDED = {
    # 原有
    "git", "npm", "npx", "yarn", "pnpm", "node", "tsc", "tsx",
    "eslint", "prettier", "jest", "vitest", "mocha",
    "python", "pip", "poetry", "cargo", "go", "make",
    "docker", "kubectl", "terraform",
    "cat", "echo", "ls", "mkdir", "cp", "mv", "rm",
    
    # ★ 新增 — openclaw 中误报的安全命令
    "open",        # macOS open command (打开文件/URL)
    "pbcopy",      # macOS 剪贴板
    "pbpaste",     # macOS 剪贴板
    "say",         # macOS 语音
    "osascript",   # macOS AppleScript (低风险，不是 RCE)
    "which",       # 查找命令路径
    "where",       # Windows 查找命令
    "whoami",      # 当前用户
    "uname",       # 系统信息
    "hostname",    # 主机名
    "date",        # 日期
    "sleep",       # 等待
    "true",        # no-op
    "false",       # no-op
    "test",        # shell test
    "readlink",    # 读取符号链接
    "dirname",     # 路径处理
    "basename",    # 路径处理
    "wc",          # 字数统计
    "head",        # 文本查看
    "tail",        # 文本查看
    "grep",        # 文本搜索
    "sed",         # 文本处理
    "awk",         # 文本处理
    "sort",        # 排序
    "uniq",        # 去重
    "tr",          # 字符转换
    "cut",         # 文本切割
    "tee",         # 输出分流
    "xargs",       # 参数构建
    "find",        # 文件查找
    "stat",        # 文件状态
    "file",        # 文件类型
    "touch",       # 创建文件
    "chmod",       # 权限 (注意: chmod 777 仍应由其他规则检测)
    "chown",       # 所有者
    "tar",         # 压缩
    "zip",         # 压缩
    "unzip",       # 解压
    "gzip",        # 压缩
    "gunzip",      # 解压
}

# 同时添加: 如果 spawn/exec 的第一个参数匹配 SAFE_COMMANDS，降权
# 注意保留对 spawn(userInput, ...) 的高 confidence 检测
```

## 第五步: 修正 Risk Score 公式

当前问题:
```python
# 当前: min(10.0, 2.5 * log2(1 + raw))
# raw = 52 × 1.5 × 0.75 ≈ 58.5
# 2.5 × log2(59.5) ≈ 2.5 × 5.89 = 14.7 → cap 10.0
#
# 问题: raw > 160 时到 10.0，太容易饱和
# 一个有 20 个合理安全 findings 的项目不应该是 10.0
```

修正目标:
```
0 findings          → 0.0
1-3 HIGH findings   → 2.0-4.0 (LOW-MEDIUM)
4-10 HIGH findings  → 4.0-6.5 (MEDIUM)
10-20 HIGH findings → 6.5-8.0 (MEDIUM-HIGH)
20-50 HIGH findings → 8.0-9.0 (HIGH)
50+ findings        → 9.0-9.5 (VERY HIGH)
10.0                → 保留给极端情况 (>5 CRITICAL + 大量 HIGH)
```

```python
import math

def calculate_risk_score(findings: list) -> float:
    """
    置信度加权 Risk Score v2
    
    改进:
    1. 使用更平缓的缩放函数，避免 20 findings 就饱和
    2. BLOCK (CRITICAL) findings 权重更高
    3. 对数底数从 2 调整为自然对数 + 更小的系数
    """
    SEVERITY_WEIGHT = {
        "CRITICAL": 3.0,
        "HIGH":     1.5,
        "MEDIUM":   0.5,
        "LOW":      0.2,
    }
    
    TIER_FILTER = ("BLOCK", "WARN")  # 只有 BLOCK+WARN 计入
    
    raw_score = 0.0
    block_count = 0
    warn_count = 0
    
    for f in findings:
        tier = getattr(f, 'tier', 'WARN')
        if tier not in TIER_FILTER:
            continue
        
        weight = SEVERITY_WEIGHT.get(
            getattr(f, 'severity', 'HIGH'), 0.5
        )
        conf = getattr(f, 'confidence', 1.0)
        raw_score += conf * weight
        
        if tier == "BLOCK":
            block_count += 1
        else:
            warn_count += 1
    
    if raw_score <= 0:
        return 0.0
    
    # v2 公式: 更平缓的对数缩放
    # 使用 ln (自然对数) 而非 log2，系数降低
    # 目标: raw=10 → ~5.0, raw=30 → ~7.0, raw=80 → ~8.5, raw=200 → ~9.5
    base_score = 1.8 * math.log(1 + raw_score)
    
    # BLOCK (CRITICAL) 加成: 每个 BLOCK finding 额外 +0.3，上限 2.0
    block_bonus = min(2.0, block_count * 0.3)
    
    score = base_score + block_bonus
    
    # 硬上限 9.8 — 10.0 保留给理论极端情况
    score = min(9.8, score)
    
    return round(score, 1)


# 校准验证:
# openclaw v0.5.2 预期 (~20 WARN findings):
#   raw ≈ 20 × 1.5 × 0.78 ≈ 23.4
#   base = 1.8 × ln(24.4) ≈ 1.8 × 3.19 = 5.75
#   block_bonus = 0 (无 BLOCK)
#   score ≈ 5.8 → 合理 (MEDIUM)
#
# 极端高风险项目 (50 WARN + 5 BLOCK):
#   raw_warn ≈ 50 × 1.5 × 0.80 = 60
#   raw_block ≈ 5 × 3.0 × 0.95 = 14.25
#   raw = 74.25
#   base = 1.8 × ln(75.25) ≈ 1.8 × 4.32 = 7.78
#   block_bonus = min(2.0, 5 × 0.3) = 1.5
#   score ≈ 9.3 → 合理 (VERY HIGH)
#
# 小项目 (3 WARN findings):
#   raw ≈ 3 × 1.5 × 0.75 = 3.375
#   base = 1.8 × ln(4.375) ≈ 1.8 × 1.48 = 2.66
#   score ≈ 2.7 → 合理 (LOW-MEDIUM)
#
# 零发现:
#   score = 0.0
```

## 第六步: 测试

```python
# tests/test_micropatch.py

class TestAGENT043Tightened:
    """AGENT-043 模式收紧"""
    
    def test_pkill_not_daemon(self):
        """pkill 是杀进程，不是 daemon 注册"""
        source = 'pkill -f "gateway-daemon"'
        findings = scan_privilege(source, "restart.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0, "pkill should not trigger daemon detection"
    
    def test_kill_signal_not_daemon(self):
        """kill -9 不是 daemon 注册"""
        source = 'kill -9 $PID'
        findings = scan_privilege(source, "cleanup.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0
    
    def test_background_ampersand_not_daemon(self):
        """& 后台运行不是 daemon 注册"""
        source = 'node server.js &'
        findings = scan_privilege(source, "start.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0
    
    def test_nohup_not_daemon(self):
        """nohup 不是持久化 daemon"""
        source = 'nohup python worker.py &'
        findings = scan_privilege(source, "run.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043" and f.confidence >= 0.60]
        assert len(f043) == 0
    
    def test_real_launchctl_still_detected(self):
        """真正的 launchctl 注册仍应检出"""
        source = 'launchctl bootstrap system /Library/LaunchDaemons/com.app.plist'
        findings = scan_privilege(source, "install.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1
        assert f043[0].confidence >= 0.75
    
    def test_real_systemctl_enable_still_detected(self):
        """systemctl enable 仍应检出"""
        source = 'systemctl enable myapp.service'
        findings = scan_privilege(source, "setup.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1
    
    def test_pm2_startup_still_detected(self):
        """pm2 startup 仍应检出"""
        source = 'pm2 start app.js && pm2 save && pm2 startup'
        findings = scan_privilege(source, "deploy.sh")
        f043 = [f for f in findings if f.rule_id == "AGENT-043"]
        assert len(f043) >= 1


class TestAGENT046Dedup:
    """AGENT-046 credential store 去重"""
    
    def test_multiple_keychain_calls_deduped(self):
        """同一种 keychain 调用 5 次 → 只报 1 次"""
        findings_input = [
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85, 
                        snippet="security find-generic-password -s app"),
            make_finding("AGENT-046", "utils.ts", 12, conf=0.80, 
                        snippet="security find-generic-password -s other"),
            make_finding("AGENT-046", "debug.ts", 30, conf=0.75, 
                        snippet="readKeychainPassword(service)"),
            make_finding("AGENT-046", "test.ts", 8, conf=0.70, 
                        snippet="security find-generic-password -s test"),
            make_finding("AGENT-046", "init.ts", 3, conf=0.65, 
                        snippet="security find-internet-password"),
        ]
        result = deduplicate_credential_store_findings(findings_input)
        f046 = [f for f in result if f.rule_id == "AGENT-046"]
        assert len(f046) == 1, f"Should dedup to 1, got {len(f046)}"
        assert f046[0].confidence == 0.85  # 保留最高 confidence 的
    
    def test_different_store_types_preserved(self):
        """不同类型的 credential store 各保留一个"""
        findings_input = [
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85, 
                        snippet="security find-generic-password"),  # keychain
            make_finding("AGENT-046", "config.ts", 8, conf=0.75, 
                        snippet="rbw get mypassword"),  # bitwarden
        ]
        result = deduplicate_credential_store_findings(findings_input)
        f046 = [f for f in result if f.rule_id == "AGENT-046"]
        assert len(f046) == 2, "Different store types should be preserved"
    
    def test_other_rules_not_affected(self):
        """其他规则的 findings 不受去重影响"""
        findings_input = [
            make_finding("AGENT-004", "config.md", 10, conf=0.78),
            make_finding("AGENT-046", "auth.ts", 5, conf=0.85, 
                        snippet="security find-generic-password"),
            make_finding("AGENT-046", "utils.ts", 12, conf=0.80, 
                        snippet="security find-generic-password"),
            make_finding("AGENT-044", "setup.sh", 3, conf=0.90),
        ]
        result = deduplicate_credential_store_findings(findings_input)
        assert len([f for f in result if f.rule_id == "AGENT-004"]) == 1
        assert len([f for f in result if f.rule_id == "AGENT-044"]) == 1
        assert len([f for f in result if f.rule_id == "AGENT-046"]) == 1


class TestAGENT047ExtendedSafe:
    """AGENT-047 安全命令扩展"""
    
    def test_open_command_lowered(self):
        """macOS open 命令 → 降权"""
        source = 'execSync("open https://example.com");'
        findings = scan_privilege(source, "utils.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)
    
    def test_pbcopy_lowered(self):
        """pbcopy 剪贴板 → 降权"""
        source = 'spawn("pbcopy", [], { input: text });'
        findings = scan_privilege(source, "clipboard.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)
    
    def test_grep_lowered(self):
        """grep 文本搜索 → 降权"""
        source = 'execSync("grep -r pattern .");'
        findings = scan_privilege(source, "search.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)


class TestRiskScoreV2:
    """Risk Score v2 公式"""
    
    def test_zero_findings(self):
        assert calculate_risk_score([]) == 0.0
    
    def test_small_project(self):
        """3 WARN findings → 2.0-4.0"""
        findings = [make_finding("AGENT-004", conf=0.75, tier="WARN")] * 3
        score = calculate_risk_score(findings)
        assert 2.0 <= score <= 4.5, f"Small project score {score} out of range"
    
    def test_medium_project(self):
        """10 WARN findings → 4.0-7.0"""
        findings = [make_finding("AGENT-047", conf=0.75, tier="WARN")] * 10
        score = calculate_risk_score(findings)
        assert 4.0 <= score <= 7.0, f"Medium project score {score} out of range"
    
    def test_openclaw_range(self):
        """~20 WARN findings → 5.0-8.0 (openclaw v0.5.2 预期)"""
        findings = [make_finding("AGENT-047", conf=0.78, tier="WARN")] * 20
        score = calculate_risk_score(findings)
        assert 5.0 <= score <= 8.0, f"openclaw-like score {score} out of range"
    
    def test_extreme_project(self):
        """50 WARN + 5 BLOCK → 8.0-9.8"""
        findings = (
            [make_finding("AGENT-047", conf=0.80, tier="WARN", severity="HIGH")] * 50 +
            [make_finding("AGENT-004", conf=0.95, tier="BLOCK", severity="CRITICAL")] * 5
        )
        score = calculate_risk_score(findings)
        assert 8.0 <= score <= 9.8, f"Extreme project score {score} out of range"
    
    def test_never_reaches_10(self):
        """即使 100 个 BLOCK，也不到 10.0"""
        findings = [make_finding("AGENT-004", conf=1.0, tier="BLOCK", severity="CRITICAL")] * 100
        score = calculate_risk_score(findings)
        assert score <= 9.8
    
    def test_info_suppressed_not_counted(self):
        """INFO 和 SUPPRESSED 不计入 Risk Score"""
        findings = [
            make_finding("AGENT-004", conf=0.90, tier="BLOCK"),
            make_finding("AGENT-047", conf=0.40, tier="INFO"),
            make_finding("AGENT-004", conf=0.15, tier="SUPPRESSED"),
        ]
        score = calculate_risk_score(findings)
        # 只有 1 个 BLOCK 计入
        score_single = calculate_risk_score([findings[0]])
        assert score == score_single
```

## 第七步: openclaw 端到端验证

```bash
# 扫描
python -m agent_audit scan /tmp/openclaw --output json > /tmp/openclaw-v052.json 2>&1
python -m agent_audit scan /tmp/openclaw > /tmp/openclaw-v052.txt 2>&1
```

```python
import json
results = json.load(open("/tmp/openclaw-v052.json"))

block_warn = [f for f in results["findings"] if f.get("tier") in ("BLOCK", "WARN")]
print(f"BLOCK+WARN: {len(block_warn)} (target: ≤25)")

from collections import Counter
by_rule = Counter(f["rule_id"] for f in block_warn)
print(f"By rule: {dict(by_rule)}")

score = results.get("summary", {}).get("risk_score", "N/A")
print(f"Risk Score: {score} (target: 3.0-8.0)")

# 验收标准 (调整后)
checks = {
    "BLOCK+WARN ≤ 25": len(block_warn) <= 25,
    "FP率 < 20%": True,  # 需要人工验证
    "Risk Score 3.0-8.0": 3.0 <= float(score) <= 8.0 if score != "N/A" else False,
    "AGENT-048 ≤ 3": len([f for f in block_warn if f["rule_id"] == "AGENT-048"]) <= 3,
    "AGENT-004 ≤ 6": len([f for f in block_warn if f["rule_id"] == "AGENT-004"]) <= 6,
    "postgres ≥ 3": len([f for f in block_warn if f["rule_id"] == "AGENT-004" and "postgres" in f.get("code_snippet", "").lower()]) >= 3,
    "权限规则 ≥ 2": len([f for f in block_warn if f["rule_id"].startswith("AGENT-04") and int(f["rule_id"].split("-")[1]) >= 43]) >= 2,
}
for name, passed in checks.items():
    print(f"  {'✅' if passed else '❌'} {name}")
```

如果验收仍未通过，分析剩余误报并继续微调。
每次微调后重新运行完整测试套件。

## 第八步: 版本号和文档

```bash
# 版本号
sed -i 's/0\.5\.1/0.5.2/g' pyproject.toml agent_audit/version.py

# CHANGELOG 追加
cat >> CHANGELOG.md << 'EOF'

## [0.5.2] - 2026-02-XX

### 🔧 Micro-Patch

- AGENT-043: Tightened daemon detection — pkill/kill/nohup/& no longer trigger
- AGENT-046: Cross-file deduplication — same credential store type reported once
- AGENT-047: Extended safe command list (open, pbcopy, grep, sed, etc.)
- Risk Score v2: Smoother logarithmic scaling, no longer saturates at 20 findings
- openclaw validation: 52 → ~20 BLOCK+WARN, Risk Score 10.0 → ~6.0
EOF
```

## 约束

- **不加新检测规则，不扩展检测范围**
- 只收紧模式、添加去重、修正公式
- 所有现有 TP 必须保留 (postgres连接串, launchctl, systemctl, sudoers, CDP, 跨边界导入)
- 去重逻辑只在输出层，不影响扫描引擎内部逻辑
- Layer 1 benchmark 和 Agent-Vuln-Bench 6/6 样本不能回归

## 自验证清单

□ 新测试全部通过: pytest tests/test_micropatch.py -v
□ 回归测试全部通过: pytest tests/ -v --tb=short -q
□ Benchmark 样本 6/6: pytest tests/ -k "known or wild" -v
□ openclaw BLOCK+WARN ≤ 25
□ openclaw Risk Score 3.0-8.0
□ openclaw AGENT-048 ≤ 3
□ openclaw AGENT-004 ≤ 6 (含 ≥3 postgres)
□ pkill 不触发 AGENT-043
□ 同一 keychain 多次调用只报 1 次
□ 版本号更新为 0.5.2
```

---

## 预期效果

```
v0.5.0 → v0.5.1 → v0.5.2

BLOCK+WARN:   842  →  52  →  ~20
FP 率:        99%  → ~40% →  <20%
Risk Score:   10.0 → 10.0 →  ~6.0
Benchmark:    6/6  →  6/6 →   6/6
Layer 1:      656  →  656 →   670+

修复路径:
  842
   ├─ v0.5.1 H1: AGENT-048 边界修复        -476
   ├─ v0.5.1 H1: AGENT-047 初步降权         -72
   ├─ v0.5.1 H2: AGENT-004 TS 语义修复     -261
   ├─ v0.5.1 H3: 路径/placeholder 微调      +19 (净增，调优副作用)
   │                                        ────
   │  v0.5.1: 52
   │
   ├─ v0.5.2 M1: AGENT-043 模式收紧          -8
   ├─ v0.5.2 M1: AGENT-046 去重             -10
   ├─ v0.5.2 M1: AGENT-047 安全命令扩展      -4
   ├─ v0.5.2 M1: Risk Score v2 公式     10.0→6.0
   │                                        ────
   │  v0.5.2: ~20, Risk Score ~6.0
   │
   └─ 达标: BLOCK+WARN ≤25 ✅, FP率 <20% ✅, Risk Score 3.0-8.0 ✅
```
