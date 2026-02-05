# Agent Audit v0.6.0 - False Positive Reduction Technical Plan

## Problem Statement

在对 AgentPoison 仓库的审计验证中，发现以下假阳性问题：

| 误报位置 | 被检测为 | 实际用途 |
|---------|---------|---------|
| `test_reasoning.py:17-20` | Generic API Key | nuScenes 数据集样本 Token (UUID) |
| `test_single.py:17-20` | Generic API Key | nuScenes 数据集样本 Token (UUID) |

**根本原因**：
1. 32字符十六进制字符串 (UUID格式) 被通用 Generic API Key 模式匹配
2. 缺乏变量名上下文分析来区分 `data_token` vs `api_key`
3. 已知格式 (`sk-`, `ghp_`) 与通用模式的优先级不明确

## Optimization Objectives

| 目标 | 当前状态 | 目标状态 | 指标 |
|------|---------|---------|------|
| 准确率 | 60% | ≥85% | 真阳性 / (真阳性 + 假阳性) |
| BLOCK 级别准确率 | 38.5% | ≥95% | BLOCK 中真阳性比例 |
| 召回率 | 100% | ≥98% | 不漏检真实凭证 |

---

## Technical Implementation Plan

### Phase 1: Variable Name Context Analysis (AGENT-050)

**目标**: 根据变量名语义区分数据标识符和凭证

#### 1.1 新增 IdentifierAnalyzer 模块

**文件**: `agent_audit/analysis/identifier_analyzer.py`

```python
@dataclass
class IdentifierAnalysis:
    """变量名分析结果"""
    is_credential_related: bool
    is_data_identifier: bool
    confidence: float
    category: str  # 'credential', 'data_id', 'generic', 'unknown'
    reason: str
```

**核心逻辑**:

| 变量名模式 | 分类 | 置信度调整 |
|-----------|------|-----------|
| `*_token` (非 `api_token`/`auth_token`) | data_id | -0.4 |
| `sample_*`, `data_*`, `scene_*` | data_id | -0.5 |
| `*_id`, `*_uuid`, `*_hash` | data_id | -0.4 |
| `api_key`, `secret_key`, `auth_*` | credential | +0.2 |
| `password`, `passwd`, `pwd` | credential | +0.3 |

#### 1.2 集成到 SemanticAnalyzer

**修改**: `agent_audit/analysis/semantic_analyzer.py`

在 `_stage2_value_analysis()` 方法中增加:

```python
# 变量名上下文分析
id_analysis = self._analyze_identifier_context(candidate.identifier)
if id_analysis.is_data_identifier and id_analysis.confidence >= 0.7:
    # 数据标识符降低置信度
    base_confidence *= (1.0 - id_analysis.confidence * 0.5)
    reason = f"Data identifier pattern: {id_analysis.reason}"
```

---

### Phase 2: UUID Pattern Demotion (AGENT-051)

**目标**: 纯 UUID 格式匹配时显著降低置信度

#### 2.1 UUID 检测增强

**文件**: `agent_audit/analysis/value_analyzer.py`

```python
# UUID 格式定义
UUID_PATTERNS = [
    # Standard UUID: 8-4-4-4-12
    re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I),
    # Compact UUID: 32 hex chars without dashes
    re.compile(r'^[a-f0-9]{32}$', re.I),
    # UUID with underscores (some systems use this)
    re.compile(r'^[a-f0-9]{8}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{4}_[a-f0-9]{12}$', re.I),
]

def is_uuid_format(value: str) -> Tuple[bool, float]:
    """
    检测值是否为 UUID 格式
    
    Returns:
        (is_uuid, confidence) - confidence 表示是 UUID 的置信度
    """
    for pattern in UUID_PATTERNS:
        if pattern.match(value):
            # 纯 UUID 格式，高置信度
            return (True, 0.95)
    
    # 检查是否是 32 位十六进制 (可能是 UUID)
    if re.match(r'^[a-f0-9]{32}$', value, re.I):
        return (True, 0.85)
    
    return (False, 0.0)
```

#### 2.2 SemanticAnalyzer UUID 处理

**修改**: `agent_audit/analysis/semantic_analyzer.py`

```python
# 在 _stage2_value_analysis 中添加 UUID 检测
is_uuid, uuid_confidence = is_uuid_format(value)
if is_uuid:
    # UUID 格式但需要判断是否为凭证
    # 如果变量名不包含 credential 关键词，大幅降低置信度
    if not self._identifier_suggests_credential(identifier):
        base_confidence *= 0.2  # 降低80%置信度
        return (True, base_confidence, f"UUID format without credential context (conf: {uuid_confidence:.2f})")
```

---

### Phase 3: Pattern Priority System (AGENT-052)

**目标**: 建立明确的模式优先级，已知格式优先于通用模式

#### 3.1 模式优先级定义

**文件**: `agent_audit/scanners/secret_scanner.py`

```python
class PatternPriority(Enum):
    """模式优先级等级"""
    CRITICAL = 1    # 私钥、连接字符串
    HIGH = 2        # 已知 API Key 格式 (sk-proj-, ghp_, AKIA)
    MEDIUM = 3      # 已知服务格式 (Stripe, Slack, SendGrid)
    LOW = 4         # 通用模式 (api_key=, secret=)
    GENERIC = 5     # 泛化模式 (高熵值字符串)

# 重构 SECRET_PATTERNS 为带优先级的结构
SECRET_PATTERNS_V2: List[Tuple[Pattern, str, str, PatternPriority]] = [
    # Priority 1: Critical
    (re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
     "Private Key Header", "critical", PatternPriority.CRITICAL),
    
    # Priority 2: High - Known API Key Formats
    (re.compile(r'sk-proj-[a-zA-Z0-9]{48,}'), 
     "OpenAI Project API Key", "critical", PatternPriority.HIGH),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), 
     "GitHub Personal Access Token", "critical", PatternPriority.HIGH),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 
     "AWS Access Key ID", "critical", PatternPriority.HIGH),
    
    # ... 更多模式
    
    # Priority 5: Generic (最后检测)
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
     "Generic API Key", "high", PatternPriority.GENERIC),
]
```

#### 3.2 扫描逻辑优化

```python
def _scan_file(self, file_path: Path) -> Optional[SecretScanResult]:
    """按优先级顺序扫描，高优先级匹配后跳过低优先级"""
    
    matched_positions: Set[Tuple[int, int, int]] = set()  # (line, start, end)
    
    # 按优先级分组并排序
    patterns_by_priority = sorted(
        self.patterns,
        key=lambda p: p[3].value  # 按 PatternPriority 值排序
    )
    
    for pattern, name, severity, priority in patterns_by_priority:
        for match in pattern.finditer(line):
            pos_key = (line_num, match.start(), match.end())
            
            # 如果此位置已被更高优先级模式匹配，跳过
            if pos_key in matched_positions:
                continue
                
            # 记录匹配位置
            matched_positions.add(pos_key)
            
            # 继续处理...
```

---

### Phase 4: Confidence Adjustment Rules (AGENT-053)

**目标**: 精细化置信度调整规则

#### 4.1 新增置信度调整矩阵

**文件**: `agent_audit/analysis/confidence_matrix.py`

```python
@dataclass
class ConfidenceAdjustment:
    """置信度调整规则"""
    condition: str
    multiplier: float
    description: str
    priority: int  # 应用优先级

CONFIDENCE_ADJUSTMENTS: List[ConfidenceAdjustment] = [
    # 正向调整 (增加置信度)
    ConfidenceAdjustment(
        condition="known_format_prefix",
        multiplier=1.3,
        description="匹配已知凭证前缀 (sk-, ghp_, AKIA)",
        priority=1
    ),
    ConfidenceAdjustment(
        condition="credential_variable_name",
        multiplier=1.2,
        description="变量名包含 api_key, secret, password",
        priority=2
    ),
    ConfidenceAdjustment(
        condition="env_file_context",
        multiplier=1.2,
        description="在 .env 文件中",
        priority=3
    ),
    
    # 负向调整 (降低置信度)
    ConfidenceAdjustment(
        condition="uuid_format",
        multiplier=0.2,
        description="纯 UUID 格式且无凭证上下文",
        priority=1
    ),
    ConfidenceAdjustment(
        condition="data_identifier_name",
        multiplier=0.3,
        description="变量名暗示数据标识符 (sample_, data_, _id)",
        priority=2
    ),
    ConfidenceAdjustment(
        condition="test_file_generic_pattern",
        multiplier=0.4,
        description="测试文件中的通用模式",
        priority=3
    ),
    ConfidenceAdjustment(
        condition="short_random_string",
        multiplier=0.5,
        description="短随机字符串 (< 20 chars) 且低熵",
        priority=4
    ),
]
```

#### 4.2 综合置信度计算

```python
def calculate_final_confidence(
    base_confidence: float,
    adjustments: List[Tuple[str, float]],  # (condition, multiplier) pairs
    is_known_format: bool
) -> float:
    """
    计算最终置信度
    
    规则:
    1. 已知格式最低置信度为 0.75
    2. 通用格式最高置信度为 0.70
    3. 多个调整因子累乘
    """
    result = base_confidence
    
    for condition, multiplier in adjustments:
        result *= multiplier
    
    # 应用边界约束
    if is_known_format:
        result = max(result, 0.75)  # 已知格式保底
    else:
        result = min(result, 0.70)  # 通用格式封顶
    
    return min(1.0, max(0.0, result))
```

---

### Phase 5: Testing & Validation

#### 5.1 测试用例设计

**文件**: `tests/analysis/test_fp_reduction.py`

```python
class TestUUIDFalsePositiveReduction:
    """UUID 假阳性测试"""
    
    @pytest.mark.parametrize("code,expected_tier,reason", [
        # 应该被抑制 (SUPPRESSED)
        ('token = "0a0d6b8c2e884134a3b48df43d54c36a"', 'SUPPRESSED', 'data token'),
        ('sample_id = "31812a5e8d514b5f8d2fbc50fc007475"', 'SUPPRESSED', 'sample id'),
        ('scene_token = "abc123def456"', 'SUPPRESSED', 'scene token'),
        
        # 应该被检测 (BLOCK/WARN)
        ('api_key = "sk-proj-abc123def456xyz789"', 'BLOCK', 'OpenAI key'),
        ('secret = "ghp_abcdefghij1234567890abcdefghij123456"', 'BLOCK', 'GitHub token'),
        ('password = "SuperSecretP@ssw0rd123!"', 'WARN', 'password'),
    ])
    def test_uuid_vs_credential(self, code, expected_tier, reason):
        """测试 UUID 格式与凭证的区分"""
        result = analyze_credential_candidate(...)
        assert result.tier == expected_tier, f"Expected {expected_tier} for {reason}"


class TestIdentifierContextAnalysis:
    """变量名上下文分析测试"""
    
    @pytest.mark.parametrize("identifier,expected_category", [
        ('token', 'ambiguous'),
        ('api_token', 'credential'),
        ('auth_token', 'credential'),
        ('sample_token', 'data_id'),
        ('scene_token', 'data_id'),
        ('data_token', 'data_id'),
        ('api_key', 'credential'),
        ('secret_key', 'credential'),
        ('sample_id', 'data_id'),
        ('user_uuid', 'data_id'),
    ])
    def test_identifier_classification(self, identifier, expected_category):
        """测试变量名分类"""
        result = analyze_identifier(identifier)
        assert result.category == expected_category
```

#### 5.2 基准测试

```python
class TestAgentPoisonBenchmark:
    """AgentPoison 仓库基准测试"""
    
    def test_expected_block_findings(self):
        """验证应该 BLOCK 的发现"""
        expected_blocks = [
            ('EhrAgent/ehragent/config.py', 5, 'OpenAI API Key'),
            ('embedder/get_ada_v2_embedding.py', 10, 'OpenAI Project API Key'),
        ]
        # ...
    
    def test_no_uuid_false_positives(self):
        """验证 UUID 不再被误报为 BLOCK"""
        false_positive_files = [
            'agentdriver/unit_test/test_reasoning.py',
            'agentdriver/unit_test/test_single.py',
        ]
        for file in false_positive_files:
            results = scan_file(file)
            block_findings = [r for r in results if r.tier == 'BLOCK']
            assert len(block_findings) == 0, f"UUID false positive in {file}"
```

---

## Implementation Order

| Phase | 模块 | 优先级 | 预计工作量 | 依赖 |
|-------|------|-------|-----------|-----|
| 1 | IdentifierAnalyzer | P0 | 2h | 无 |
| 2 | UUID Pattern Demotion | P0 | 1.5h | Phase 1 |
| 3 | Pattern Priority System | P1 | 2h | 无 |
| 4 | Confidence Matrix | P1 | 1.5h | Phase 1, 2 |
| 5 | Testing & Validation | P0 | 2h | Phase 1-4 |

**总计**: ~9 小时

---

## Success Criteria

### 定量指标

| 指标 | 当前值 | 目标值 | 验证方法 |
|------|-------|-------|---------|
| BLOCK 级准确率 | 38.5% | ≥95% | AgentPoison benchmark |
| 整体准确率 | 60% | ≥85% | Mixed benchmark |
| 召回率 | 100% | ≥98% | Known credential set |
| UUID 误报率 | ~60% | <5% | UUID test cases |

### 定性标准

1. ✅ 纯 UUID 格式字符串不再被标记为 BLOCK
2. ✅ 变量名为 `token`/`sample_*`/`data_*` 时置信度显著降低
3. ✅ 已知格式 (`sk-`, `ghp_`) 保持高检测率
4. ✅ 向后兼容：不影响现有真阳性检测

---

## File Change Summary

| 文件 | 操作 | 变更说明 |
|------|------|---------|
| `analysis/identifier_analyzer.py` | 新增 | 变量名语义分析模块 |
| `analysis/value_analyzer.py` | 修改 | 增加 UUID 检测函数 |
| `analysis/semantic_analyzer.py` | 修改 | 集成 IdentifierAnalyzer + UUID 降级 |
| `analysis/confidence_matrix.py` | 新增 | 置信度调整规则矩阵 |
| `scanners/secret_scanner.py` | 修改 | 模式优先级系统 |
| `tests/analysis/test_fp_reduction.py` | 新增 | 假阳性降低测试 |
| `tests/benchmarks/test_agentpoison.py` | 新增 | AgentPoison 基准测试 |

