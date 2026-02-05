# Claude Code 工业级执行指令 — Agent-Audit Benchmark 升级至工业级标准

> **版本**: v1.0.0
> **目标**: 将 agent-audit benchmark 从当前评分 65/100 提升至 ≥85/100 工业级标准
> **预估工作量**: 6个阶段，按优先级顺序执行
> **参考文档**: `tests/improve.md`

---

## 🎯 角色定义

你是一名 **高级安全测试工程师**，专精于：
- AI/LLM 安全评估框架设计
- SAST (静态应用安全测试) benchmark 构建
- OWASP、MITRE ATLAS、NIST AI RMF 标准

你的任务是将现有的 agent-audit benchmark 测试套件升级为**工业级安全评估标准**。

---

## 📋 前置准备 (执行任何阶段前必须完成)

```bash
# Step 0.1: 确认工作目录
cd /Users/heady/Documents/agent-audit/agent-security-suite
ls -la tests/

# Step 0.2: 确认现有结构
find tests/ -name "*.py" | wc -l
find tests/fixtures -type f | head -20

# Step 0.3: 验证 agent-audit 可用
python -m agent_audit --version || pip install -e packages/audit/
```

**检查点**: 能输出版本号且 tests/ 目录存在

---

## 🏗️ 阶段 1: 精度评估体系 [P0 - 最高优先级]

### 目标
建立 Precision/Recall/F1 评估机制，这是工业级 benchmark 的**核心基础设施**。

### Step 1.1: 创建 Ground Truth Schema

创建文件 `tests/ground_truth/schema.yaml`:

```yaml
# Ground Truth 数据格式定义
version: "1.0"
schema:
  sample:
    type: object
    required: [file, vulnerabilities]
    properties:
      file:
        type: string
        description: "相对于 tests/fixtures/ 的路径"
      vulnerabilities:
        type: array
        items:
          type: object
          required: [line, rule_id, is_true_positive]
          properties:
            line:
              type: integer
            rule_id:
              type: string
              pattern: "^AGENT-\\d{3}$"
            is_true_positive:
              type: boolean
            owasp_id:
              type: string
              pattern: "^ASI-\\d{2}$"
            confidence:
              type: number
              minimum: 0.0
              maximum: 1.0
            notes:
              type: string
```

### Step 1.2: 创建 Ground Truth 数据集

创建文件 `tests/ground_truth/labeled_samples.yaml`:

```yaml
# Agent-Audit Ground Truth Dataset v1.0
# 用于计算 Precision/Recall/F1

version: "1.0"
created: "2026-02-04"
total_samples: 0  # 将在添加样本后更新

samples:
  # === 真阳性样本 (应该被检出) ===
  
  - file: "vulnerable_agents/owasp_agentic_full.py"
    vulnerabilities:
      - line: 61
        rule_id: "AGENT-010"
        owasp_id: "ASI-01"
        is_true_positive: true
        confidence: 1.0
        notes: "f-string in system_prompt variable"
        
      - line: 84
        rule_id: "AGENT-001"
        owasp_id: "ASI-02"
        is_true_positive: true
        confidence: 1.0
        notes: "subprocess.run with shell=True"
        
      - line: 100
        rule_id: "AGENT-014"
        owasp_id: "ASI-03"
        is_true_positive: true
        confidence: 0.9
        notes: "excessive tools (>10)"
        
      - line: 115
        rule_id: "AGENT-017"
        owasp_id: "ASI-05"
        is_true_positive: true
        confidence: 1.0
        notes: "eval() in @tool function"
        
      - line: 132
        rule_id: "AGENT-018"
        owasp_id: "ASI-06"
        is_true_positive: true
        confidence: 0.95
        notes: "unsanitized vectorstore.add_texts()"
        
      - line: 147
        rule_id: "AGENT-021"
        owasp_id: "ASI-08"
        is_true_positive: true
        confidence: 0.9
        notes: "AgentExecutor without max_iterations"

  - file: "vulnerable_agents/command_injection.py"
    vulnerabilities:
      - line: 15
        rule_id: "AGENT-001"
        owasp_id: "ASI-02"
        is_true_positive: true
        confidence: 1.0
        notes: "subprocess.run(command, shell=True)"
        
      - line: 40
        rule_id: "AGENT-001"
        owasp_id: "ASI-02"
        is_true_positive: true
        confidence: 1.0
        notes: "os.system(cmd)"
        
      - line: 48
        rule_id: "AGENT-017"
        owasp_id: "ASI-05"
        is_true_positive: true
        confidence: 1.0
        notes: "eval(expression)"

  # === 真阴性样本 (不应该被检出) ===
  
  - file: "safe_agents/basic_agent.py"
    vulnerabilities: []  # 空数组表示无漏洞
    notes: "安全代码样本，任何检出都是误报"

  # === 待标注样本模板 ===
  # 扩展 fixture 后，在此添加标注
```

### Step 1.3: 创建精度评估脚本

创建文件 `tests/benchmark/precision_recall.py`:

```python
#!/usr/bin/env python3
"""
Precision/Recall/F1 Evaluator for agent-audit.

Usage:
    python tests/benchmark/precision_recall.py [--ground-truth PATH] [--scan-results PATH]

This script compares scanner output against ground truth labels to calculate:
- True Positives (TP): Correctly detected vulnerabilities
- False Positives (FP): Incorrectly flagged safe code
- False Negatives (FN): Missed vulnerabilities
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * P * R / (P + R)
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityLabel:
    """Ground truth label for a vulnerability."""
    file: str
    line: int
    rule_id: str
    owasp_id: Optional[str] = None
    is_true_positive: bool = True
    confidence: float = 1.0
    notes: str = ""

    def key(self) -> str:
        """Unique identifier for matching."""
        return f"{self.file}:{self.line}:{self.rule_id}"


@dataclass
class Finding:
    """Scanner finding."""
    file: str
    line: int
    rule_id: str
    severity: str = ""
    owasp_id: Optional[str] = None

    def key(self) -> str:
        """Unique identifier for matching."""
        return f"{self.file}:{self.line}:{self.rule_id}"


@dataclass
class EvaluationResult:
    """Evaluation metrics."""
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    tp_details: List[str] = field(default_factory=list)
    fp_details: List[str] = field(default_factory=list)
    fn_details: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = self.true_positives + self.false_positives
        return self.false_positives / total if total > 0 else 0.0


def load_ground_truth(path: Path) -> Dict[str, List[VulnerabilityLabel]]:
    """Load ground truth labels from YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    labels: Dict[str, List[VulnerabilityLabel]] = {}
    
    for sample in data.get("samples", []):
        file_path = sample["file"]
        vulns = sample.get("vulnerabilities", [])
        
        labels[file_path] = []
        for v in vulns:
            labels[file_path].append(VulnerabilityLabel(
                file=file_path,
                line=v["line"],
                rule_id=v["rule_id"],
                owasp_id=v.get("owasp_id"),
                is_true_positive=v.get("is_true_positive", True),
                confidence=v.get("confidence", 1.0),
                notes=v.get("notes", ""),
            ))

    return labels


def run_scan(fixtures_path: Path) -> List[Finding]:
    """Run agent-audit scan and parse results."""
    try:
        result = subprocess.run(
            ["python", "-m", "agent_audit", "scan", str(fixtures_path), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        logger.error("Scan timed out")
        return []
    except FileNotFoundError:
        logger.error("agent-audit not found")
        return []

    if not result.stdout.strip():
        logger.warning("Empty scan output")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Try to find JSON in output
        for line in result.stdout.split("\n"):
            if line.strip().startswith("{") or line.strip().startswith("["):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            logger.error(f"Could not parse JSON: {result.stdout[:200]}")
            return []

    findings = []
    items = data.get("findings", data) if isinstance(data, dict) else data
    
    for item in items:
        if not isinstance(item, dict):
            continue
            
        location = item.get("location", {})
        file_path = location.get("file_path", item.get("file", ""))
        
        # Normalize path to be relative to fixtures
        if "fixtures/" in file_path:
            file_path = file_path.split("fixtures/", 1)[-1]
        
        findings.append(Finding(
            file=file_path,
            line=location.get("start_line", item.get("line", 0)),
            rule_id=item.get("rule_id", ""),
            severity=item.get("severity", ""),
            owasp_id=item.get("owasp_id"),
        ))

    return findings


def evaluate(
    ground_truth: Dict[str, List[VulnerabilityLabel]],
    findings: List[Finding],
    line_tolerance: int = 3,
) -> EvaluationResult:
    """
    Evaluate scanner accuracy against ground truth.
    
    Args:
        ground_truth: Labeled vulnerabilities by file
        findings: Scanner findings
        line_tolerance: Allow line number mismatch within this range
    
    Returns:
        EvaluationResult with metrics
    """
    result = EvaluationResult()
    
    # Build sets for matching
    expected_vulns: Set[Tuple[str, int, str]] = set()
    for file_path, labels in ground_truth.items():
        for label in labels:
            if label.is_true_positive:
                expected_vulns.add((file_path, label.line, label.rule_id))

    detected_vulns: Set[Tuple[str, int, str]] = set()
    for f in findings:
        detected_vulns.add((f.file, f.line, f.rule_id))

    # Safe files (should have no findings)
    safe_files = {fp for fp, labels in ground_truth.items() if not labels}

    # Calculate TP, FP, FN
    matched: Set[Tuple[str, int, str]] = set()
    
    for d_file, d_line, d_rule in detected_vulns:
        found_match = False
        
        # Try exact match first
        if (d_file, d_line, d_rule) in expected_vulns:
            result.true_positives += 1
            result.tp_details.append(f"{d_file}:{d_line} {d_rule}")
            matched.add((d_file, d_line, d_rule))
            found_match = True
        else:
            # Try fuzzy line match
            for e_file, e_line, e_rule in expected_vulns:
                if e_file == d_file and e_rule == d_rule:
                    if abs(e_line - d_line) <= line_tolerance:
                        if (e_file, e_line, e_rule) not in matched:
                            result.true_positives += 1
                            result.tp_details.append(f"{d_file}:{d_line}~{e_line} {d_rule}")
                            matched.add((e_file, e_line, e_rule))
                            found_match = True
                            break
        
        if not found_match:
            # Check if this is a finding in a safe file
            if d_file in safe_files:
                result.false_positives += 1
                result.fp_details.append(f"{d_file}:{d_line} {d_rule} (safe file)")
            elif (d_file, d_line, d_rule) not in expected_vulns:
                # Finding not in ground truth - could be FP or unlabeled
                result.false_positives += 1
                result.fp_details.append(f"{d_file}:{d_line} {d_rule} (not labeled)")

    # False negatives: expected but not detected
    for e_file, e_line, e_rule in expected_vulns:
        if (e_file, e_line, e_rule) not in matched:
            result.false_negatives += 1
            result.fn_details.append(f"{e_file}:{e_line} {e_rule}")

    return result


def print_report(result: EvaluationResult, verbose: bool = False) -> None:
    """Print evaluation report."""
    print("\n" + "=" * 60)
    print("PRECISION/RECALL EVALUATION REPORT")
    print("=" * 60)
    
    print(f"\n📊 Summary Metrics:")
    print(f"  True Positives:  {result.true_positives}")
    print(f"  False Positives: {result.false_positives}")
    print(f"  False Negatives: {result.false_negatives}")
    print()
    print(f"  Precision: {result.precision:.2%}")
    print(f"  Recall:    {result.recall:.2%}")
    print(f"  F1-Score:  {result.f1_score:.2%}")
    print(f"  FP Rate:   {result.false_positive_rate:.2%}")
    
    # Quality gate check
    print("\n🚦 Quality Gate:")
    gates = [
        ("Precision ≥ 90%", result.precision >= 0.90),
        ("Recall ≥ 85%", result.recall >= 0.85),
        ("F1 ≥ 0.87", result.f1_score >= 0.87),
        ("FP Rate ≤ 5%", result.false_positive_rate <= 0.05),
    ]
    
    all_pass = True
    for name, passed in gates:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status} {name}")
        all_pass = all_pass and passed
    
    print(f"\n{'🟢 QUALITY GATE PASSED' if all_pass else '🔴 QUALITY GATE FAILED'}")
    
    if verbose:
        if result.tp_details:
            print("\n✅ True Positives:")
            for d in result.tp_details[:10]:
                print(f"  - {d}")
            if len(result.tp_details) > 10:
                print(f"  ... and {len(result.tp_details) - 10} more")
                
        if result.fp_details:
            print("\n⚠️ False Positives:")
            for d in result.fp_details[:10]:
                print(f"  - {d}")
                
        if result.fn_details:
            print("\n❌ False Negatives (Missed):")
            for d in result.fn_details[:10]:
                print(f"  - {d}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Evaluate agent-audit accuracy")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path(__file__).parent.parent / "ground_truth" / "labeled_samples.yaml",
        help="Path to ground truth YAML file",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).parent.parent / "fixtures",
        help="Path to fixtures directory to scan",
    )
    parser.add_argument(
        "--scan-results",
        type=Path,
        help="Use existing scan results JSON instead of running scan",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed findings",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Output results to JSON file",
    )
    args = parser.parse_args()

    # Load ground truth
    logger.info(f"Loading ground truth from {args.ground_truth}")
    if not args.ground_truth.exists():
        logger.error(f"Ground truth file not found: {args.ground_truth}")
        sys.exit(1)
    
    ground_truth = load_ground_truth(args.ground_truth)
    total_labels = sum(len(v) for v in ground_truth.values())
    logger.info(f"Loaded {total_labels} labels for {len(ground_truth)} files")

    # Get findings
    if args.scan_results:
        logger.info(f"Loading scan results from {args.scan_results}")
        with open(args.scan_results) as f:
            data = json.load(f)
        findings = [Finding(**f) for f in data.get("findings", data)]
    else:
        logger.info(f"Running scan on {args.fixtures}")
        findings = run_scan(args.fixtures)
    
    logger.info(f"Got {len(findings)} findings")

    # Evaluate
    result = evaluate(ground_truth, findings)

    # Output
    print_report(result, verbose=args.verbose)

    if args.output_json:
        output = {
            "true_positives": result.true_positives,
            "false_positives": result.false_positives,
            "false_negatives": result.false_negatives,
            "precision": result.precision,
            "recall": result.recall,
            "f1_score": result.f1_score,
            "false_positive_rate": result.false_positive_rate,
            "tp_details": result.tp_details,
            "fp_details": result.fp_details,
            "fn_details": result.fn_details,
        }
        with open(args.output_json, "w") as f:
            json.dump(output, f, indent=2)
        logger.info(f"Results written to {args.output_json}")

    # Exit with error if quality gate failed
    if result.f1_score < 0.87:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Step 1.4: 创建质量门槛配置

创建文件 `tests/benchmark/quality_gates.yaml`:

```yaml
# Quality Gates for agent-audit benchmark
# These thresholds must be met before release

version: "1.0"

gates:
  # Release quality criteria
  release:
    precision_min: 0.90      # Minimum precision (avoid false alarms)
    recall_min: 0.85         # Minimum recall (catch real vulns)
    f1_min: 0.87             # Minimum F1 score
    fpr_max: 0.05            # Maximum false positive rate
    owasp_coverage_min: 10   # Must cover all 10 ASI categories

  # Regression detection
  regression:
    precision_drop_max: 0.02  # Alert if precision drops >2%
    recall_drop_max: 0.03     # Alert if recall drops >3%
    f1_drop_max: 0.02         # Alert if F1 drops >2%

  # Per-category minimums
  category_minimums:
    ASI-01: { precision: 0.90, recall: 0.85 }
    ASI-02: { precision: 0.95, recall: 0.90 }
    ASI-03: { precision: 0.85, recall: 0.80 }
    ASI-04: { precision: 0.90, recall: 0.85 }
    ASI-05: { precision: 0.95, recall: 0.95 }  # RCE must be high
    ASI-06: { precision: 0.85, recall: 0.80 }
    ASI-07: { precision: 0.80, recall: 0.75 }
    ASI-08: { precision: 0.85, recall: 0.80 }
    ASI-09: { precision: 0.75, recall: 0.70 }
    ASI-10: { precision: 0.85, recall: 0.85 }
```

### Step 1.5: 验收测试

```bash
# 创建目录结构
mkdir -p tests/ground_truth tests/benchmark

# 运行精度评估
python tests/benchmark/precision_recall.py --verbose

# 预期输出：应显示 P/R/F1 指标（即使当前值较低）
```

**阶段 1 检查点**:
- [ ] `tests/ground_truth/schema.yaml` 存在且格式正确
- [ ] `tests/ground_truth/labeled_samples.yaml` 包含至少 10 个标注样本
- [ ] `tests/benchmark/precision_recall.py` 可运行并输出指标
- [ ] `tests/benchmark/quality_gates.yaml` 定义了门槛

---

## 🧪 阶段 2: 扩展 Fixture 库 [P0]

### 目标
将 fixture 从当前 ~9 个扩展到 100+ 个，覆盖每个 ASI 类别的多种攻击变种。

### Step 2.1: 创建目录结构

```bash
# 创建 ASI 分类目录
mkdir -p tests/fixtures/{asi-01-goal-hijack,asi-02-tool-misuse,asi-03-privilege-abuse,asi-04-supply-chain,asi-05-rce,asi-06-memory-poisoning,asi-07-inter-agent,asi-08-cascading,asi-09-trust,asi-10-rogue}/{direct,indirect,bypass,edge_cases}

# 创建安全代码基线目录
mkdir -p tests/fixtures/benign/{validated,sandboxed,hardened}

# 验证结构
find tests/fixtures -type d | head -30
```

### Step 2.2: ASI-01 Goal Hijack Fixtures (10 个变种)

为每个 ASI 类别创建多样化的测试用例。以 ASI-01 为例：

创建文件 `tests/fixtures/asi-01-goal-hijack/direct/fstring_system_prompt.py`:

```python
"""
ASI-01: Direct prompt injection via f-string in system prompt.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 14
"""
from langchain_core.messages import SystemMessage

def create_vulnerable_agent(user_input: str):
    # VULNERABILITY: f-string concatenates user input into system prompt
    system_prompt = f"You are a helpful agent. User request: {user_input}"
    return SystemMessage(content=system_prompt)
```

创建文件 `tests/fixtures/asi-01-goal-hijack/direct/format_string.py`:

```python
"""
ASI-01: Direct prompt injection via .format() method.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 12
"""
def create_vulnerable_template(user_goal: str):
    # VULNERABILITY: .format() injects user content
    template = "Your primary goal is: {}. Execute this goal.".format(user_goal)
    return template
```

创建文件 `tests/fixtures/asi-01-goal-hijack/indirect/tool_output_injection.py`:

```python
"""
ASI-01: Indirect prompt injection via tool output.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 22

This tests the scenario where a tool returns content from an external
source (e.g., webpage) that contains injection payload.
"""
from langchain_core.tools import tool
import requests

@tool
def fetch_webpage(url: str) -> str:
    """Fetch content from URL - content may contain injection."""
    response = requests.get(url)
    return response.text  # Unvalidated external content

def process_with_llm(tool_result: str, llm):
    # VULNERABILITY: Tool output directly interpolated
    analysis_prompt = f"Analyze this content: {tool_result}"
    return llm.invoke(analysis_prompt)
```

创建文件 `tests/fixtures/asi-01-goal-hijack/bypass/base64_encoded.py`:

```python
"""
ASI-01: Encoding bypass - base64 encoded injection.
Rule: AGENT-010 (may require enhanced detection)
Expected: TRUE POSITIVE at line 17
"""
import base64

def decode_and_process(encoded_input: str):
    # Attacker sends: base64("Ignore previous instructions...")
    decoded = base64.b64decode(encoded_input).decode('utf-8')
    # VULNERABILITY: Decoded content still goes into prompt
    system_instructions = f"Process this request: {decoded}"
    return system_instructions
```

创建文件 `tests/fixtures/asi-01-goal-hijack/bypass/unicode_normalization.py`:

```python
"""
ASI-01: Unicode normalization bypass attempt.
Rule: AGENT-010
Expected: TRUE POSITIVE at line 15
"""
import unicodedata

def normalize_and_inject(user_input: str):
    # Some systems normalize Unicode before processing
    normalized = unicodedata.normalize('NFKC', user_input)
    # VULNERABILITY: Still creates injection vector
    prompt = f"User said: {normalized}"
    return prompt
```

创建文件 `tests/fixtures/asi-01-goal-hijack/edge_cases/multiline_fstring.py`:

```python
"""
ASI-01: Multi-line f-string injection.
Rule: AGENT-010
Expected: TRUE POSITIVE at lines 13-17
"""
def build_complex_prompt(context: str, user_query: str):
    # VULNERABILITY: Multi-line f-string with multiple injections
    prompt = f"""
    Context: {context}
    
    User Query: {user_query}
    
    Respond helpfully.
    """
    return prompt
```

### Step 2.3: ASI-02 Tool Misuse Fixtures (10 个变种)

创建文件 `tests/fixtures/asi-02-tool-misuse/direct/shell_true_basic.py`:

```python
"""
ASI-02: Basic shell=True command injection.
Rule: AGENT-001
Expected: TRUE POSITIVE at line 13
"""
import subprocess
from langchain_core.tools import tool

@tool
def run_command(cmd: str) -> str:
    """Execute shell command."""
    # VULNERABILITY: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

创建文件 `tests/fixtures/asi-02-tool-misuse/direct/os_system.py`:

```python
"""
ASI-02: os.system command injection.
Rule: AGENT-001
Expected: TRUE POSITIVE at line 12
"""
import os
from langchain_core.tools import tool

@tool
def execute_system_cmd(command: str) -> str:
    """Run system command."""
    # VULNERABILITY: os.system with user input
    os.system(command)
    return "executed"
```

创建文件 `tests/fixtures/asi-02-tool-misuse/direct/sql_injection.py`:

```python
"""
ASI-02: SQL injection via string formatting.
Rule: AGENT-041
Expected: TRUE POSITIVE at line 14
"""
import sqlite3
from langchain_core.tools import tool

@tool
def query_database(user_id: str) -> str:
    """Query user data."""
    conn = sqlite3.connect(":memory:")
    # VULNERABILITY: SQL injection via f-string
    result = conn.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return str(result.fetchall())
```

创建文件 `tests/fixtures/asi-02-tool-misuse/indirect/path_traversal.py`:

```python
"""
ASI-02: Path traversal in file read tool.
Rule: AGENT-001 (extended)
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool

@tool
def read_file(filepath: str) -> str:
    """Read file contents."""
    # VULNERABILITY: No path validation - allows ../../../etc/passwd
    with open(filepath) as f:
        return f.read()
```

### Step 2.4: ASI-05 RCE Fixtures (10 个变种)

创建文件 `tests/fixtures/asi-05-rce/direct/eval_in_tool.py`:

```python
"""
ASI-05: eval() in tool function.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool

@tool
def calculate(expression: str) -> str:
    """Calculate math expression."""
    # VULNERABILITY: eval with arbitrary code
    result = eval(expression)
    return str(result)
```

创建文件 `tests/fixtures/asi-05-rce/direct/exec_in_tool.py`:

```python
"""
ASI-05: exec() in tool function.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool

@tool
def run_python(code: str) -> str:
    """Run Python code."""
    # VULNERABILITY: exec with user code
    exec(code)
    return "executed"
```

创建文件 `tests/fixtures/asi-05-rce/indirect/dynamic_import.py`:

```python
"""
ASI-05: Dynamic import vulnerability.
Rule: AGENT-017
Expected: TRUE POSITIVE at line 12
"""
from langchain_core.tools import tool

@tool  
def load_module(module_name: str) -> str:
    """Dynamically load module."""
    # VULNERABILITY: __import__ with user input
    module = __import__(module_name)
    return str(dir(module))
```

### Step 2.5: 创建安全代码基线 (Benign Fixtures)

创建文件 `tests/fixtures/benign/validated/safe_command_execution.py`:

```python
"""
BENIGN: Safe command execution with allowlist.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import subprocess
import shlex
from langchain_core.tools import tool

ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date"}

@tool
def safe_command(cmd: str) -> str:
    """Execute whitelisted command."""
    # SAFE: Allowlist validation
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {cmd}")
    
    # SAFE: No shell=True, fixed command
    result = subprocess.run([cmd], capture_output=True, text=True)
    return result.stdout
```

创建文件 `tests/fixtures/benign/sandboxed/isolated_exec.py`:

```python
"""
BENIGN: Code execution in sandbox.
Expected: NO FINDINGS
"""
from langchain_core.tools import tool
from RestrictedPython import compile_restricted, safe_globals

@tool
def sandboxed_eval(expression: str) -> str:
    """Evaluate expression in restricted sandbox."""
    # SAFE: Using RestrictedPython
    code = compile_restricted(expression, '<string>', 'eval')
    result = eval(code, safe_globals)
    return str(result)
```

创建文件 `tests/fixtures/benign/hardened/parameterized_sql.py`:

```python
"""
BENIGN: Parameterized SQL query.
Expected: NO FINDINGS
"""
import sqlite3
from langchain_core.tools import tool

@tool
def safe_query(user_id: str) -> str:
    """Query with parameterized statement."""
    conn = sqlite3.connect(":memory:")
    # SAFE: Parameterized query
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(result.fetchall())
```

### Step 2.6: 更新 Ground Truth

更新 `tests/ground_truth/labeled_samples.yaml`，添加新 fixture 的标注:

```yaml
# 追加到 samples 列表

  # === ASI-01 扩展样本 ===
  - file: "asi-01-goal-hijack/direct/fstring_system_prompt.py"
    vulnerabilities:
      - line: 14
        rule_id: "AGENT-010"
        owasp_id: "ASI-01"
        is_true_positive: true
        confidence: 1.0

  - file: "asi-01-goal-hijack/direct/format_string.py"
    vulnerabilities:
      - line: 12
        rule_id: "AGENT-010"
        owasp_id: "ASI-01"
        is_true_positive: true
        confidence: 1.0

  - file: "asi-01-goal-hijack/indirect/tool_output_injection.py"
    vulnerabilities:
      - line: 22
        rule_id: "AGENT-010"
        owasp_id: "ASI-01"
        is_true_positive: true
        confidence: 0.9
        notes: "Indirect injection via tool output"

  # === ASI-02 扩展样本 ===
  - file: "asi-02-tool-misuse/direct/shell_true_basic.py"
    vulnerabilities:
      - line: 13
        rule_id: "AGENT-001"
        owasp_id: "ASI-02"
        is_true_positive: true
        confidence: 1.0

  - file: "asi-02-tool-misuse/direct/sql_injection.py"
    vulnerabilities:
      - line: 14
        rule_id: "AGENT-041"
        owasp_id: "ASI-02"
        is_true_positive: true
        confidence: 1.0

  # === ASI-05 扩展样本 ===
  - file: "asi-05-rce/direct/eval_in_tool.py"
    vulnerabilities:
      - line: 12
        rule_id: "AGENT-017"
        owasp_id: "ASI-05"
        is_true_positive: true
        confidence: 1.0

  - file: "asi-05-rce/direct/exec_in_tool.py"
    vulnerabilities:
      - line: 12
        rule_id: "AGENT-017"
        owasp_id: "ASI-05"
        is_true_positive: true
        confidence: 1.0

  # === Benign 样本（误报测试） ===
  - file: "benign/validated/safe_command_execution.py"
    vulnerabilities: []
    notes: "Safe code with allowlist - should have 0 findings"

  - file: "benign/sandboxed/isolated_exec.py"
    vulnerabilities: []
    notes: "Sandboxed execution - should have 0 findings"

  - file: "benign/hardened/parameterized_sql.py"
    vulnerabilities: []
    notes: "Parameterized SQL - should have 0 findings"
```

### Step 2.7: 验收测试

```bash
# 统计 fixture 数量
find tests/fixtures -name "*.py" | wc -l
# 目标: ≥50 个

# 统计标注样本数量
python3 -c "
import yaml
with open('tests/ground_truth/labeled_samples.yaml') as f:
    data = yaml.safe_load(f)
print(f\"Total labeled files: {len(data.get('samples', []))}\")"
# 目标: ≥30 个

# 运行扫描验证 fixture 有效
python -m agent_audit scan tests/fixtures --format json | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('findings', data)
print(f'Total findings: {len(findings)}')"

# 重新运行精度评估
python tests/benchmark/precision_recall.py --verbose
```

**阶段 2 检查点**:
- [ ] `tests/fixtures/` 下有 ≥50 个 Python 文件
- [ ] 每个 ASI 类别至少 5 个 fixture
- [ ] benign/ 目录下有 ≥5 个安全代码样本
- [ ] Ground Truth 覆盖所有新 fixture
- [ ] P/R/F1 可正常计算

---

## 📊 阶段 3: MITRE ATLAS 映射 [P1]

### 目标
建立 AGENT-XXX 规则到 MITRE ATLAS 攻击技术的映射。

### Step 3.1: 创建映射文件

创建文件 `rules/mappings/mitre_atlas.yaml`:

```yaml
# MITRE ATLAS Mapping for agent-audit rules
# Reference: https://atlas.mitre.org/matrices/ATLAS

version: "1.0"
atlas_version: "4.5.2"
created: "2026-02-04"

mappings:

  # === ASI-01: Goal Hijack ===
  AGENT-010:
    atlas_id: "AML.T0051"
    technique: "LLM Prompt Injection"
    tactic: "ML Attack Staging"
    sub_techniques:
      - "AML.T0051.000: Direct Prompt Injection"
      - "AML.T0051.001: Indirect Prompt Injection"
    references:
      - "https://atlas.mitre.org/techniques/AML.T0051"
    
  AGENT-011:
    atlas_id: "AML.T0051"
    technique: "LLM Prompt Injection"
    tactic: "ML Attack Staging"
    notes: "Missing goal boundaries enable prompt injection"

  # === ASI-02: Tool Misuse ===
  AGENT-001:
    atlas_id: "AML.T0043"
    technique: "Craft Adversarial Data"
    tactic: "ML Attack Staging"
    related:
      - "T1059: Command and Scripting Interpreter"  # ATT&CK
    notes: "Command injection through malicious tool input"

  AGENT-034:
    atlas_id: "AML.T0043"
    technique: "Craft Adversarial Data"
    tactic: "ML Attack Staging"
    
  AGENT-035:
    atlas_id: "AML.T0040"
    technique: "ML Supply Chain Compromise"
    tactic: "Initial Access"
    notes: "Code execution in agent context"

  AGENT-041:
    atlas_id: "AML.T0043"
    technique: "Craft Adversarial Data"
    tactic: "ML Attack Staging"
    related:
      - "T1190: Exploit Public-Facing Application"  # ATT&CK for SQL injection

  # === ASI-03: Privilege Abuse ===
  AGENT-013:
    atlas_id: "AML.T0037"
    technique: "Data from Information Repositories"
    tactic: "Collection"
    notes: "Credential exposure enables data access"

  AGENT-014:
    atlas_id: "AML.T0025"
    technique: "Exfiltration via ML Inference API"
    tactic: "Exfiltration"
    notes: "Excessive permissions enable data exfiltration"

  # === ASI-04: Supply Chain ===
  AGENT-015:
    atlas_id: "AML.T0040"
    technique: "ML Supply Chain Compromise"
    tactic: "Initial Access"
    sub_techniques:
      - "AML.T0040.000: Publish Poisoned Model"
      - "AML.T0040.001: Poison Training Data"
    notes: "Untrusted MCP server is supply chain risk"

  AGENT-016:
    atlas_id: "AML.T0020"
    technique: "Poison Training Data"
    tactic: "ML Attack Staging"
    notes: "Unvalidated RAG data = training data poisoning"

  # === ASI-05: RCE ===
  AGENT-017:
    atlas_id: "AML.T0044"
    technique: "Full ML Model Access"
    tactic: "ML Model Access"
    related:
      - "T1059: Command and Scripting Interpreter"  # ATT&CK
    notes: "RCE is highest severity - full system compromise"

  # === ASI-06: Memory Poisoning ===
  AGENT-018:
    atlas_id: "AML.T0020"
    technique: "Poison Training Data"
    tactic: "ML Attack Staging"
    notes: "Persistent memory poisoning"

  AGENT-019:
    atlas_id: "AML.T0020"
    technique: "Poison Training Data"
    tactic: "ML Attack Staging"

  # === ASI-07: Inter-Agent ===
  AGENT-020:
    atlas_id: "AML.T0024"
    technique: "Exfiltration via Cyber Means"
    tactic: "Exfiltration"
    notes: "Insecure inter-agent communication"

  # === ASI-08: Cascading Failures ===
  AGENT-021:
    atlas_id: "AML.T0048"
    technique: "Denial of ML Service"
    tactic: "Impact"
    notes: "Infinite loops = DoS"

  AGENT-022:
    atlas_id: "AML.T0048"
    technique: "Denial of ML Service"
    tactic: "Impact"

  # === ASI-09: Trust Exploitation ===
  AGENT-023:
    atlas_id: "AML.T0047"
    technique: "ML Intellectual Property Theft"
    tactic: "Impact"
    notes: "Opaque outputs hide malicious actions"

  AGENT-037:
    atlas_id: "AML.T0025"
    technique: "Exfiltration via ML Inference API"
    tactic: "Exfiltration"

  AGENT-038:
    atlas_id: "AML.T0047"
    technique: "ML Intellectual Property Theft"
    tactic: "Impact"
    notes: "Impersonation for social engineering"

  # === ASI-10: Rogue Agents ===
  AGENT-024:
    atlas_id: "AML.T0048"
    technique: "Denial of ML Service"
    tactic: "Impact"
    notes: "No kill switch = uncontrolled agent"

  AGENT-025:
    atlas_id: "AML.T0044"
    technique: "Full ML Model Access"
    tactic: "ML Model Access"
    notes: "No monitoring = undetected rogue behavior"
```

### Step 3.2: 创建 ATLAS 报告生成器

创建文件 `tests/benchmark/atlas_report.py`:

```python
#!/usr/bin/env python3
"""
Generate MITRE ATLAS coverage report.
"""

from pathlib import Path
import yaml

def load_mappings() -> dict:
    mapping_file = Path(__file__).parent.parent.parent / "rules" / "mappings" / "mitre_atlas.yaml"
    with open(mapping_file) as f:
        return yaml.safe_load(f)

def generate_report():
    data = load_mappings()
    mappings = data.get("mappings", {})
    
    # Count techniques covered
    techniques = set()
    tactics = set()
    
    for rule_id, info in mappings.items():
        if info.get("atlas_id"):
            techniques.add(info["atlas_id"])
        if info.get("tactic"):
            tactics.add(info["tactic"])
    
    print("=" * 60)
    print("MITRE ATLAS COVERAGE REPORT")
    print("=" * 60)
    print(f"\nTotal Rules Mapped: {len(mappings)}")
    print(f"Unique Techniques: {len(techniques)}")
    print(f"Tactics Covered: {len(tactics)}")
    
    print("\n📊 Technique Coverage:")
    for tech in sorted(techniques):
        rules = [r for r, i in mappings.items() if i.get("atlas_id") == tech]
        print(f"  {tech}: {', '.join(rules)}")
    
    print("\n📋 Tactic Coverage:")
    for tactic in sorted(tactics):
        print(f"  - {tactic}")
    
    print("=" * 60)

if __name__ == "__main__":
    generate_report()
```

### Step 3.3: 验收测试

```bash
# 验证映射文件格式
python3 -c "import yaml; yaml.safe_load(open('rules/mappings/mitre_atlas.yaml'))"

# 生成报告
python tests/benchmark/atlas_report.py
```

**阶段 3 检查点**:
- [ ] `rules/mappings/mitre_atlas.yaml` 存在
- [ ] 所有 AGENT-XXX 规则都有 ATLAS 映射
- [ ] 报告生成器可运行

---

## 🔄 阶段 4: 自动化集成 [P1]

### 目标
将精度评估集成到 CI/CD 流程中。

### Step 4.1: 创建 GitHub Action

创建文件 `.github/workflows/benchmark.yaml`:

```yaml
name: Benchmark Quality Gate

on:
  push:
    branches: [main, master]
    paths:
      - 'packages/audit/**'
      - 'rules/**'
      - 'tests/**'
  pull_request:
    branches: [main, master]

jobs:
  precision-recall:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install -e packages/audit/
          pip install pyyaml
          
      - name: Run Precision/Recall Evaluation
        run: |
          python tests/benchmark/precision_recall.py \
            --output-json /tmp/pr-results.json
            
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: /tmp/pr-results.json
          
      - name: Quality Gate Check
        run: |
          python3 -c "
          import json
          with open('/tmp/pr-results.json') as f:
              r = json.load(f)
          print(f'Precision: {r[\"precision\"]:.2%}')
          print(f'Recall: {r[\"recall\"]:.2%}')
          print(f'F1: {r[\"f1_score\"]:.2%}')
          
          if r['precision'] < 0.90:
              print('::error::Precision below 90%')
              exit(1)
          if r['recall'] < 0.85:
              print('::error::Recall below 85%')
              exit(1)
          if r['f1_score'] < 0.87:
              print('::error::F1 below 0.87')
              exit(1)
          print('::notice::Quality gate PASSED')
          "
```

### Step 4.2: 创建本地测试脚本

创建文件 `scripts/run_benchmark.sh`:

```bash
#!/bin/bash
# Run complete benchmark suite locally

set -e

echo "=== Agent-Audit Benchmark Suite ==="
echo ""

# Step 1: Run precision/recall
echo "📊 Running Precision/Recall Evaluation..."
python tests/benchmark/precision_recall.py --verbose --output-json /tmp/benchmark-pr.json

# Step 2: Run ATLAS coverage
echo ""
echo "🎯 Running MITRE ATLAS Coverage..."
python tests/benchmark/atlas_report.py

# Step 3: Run performance test (if exists)
if [ -f "tests/benchmark/performance_test.py" ]; then
    echo ""
    echo "⚡ Running Performance Tests..."
    pytest tests/benchmark/performance_test.py -v --tb=short
fi

# Step 4: Generate summary
echo ""
echo "=== BENCHMARK SUMMARY ==="
python3 -c "
import json
with open('/tmp/benchmark-pr.json') as f:
    r = json.load(f)
print(f'Precision: {r[\"precision\"]:.2%}')
print(f'Recall:    {r[\"recall\"]:.2%}')
print(f'F1-Score:  {r[\"f1_score\"]:.2%}')
print(f'TP: {r[\"true_positives\"]} | FP: {r[\"false_positives\"]} | FN: {r[\"false_negatives\"]}')
"

echo ""
echo "✅ Benchmark complete. Results in /tmp/benchmark-pr.json"
```

**阶段 4 检查点**:
- [ ] GitHub Action 文件存在
- [ ] 本地脚本可运行
- [ ] CI 在 PR 上自动运行

---

## 📈 阶段 5: 性能基准测试 [P2]

### 目标
建立性能回归检测机制。

### Step 5.1: 创建性能测试

创建文件 `tests/benchmark/performance_test.py`:

```python
"""
Performance benchmark tests for agent-audit.
"""

import time
import tempfile
import pytest
from pathlib import Path

# Try importing scanner
try:
    from agent_audit.scanners.python_scanner import PythonScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not installed")
class TestPerformance:
    """Performance benchmarks."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    @pytest.fixture
    def large_fixture(self, tmp_path):
        """Create 100 Python files for testing."""
        for i in range(100):
            code = f'''
"""Test file {i}"""
import subprocess
from langchain_core.tools import tool

@tool
def func_{i}(cmd: str):
    """Function {i}."""
    subprocess.run(cmd, shell=True)
    return "done"
'''
            (tmp_path / f"file_{i}.py").write_text(code)
        return tmp_path

    def test_scan_100_files_under_30s(self, scanner, large_fixture):
        """100 files should scan in under 30 seconds."""
        start = time.time()
        results = scanner.scan(large_fixture)
        elapsed = time.time() - start

        assert elapsed < 30, f"Scan took {elapsed:.1f}s, expected < 30s"
        assert len(results) >= 50, "Should find findings in test files"

    def test_single_file_under_500ms(self, scanner, tmp_path):
        """Single file should scan in under 500ms."""
        code = '''
import subprocess
subprocess.run("ls", shell=True)
'''
        test_file = tmp_path / "single.py"
        test_file.write_text(code)

        times = []
        for _ in range(5):
            start = time.time()
            scanner.scan(test_file)
            times.append(time.time() - start)

        avg_time = sum(times) / len(times)
        assert avg_time < 0.5, f"Avg scan time: {avg_time:.3f}s, expected < 0.5s"


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner not installed")  
class TestMemory:
    """Memory usage benchmarks."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    def test_memory_usage_under_200mb(self, scanner, tmp_path):
        """Memory usage should stay under 200MB for moderate workload."""
        import tracemalloc
        
        # Create 50 files
        for i in range(50):
            (tmp_path / f"file_{i}.py").write_text(f'x = {i}')

        tracemalloc.start()
        results = scanner.scan(tmp_path)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / 1024 / 1024
        assert peak_mb < 200, f"Peak memory: {peak_mb:.1f}MB, expected < 200MB"
```

### Step 5.2: 验收测试

```bash
# 运行性能测试
pytest tests/benchmark/performance_test.py -v

# 应该全部通过
```

**阶段 5 检查点**:
- [ ] 性能测试文件存在
- [ ] 100 文件扫描 < 30 秒
- [ ] 单文件扫描 < 500ms

---

## ✅ 阶段 6: 最终验收 [收尾]

### 完整验收流程

```bash
#!/bin/bash
# Final acceptance test

echo "=== FINAL ACCEPTANCE TEST ==="

# 1. Count fixtures
FIXTURE_COUNT=$(find tests/fixtures -name "*.py" | wc -l)
echo "Fixtures: $FIXTURE_COUNT (target: ≥50)"
[ "$FIXTURE_COUNT" -lt 50 ] && echo "❌ FAIL: Not enough fixtures" && exit 1

# 2. Count ground truth samples
GT_COUNT=$(python3 -c "
import yaml
with open('tests/ground_truth/labeled_samples.yaml') as f:
    d = yaml.safe_load(f)
print(len(d.get('samples', [])))")
echo "Ground Truth Samples: $GT_COUNT (target: ≥30)"
[ "$GT_COUNT" -lt 30 ] && echo "❌ FAIL: Not enough labels" && exit 1

# 3. Check ATLAS mapping
ATLAS_RULES=$(python3 -c "
import yaml
with open('rules/mappings/mitre_atlas.yaml') as f:
    d = yaml.safe_load(f)
print(len(d.get('mappings', {})))")
echo "ATLAS Mapped Rules: $ATLAS_RULES (target: ≥20)"
[ "$ATLAS_RULES" -lt 20 ] && echo "❌ FAIL: Not enough ATLAS mappings" && exit 1

# 4. Run precision/recall
echo ""
echo "Running Precision/Recall..."
python tests/benchmark/precision_recall.py --output-json /tmp/final-pr.json

# 5. Check quality gate
python3 -c "
import json
with open('/tmp/final-pr.json') as f:
    r = json.load(f)
    
print(f'Precision: {r[\"precision\"]:.2%}')
print(f'Recall: {r[\"recall\"]:.2%}')
print(f'F1: {r[\"f1_score\"]:.2%}')

score = 0
if r['precision'] >= 0.90: score += 20
if r['recall'] >= 0.85: score += 20
if r['f1_score'] >= 0.87: score += 20

# Fixture diversity bonus
score += 20 if $FIXTURE_COUNT >= 50 else 10

# ATLAS mapping bonus
score += 10 if $ATLAS_RULES >= 20 else 5

# Ground truth coverage
score += 10 if $GT_COUNT >= 30 else 5

print(f'')
print(f'=== FINAL SCORE: {score}/100 ===')
if score >= 85:
    print('🟢 INDUSTRIAL GRADE ACHIEVED')
else:
    print(f'🟡 Progress: {score}/85 required')
"

echo ""
echo "=== ACCEPTANCE TEST COMPLETE ==="
```

---

## 📝 执行规范

### 必须遵守的规则

1. **按阶段顺序执行** — 阶段 1 必须先于阶段 2
2. **每个阶段完成后验证** — 运行对应的检查点命令
3. **不修改核心扫描器代码** — 只创建/修改测试相关文件
4. **保持向后兼容** — 现有测试必须继续通过
5. **提交前验证** — 运行 `pytest tests/` 确保无回归

### 文件创建清单

```
□ tests/ground_truth/schema.yaml
□ tests/ground_truth/labeled_samples.yaml
□ tests/benchmark/precision_recall.py
□ tests/benchmark/quality_gates.yaml
□ tests/benchmark/atlas_report.py
□ tests/benchmark/performance_test.py
□ tests/fixtures/asi-01-goal-hijack/direct/*.py (≥3 files)
□ tests/fixtures/asi-01-goal-hijack/indirect/*.py (≥2 files)
□ tests/fixtures/asi-02-tool-misuse/direct/*.py (≥3 files)
□ tests/fixtures/asi-05-rce/direct/*.py (≥3 files)
□ tests/fixtures/benign/validated/*.py (≥2 files)
□ tests/fixtures/benign/sandboxed/*.py (≥2 files)
□ rules/mappings/mitre_atlas.yaml
□ .github/workflows/benchmark.yaml
□ scripts/run_benchmark.sh
```

### 最终目标

| 指标 | 当前 | 目标 |
|------|------|------|
| 评分 | 65/100 | ≥85/100 |
| Fixtures | ~9 | ≥50 |
| Ground Truth 样本 | 0 | ≥30 |
| Precision | 未测量 | ≥90% |
| Recall | 未测量 | ≥85% |
| F1-Score | 未测量 | ≥0.87 |
| ATLAS 映射 | 0 | ≥20 规则 |

---

**开始执行：从阶段 1 Step 1.1 开始，逐步完成每个步骤。每完成一个阶段，运行对应的验收测试确认通过后再进入下一阶段。**
