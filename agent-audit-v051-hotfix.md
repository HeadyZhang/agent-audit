# agent-audit v0.5.1 热修复方案

> **状态**: v0.5.0 合成样本 6/6 通过，但 openclaw 实战 842 findings / 99% FP
> **目标**: openclaw BLOCK+WARN ≤15, FP率 <20%, Risk Score 3.0-8.0
> **Prompt 数量**: 3 个 (H1→H2→H3)，预计 2-3 小时

---

## 问题诊断

```
openclaw v0.5.0 扫描: 842 BLOCK+WARN findings

误报来源分解:
┌──────────────────────────────────────────────────────────────┐
│ AGENT-048: 478 个 (57%)                                     │
│ 根因: extensions/ 下任何 from "../ 导入都触发               │
│ 修复: 区分"扩展内部导入" vs "跨越扩展边界导入"              │
├──────────────────────────────────────────────────────────────┤
│ AGENT-004: 267 个 (32%)                                     │
│ 根因: TS 语义分析未生效 — 变量引用/类型定义/schema 仍触发    │
│   ├─ password: state.password     → 应识别为 VARIABLE_REF   │
│   ├─ webhookSecret?: string       → 应识别为 TYPE_DEFINITION│
│   ├─ password: z.string().optional() → 应识别为 TYPE_DEF    │
│   └─ "Found Generic Secret" conf=1.0 → 应降为 0.50         │
│ 修复: 增强 _infer_value_type() + 降低 generic 模式 conf     │
├──────────────────────────────────────────────────────────────┤
│ AGENT-047: 81 个 (10%)                                      │
│ 根因: 所有 child_process/spawn 调用都以 0.80 报告            │
│ 修复: 构建脚本/工具链目录降权 + 硬编码参数降权               │
├──────────────────────────────────────────────────────────────┤
│ 其他: 16 个 (2%)                                            │
│ AGENT-043:12, AGENT-044:2, AGENT-045:9, AGENT-046:17       │
│ 大部分合理，少量需调整                                       │
└──────────────────────────────────────────────────────────────┘

真阳性: ~20 个 (postgres连接串4 + 权限规则若干合理检出)
目标: BLOCK+WARN ≤ 15, 意味着需要消除 ~827 个误报
```

### 修复优先级

| 优先级 | 修复项 | 消除误报数 | 占比 |
|--------|--------|-----------|------|
| **P0** | AGENT-048 扩展边界判断 | ~470 | 56% |
| **P0** | AGENT-004 TS 语义增强 + generic 降权 | ~260 | 31% |
| **P1** | AGENT-047 目录/参数降权 | ~70 | 8% |
| **P2** | AGENT-043/045/046 微调 | ~10 | 1% |
| 合计 | | ~810 | 96% |

预期修复后: 842 - 810 = **~32 findings**，其中 ~20 TP + ~12 FP = FP率 ~37%
进一步调优后目标: **≤15 WARN+**, FP率 <20%

---

## Prompt 执行顺序

```
H1 (AGENT-048 + AGENT-047 修复) ──→ H2 (AGENT-004 语义增强) ──→ H3 (openclaw 验证 + 微调)
        消除 ~540 FP                      消除 ~260 FP                  验证 + 尾部清理
```

---

## Prompt H1: AGENT-048 扩展边界修复 + AGENT-047 降权

```markdown
# 角色
你是 agent-audit 的安全规则维护者。你正在修复 v0.5.0 中两条规则的误报问题。
这是一个热修复任务——只修 bug，不加新功能。

# 背景
openclaw (100k+ star TypeScript 项目) 实战扫描暴露严重误报:
- AGENT-048: 478 个误报 (占总误报 57%)
- AGENT-047: 81 个误报 (占总误报 10%)

## AGENT-048 误报根因

当前逻辑: 检测 extensions/ 目录下任何 `from "../` 导入 → 报告为 "跨边界导入"
实际情况: extensions/tlon/src/monitor/utils.ts 中的 `import { normalizeShip } from "../targets.js"`
         是扩展**内部**模块间的正常导入，不是跨越扩展边界访问 core 代码。

正确逻辑: 只有当导入**跨出了所在扩展目录**（即目标路径解析后不在同一 extension 下）才报告。

误报样本:
```
extensions/tlon/src/monitor/utils.ts:
  import { normalizeShip } from "../targets.js"     ← FP: 还在 extensions/tlon/ 内
  import { Monitor } from "./monitor.js"             ← FP: 还在 extensions/tlon/ 内

应该触发的示例:
  extensions/tlon/src/index.ts:
  import { CoreAPI } from "../../src/core/api.js"    ← TP: 跨出了 extensions/tlon/
  import { AgentRunner } from "../../../core/runner"  ← TP: 跨出了 extensions/
```

## AGENT-047 误报根因

当前逻辑: 所有 child_process/spawn/exec 调用 → confidence 0.80 (WARN)
实际情况: openclaw 有大量合法的子进程调用 (构建工具、git 操作、npm 脚本)

降权条件:
1. 在 scripts/、build/、tools/、bin/ 目录下 → ×0.50
2. 命令参数完全是硬编码字符串 → ×0.60
3. 调用的是已知安全命令 (git, npm, node, tsc, eslint) → ×0.50
4. 多个降权条件可叠加，最低 confidence = 0.15

# 任务

## 第一步: 定位 AGENT-048 实现代码

```bash
grep -rn "AGENT.048\|extension.*permission\|extension.*boundary\|extension.*no.*permission" \
    agent_audit/ --include="*.py" -l
# 读取每个相关文件
```

## 第二步: 修复 AGENT-048 扩展边界判断

核心修改: 添加 `import_crosses_extension_boundary()` 函数

```python
def import_crosses_extension_boundary(file_path: str, import_path: str) -> bool:
    """
    判断一个 import 是否跨越了扩展边界。
    
    规则:
    1. 确定文件所在的 extension 根目录 (extensions/<name>/)
    2. 解析 import 的相对路径，得到目标文件的绝对路径
    3. 检查目标路径是否仍在同一 extension 根目录内
    4. 只有跨出 extension 根目录的导入才是"跨边界"
    
    示例:
    file: extensions/tlon/src/utils.ts
    extension_root: extensions/tlon/
    
    import "../targets.js"  → extensions/tlon/targets.js → 同一 extension ✓ → False
    import "../../src/core" → src/core → 跨出 extension ✗ → True
    import "@core/api"      → 绝对导入 core 包 → True (需要配置 core 包名列表)
    """
    # 1. 找到 extension 根目录
    parts = Path(file_path).parts
    ext_idx = None
    for i, part in enumerate(parts):
        if part in ("extensions", "plugins", "addons", "packages"):
            if i + 1 < len(parts):
                ext_idx = i + 1
                break
    
    if ext_idx is None:
        return False  # 不在 extension 目录中
    
    extension_root = Path(*parts[:ext_idx + 1])  # extensions/<name>
    
    # 2. 解析相对导入
    if import_path.startswith("."):
        file_dir = Path(file_path).parent
        resolved = (file_dir / import_path).resolve()
        # 注意: 这里用字符串前缀匹配，因为 resolve() 可能处理 ..
        # 更安全的做法是 normpath
        import os
        resolved_str = os.path.normpath(os.path.join(str(file_dir), import_path))
        extension_root_str = str(extension_root)
        return not resolved_str.startswith(extension_root_str)
    else:
        # 绝对导入 (如 import "core/api")
        # 这种通常不是扩展内部导入，但也不一定是跨边界
        # 保守处理: 检查是否导入了已知的 core 包
        CORE_PACKAGE_PATTERNS = [
            "src/", "core/", "lib/", "agent_audit/",
        ]
        return any(import_path.startswith(p) for p in CORE_PACKAGE_PATTERNS)


def check_extension_boundary(file_path: str, source: str, language: str) -> list:
    """
    重写后的 AGENT-048 检测逻辑
    """
    findings = []
    
    # 1. 确认文件在 extension 目录中
    if not is_in_extension_dir(file_path):
        return findings
    
    # 2. 检查是否缺少 manifest/permissions 声明
    extension_root = get_extension_root(file_path)
    has_manifest = any(
        (extension_root / name).exists()
        for name in ["manifest.json", "package.json", "permissions.yaml", "plugin.yaml"]
    )
    
    # 3. 分析导入 — 只报告跨边界导入
    if language in ("typescript", "javascript"):
        imports = extract_imports(source)  # 从 AST 或正则提取
        cross_boundary_imports = [
            imp for imp in imports
            if import_crosses_extension_boundary(file_path, imp.path)
        ]
        
        if cross_boundary_imports:
            # 有跨边界导入 → 报告
            conf = 0.80 if not has_manifest else 0.60
            findings.append(Finding(
                rule_id="AGENT-048",
                confidence=conf,
                message=f"Extension imports core modules without permission boundary: "
                        f"{', '.join(imp.path for imp in cross_boundary_imports[:3])}",
                ...
            ))
    
    # 4. 如果整个 extension 目录没有任何权限声明 → 报告一次 (不是每个文件)
    #    这个检查应该在扫描器层面去重，不是每个文件都报
    
    return findings
```

**关键改动**: 
- 从"每个文件每个导入都报告"改为"只报告跨边界导入"
- 整个 extension 缺少 manifest 只报告一次（去重）

## 第三步: 修复 AGENT-047 降权

```python
SAFE_COMMANDS = {
    "git", "npm", "npx", "yarn", "pnpm", "node", "tsc", "tsx",
    "eslint", "prettier", "jest", "vitest", "mocha",
    "python", "pip", "poetry", "cargo", "go", "make",
    "docker", "kubectl", "terraform",
    "cat", "echo", "ls", "mkdir", "cp", "mv", "rm",
    "curl", "wget",  # 注意: 这些可能有 SSRF 风险，但作为构建工具是安全的
}

TOOL_DIRECTORIES = {
    "scripts", "build", "tools", "bin", "ci", ".github",
    "devtools", "tooling", "infra", "deploy",
}

def adjust_subprocess_confidence(
    base_confidence: float,
    file_path: str,
    command_args: list[str] | None,
) -> float:
    """
    根据上下文降低 AGENT-047 的 confidence
    """
    conf = base_confidence
    
    # 降权 1: 工具目录
    parts = set(Path(file_path).parts)
    if parts & TOOL_DIRECTORIES:
        conf *= 0.50
    
    # 降权 2: 已知安全命令
    if command_args and len(command_args) > 0:
        cmd = Path(command_args[0]).name.lower()
        if cmd in SAFE_COMMANDS:
            conf *= 0.50
    
    # 降权 3: 完全硬编码参数（没有变量插值）
    if command_args and all(is_literal_string(arg) for arg in command_args):
        conf *= 0.60
    
    # 最低不低于 0.15（仍然记录为 SUPPRESSED）
    return max(conf, 0.15)
```

## 第四步: 测试

```python
# tests/test_hotfix_048.py

class TestAGENT048Hotfix:
    """AGENT-048 扩展边界修复测试"""
    
    def test_internal_import_not_flagged(self):
        """扩展内部导入不应触发"""
        source = 'import { normalizeShip } from "../targets.js";'
        findings = scan_privilege(source, "extensions/tlon/src/monitor/utils.ts")
        f048 = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(f048) == 0, f"Internal import should not be flagged, got {f048}"
    
    def test_internal_relative_import(self):
        """同一扩展内的相对导入不触发"""
        source = 'import { Monitor } from "./monitor.js";'
        findings = scan_privilege(source, "extensions/tlon/src/index.ts")
        f048 = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(f048) == 0
    
    def test_cross_boundary_import_flagged(self):
        """跨越扩展边界的导入应该触发"""
        source = 'import { CoreAPI } from "../../../src/core/api.js";'
        findings = scan_privilege(source, "extensions/tlon/src/index.ts")
        f048 = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(f048) >= 1
    
    def test_absolute_core_import_flagged(self):
        """绝对导入 core 模块应该触发"""
        source = 'import { Runner } from "src/core/runner";'
        findings = scan_privilege(source, "extensions/tlon/src/index.ts")
        f048 = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(f048) >= 1
    
    def test_non_extension_file_ignored(self):
        """非 extension 目录的文件不触发"""
        source = 'import { something } from "../other.js";'
        findings = scan_privilege(source, "src/utils/helper.ts")
        f048 = [f for f in findings if f.rule_id == "AGENT-048"]
        assert len(f048) == 0


class TestAGENT047Hotfix:
    """AGENT-047 降权测试"""
    
    def test_build_script_lowered(self):
        """构建脚本中的 subprocess → 降权到 INFO 或 SUPPRESSED"""
        source = '''
import { execSync } from "child_process";
execSync("npm install");
'''
        findings = scan_privilege(source, "scripts/build.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047), \
                f"Build script subprocess should be low confidence, got {[f.confidence for f in f047]}"
    
    def test_safe_command_lowered(self):
        """已知安全命令 → 降权"""
        source = 'execSync("git status");'
        findings = scan_privilege(source, "src/utils.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        if f047:
            assert all(f.confidence < 0.50 for f in f047)
    
    def test_dynamic_command_kept(self):
        """动态命令参数 → 保持高 confidence"""
        source = '''
import { spawn } from "child_process";
spawn(userInput, args, { shell: true });
'''
        findings = scan_privilege(source, "src/runner.ts")
        f047 = [f for f in findings if f.rule_id == "AGENT-047"]
        assert len(f047) >= 1
        assert any(f.confidence >= 0.60 for f in f047)
```

## 约束

- **只修 bug，不加新功能**
- 不改变规则的 ASI 映射和严重级别定义
- 保留 AGENT-048 对真正缺少权限边界的扩展的检测能力
- 保留 AGENT-047 对动态命令执行的检测能力
- 现有测试不能破坏

## 自验证

```bash
# 1. 新测试
pytest tests/test_hotfix_048.py tests/test_hotfix_047.py -v

# 2. 回归
pytest tests/ -v --tb=short -q

# 3. 快速验证: 扩展内部导入不再误报
python -c "
source = 'import { normalizeShip } from \"../targets.js\";'
findings = scan_privilege(source, 'extensions/tlon/src/monitor/utils.ts')
f048 = [f for f in findings if f.rule_id == 'AGENT-048']
print(f'AGENT-048 internal import: {len(f048)} findings (should be 0)')
"
```
```

---

## Prompt H2: AGENT-004 TypeScript 语义增强 + Generic 模式降权

```markdown
# 角色
你是 agent-audit 的安全工程师。你正在修复 AGENT-004 对 TypeScript 代码的误报问题。

# 前置条件
Prompt H1 已完成（AGENT-048 和 AGENT-047 误报已修复）。

验证:
```bash
pytest tests/test_hotfix_048.py tests/test_hotfix_047.py -v
# 确认通过
```

# 背景
openclaw 扫描中 AGENT-004 产生 267 个 BLOCK 级误报:
- .ts 文件: 188 个 (全是变量引用/类型定义，语义分析未生效)
- .md 文件: 75 个 (文档描述中的关键词匹配)

误报样本分析:
```
❌ password: state.password,          → VARIABLE_REF (state.password 是属性访问)
❌ webhookSecret?: string;            → TYPE_DEFINITION (TypeScript 接口属性)
❌ password: z.string().optional()    → TYPE_DEFINITION (Zod schema)
❌ const token = resolveToken(...)    → FUNCTION_CALL
❌ apiKey: "YOUR_API_KEY_HERE"        → PLACEHOLDER
❌ "Found Generic Secret/Password"   → confidence=1.0 应降为 0.50
```

# 根因诊断

v0.5.0 的 C2a 创建了 `semantic_analyzer.py` 三阶段引擎，但有两个问题:

1. **_infer_value_type() 覆盖不足**: 
   对 TypeScript 特有的模式（接口属性声明、Zod schema、属性访问表达式）
   未正确分类为 TYPE_DEFINITION 或 VARIABLE_REF。
   tree-sitter 解析器可能在这些边缘情况下返回了 OTHER 而非正确类型。

2. **Generic 模式 confidence 过高**:
   当无法匹配已知凭证格式时，fallback 到 "Found Generic Secret/Password" 
   并给 confidence=1.0 (BLOCK)。这意味着任何包含 "password" 关键词的字符串赋值
   都直接进入 BLOCK 层——完全绕过了三阶段引擎的设计意图。

# 任务

## 第一步: 定位问题代码

```bash
# 1. 语义分析器
cat agent_audit/analysis/semantic_analyzer.py

# 2. value_type 推断逻辑
grep -n "_infer_value_type\|ValueType\|value_type\|LITERAL_STRING\|FUNCTION_CALL\|VARIABLE_REF\|ENV_READ\|TYPE_DEFINITION" \
    agent_audit/analysis/semantic_analyzer.py

# 3. tree-sitter 解析器的 find_assignments
cat agent_audit/parsers/treesitter_parser.py

# 4. 找到 "Generic Secret" 的来源
grep -rn "Generic Secret\|Generic Password\|generic.*credential\|Found.*Generic\|confidence.*1\.0\|confidence=1" \
    agent_audit/ --include="*.py"

# 5. AGENT-004 规则中如何调用语义分析器
grep -rn "AGENT.004\|semantic_analyz\|scan_for_credential\|check_credential" \
    agent_audit/ --include="*.py" -l
# 逐个读取
```

**先读取所有相关代码，理解 confidence=1.0 是在哪里被设置的。**

## 第二步: 修复 tree-sitter 解析器的 TypeScript 模式识别

在 `treesitter_parser.py` 的 `find_assignments()` 中增强 TypeScript 模式:

```python
# 需要正确识别的 TypeScript AST 节点类型:

# 1. 接口/类型属性声明
# `webhookSecret?: string;` 
# AST: property_signature { name: property_identifier, type: type_annotation }
# → 应返回 value_type = TYPE_DEFINITION, 不应作为 assignment 返回

# 2. Zod schema 属性
# `password: z.string().optional()`
# AST: pair { key: property_identifier, value: call_expression(member_expression) }
# → 当 value 是 z.xxx() 调用链时, value_type = TYPE_DEFINITION

# 3. 对象属性 - 值是属性访问
# `password: state.password`
# AST: pair { key: property_identifier, value: member_expression }
# → value_type = VARIABLE_REF (不是 LITERAL_STRING)

# 4. 对象属性 - 值是变量
# `password: password` (shorthand) 或 `password: userPassword`
# AST: pair { key: property_identifier, value: identifier }
# → value_type = VARIABLE_REF

# 5. 解构赋值
# `const { password, token } = config;`
# AST: variable_declarator { pattern: object_pattern, value: identifier }
# → 不应产生任何 LITERAL_STRING assignment

# tree-sitter TypeScript 节点类型参考:
TS_TYPE_DEFINITION_NODES = {
    "property_signature",         # interface Foo { bar: string }
    "type_alias_declaration",     # type Foo = string
    "interface_declaration",      # interface Foo {}
    "enum_declaration",           # enum Foo {}
}

TS_VARIABLE_REF_VALUE_NODES = {
    "identifier",                 # password: someVar
    "member_expression",          # password: state.password
    "subscript_expression",       # password: config["password"]
}

ZOD_CHAIN_METHODS = {
    "string", "number", "boolean", "object", "array", "enum",
    "optional", "nullable", "default", "describe", "refine",
    "transform", "pipe", "coerce",
}

def is_zod_schema_call(node) -> bool:
    """判断一个 call_expression 是否是 Zod schema 定义链"""
    # 检查调用链: z.string().optional() 
    # 即 member_expression 的 object 最终是 identifier "z"
    # 且方法名在 ZOD_CHAIN_METHODS 中
    ...
```

## 第三步: 修复 semantic_analyzer.py 的 fallback confidence

```python
# 找到 "Generic Secret/Password" 的代码位置并修改:

# 当前 (有问题):
# 某处: confidence = 1.0, reason = "Found Generic Secret/Password"

# 修复后:
def _calculate_generic_confidence(identifier: str, value: str, context: dict) -> float:
    """
    对不匹配任何已知格式的 "generic" 凭证匹配计算 confidence
    
    这是 AGENT-004 的 fallback 路径——标识符名匹配了关键词
    但值不匹配任何已知凭证格式。
    
    返回的 confidence 应该较低，因为大多数情况是:
    - 变量传递 (password = config.password)
    - 类型定义 (password: string)  
    - 占位符 (password: "CHANGE_ME")
    - 函数参数名 (function(password))
    
    只有高 entropy + 合理长度的字符串字面量才值得较高 confidence。
    """
    from agent_audit.analysis.entropy import shannon_entropy
    from agent_audit.analysis.placeholder_detector import is_placeholder
    
    # 如果值不是字符串字面量，直接低 confidence
    if not isinstance(value, str) or len(value) < 4:
        return 0.15
    
    # 占位符检测
    is_ph, ph_conf = is_placeholder(value)
    if is_ph and ph_conf > 0.5:
        return 0.15
    
    # 值等于标识符名
    if value.lower().strip('"\'') == identifier.lower():
        return 0.15
    
    # Entropy 分析
    ent = shannon_entropy(value)
    
    if ent > 4.5 and len(value) > 16:
        return 0.70  # 高 entropy + 长字符串 → 可疑
    elif ent > 4.0 and len(value) > 12:
        return 0.55  # 中等 entropy → 值得关注
    elif ent > 3.5 and len(value) > 8:
        return 0.40  # INFO 层
    else:
        return 0.25  # 低 entropy → 大概率不是真实凭证
    
    # 注意: 永远不要对 generic 模式返回 >= 0.90 (BLOCK)
    # BLOCK 层只给已知格式匹配 (ghp_*, sk-*, AKIA* 等)
```

## 第四步: 确保语义分析器被正确调用

检查 AGENT-004 的扫描流程，确认:

```python
# 对 .ts/.js 文件的扫描流程应该是:
# 1. tree-sitter 解析 → 获取 assignments + value_types
# 2. 过滤: value_type 为 FUNCTION_CALL/VARIABLE_REF/ENV_READ/TYPE_DEFINITION → 跳过
# 3. 对剩余 LITERAL_STRING 类型的赋值 → 执行 Stage 2 值分析
# 4. 上下文调整 (文件类型乘数)
# 5. 生成 Finding

# 如果步骤 1-2 没有正确执行（tree-sitter 返回了错误的 value_type），
# 则大量非字面量赋值会"穿透"到步骤 3-4，导致误报。

# 检查: 扫描 .ts 文件时是否真的在用 tree-sitter？
# 还是 fallback 到了正则扫描？
grep -n "tree.sitter\|TreeSitter\|treesitter\|find_assignments\|_infer_value_type" \
    agent_audit/analysis/semantic_analyzer.py
```

**关键排查**: 可能 tree-sitter 对 .ts 文件的解析路径没有被正确触发，
导致所有 .ts 文件走了 regex fallback 路径（confidence=1.0）。

## 第五步: 增强 .md 文件的上下文调整

```python
# 当前 .md 文件乘数: 0.85 (仍然很高)
# 问题: 75 个 .md 文件误报，confidence 0.85 后仍是 WARN

# 修复方案:
# 1. .md 文件中的 "Generic Secret" → confidence × 0.50 (而非 0.85)
# 2. .md 文件中匹配已知格式 → 保持 × 0.85 (postgres:// 等仍应报告)

FILE_TYPE_MULTIPLIERS = {
    # 匹配已知格式时的乘数
    "known_format": {
        ".md": 0.85, ".rst": 0.85, ".txt": 0.85,
    },
    # generic 模式时的乘数 (更激进的降权)
    "generic": {
        ".md": 0.40, ".rst": 0.40, ".txt": 0.40,
    },
}
```

## 第六步: 测试

```python
# tests/test_hotfix_004.py

class TestAGENT004Hotfix:
    """AGENT-004 TypeScript 误报修复测试"""
    
    # === 误报消除 (8个) ===
    
    def test_ts_state_password_variable_ref(self):
        """password: state.password → 不报告"""
        source = 'const config = { password: state.password };'
        findings = scan_004(source, "settings.ts")
        assert len(findings) == 0, f"Variable ref should not trigger, got {findings}"
    
    def test_ts_interface_property(self):
        """webhookSecret?: string → 不报告"""
        source = '''
interface Config {
    webhookSecret?: string;
    apiKey: string;
    password: string;
}'''
        findings = scan_004(source, "types.ts")
        assert len(findings) == 0
    
    def test_ts_zod_schema(self):
        """password: z.string().optional() → 不报告"""
        source = '''
const schema = z.object({
    password: z.string().optional(),
    apiKey: z.string().min(1),
    secret: z.string().default(""),
});'''
        findings = scan_004(source, "schema.ts")
        assert len(findings) == 0
    
    def test_ts_destructuring(self):
        """const { password, token } = config → 不报告"""
        source = 'const { password, token, secret } = config;'
        findings = scan_004(source, "handler.ts")
        assert len(findings) == 0
    
    def test_ts_function_param(self):
        """function login(password: string) → 不报告"""
        source = 'function login(password: string, token: string) { ... }'
        findings = scan_004(source, "auth.ts")
        assert len(findings) == 0
    
    def test_generic_secret_not_block(self):
        """Generic Secret 匹配不应该是 BLOCK 级别"""
        source = 'const secret = "some_value_here";'
        findings = scan_004(source, "config.ts")
        if findings:
            assert all(f.confidence < 0.90 for f in findings), \
                "Generic secret should not be BLOCK tier"
    
    def test_md_generic_suppressed(self):
        """.md 文件中的 generic 关键词匹配 → SUPPRESSED 或 INFO"""
        source = 'Set your `password` in the config file'
        findings = scan_004(source, "README.md")
        if findings:
            assert all(f.confidence < 0.60 for f in findings)
    
    def test_ts_object_shorthand(self):
        """{ password } 简写 → 不报告"""
        source = 'return { password, username, token };'
        findings = scan_004(source, "response.ts")
        assert len(findings) == 0
    
    # === 真阳性保留 (4个) ===
    
    def test_tp_postgres_in_md(self):
        """postgres 连接串在 .md 中仍应检出"""
        source = 'POSTGRES_URL=postgres://admin:realpass@localhost:5432/db'
        findings = scan_004(source, "setup.md")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.60
    
    def test_tp_hardcoded_api_key(self):
        """硬编码 API key 仍应检出"""
        source = 'const API_KEY = "sk-proj-1234567890abcdefghijklmnop";'
        findings = scan_004(source, "config.ts")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85
    
    def test_tp_hardcoded_string_literal(self):
        """字符串字面量赋值给 secret 变量仍应检出"""
        source = 'const secret = "aB3xQ9mK7pL2nR5tY8wE4jF6hG1iD0";'
        findings = scan_004(source, "app.ts")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.50
    
    def test_tp_github_token(self):
        """GitHub token 仍应检出"""
        source = 'const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";'
        findings = scan_004(source, "deploy.ts")
        assert len(findings) >= 1
        assert findings[0].confidence >= 0.85
```

## 约束

- **只修误报，不改检测范围**
- 已知格式匹配 (ghp_*, sk-*, postgres://) 的 confidence 不降低
- 不影响 Python 文件的检测（Python AST 路径不变）
- 确保 tree-sitter 路径对 .ts/.js 文件被正确激活

## 自验证

```bash
# 1. 新测试
pytest tests/test_hotfix_004.py -v

# 2. 回归 (含 benchmark 样本)
pytest tests/ -v --tb=short -q

# 3. 关键验证
python -c "
# TS 变量引用不应触发
r1 = scan_004('const config = { password: state.password };', 'test.ts')
print(f'state.password: {len(r1)} findings (should be 0)')

# TS Zod schema 不应触发
r2 = scan_004('password: z.string().optional()', 'schema.ts')
print(f'zod schema: {len(r2)} findings (should be 0)')

# 已知格式仍应触发
r3 = scan_004('const KEY = \"sk-proj-1234567890abcdef\";', 'config.ts')
print(f'sk-proj-: {len(r3)} findings (should be >= 1)')

# Generic Secret 不应是 BLOCK
r4 = scan_004('const secret = \"some_value\";', 'app.ts')
if r4:
    print(f'Generic conf: {r4[0].confidence} (should be < 0.90)')
"
```
```

---

## Prompt H3: openclaw 验证 + 尾部微调

```markdown
# 角色
你是 agent-audit 的 QA 工程师。你正在对 v0.5.1 热修复进行端到端验证。

# 前置条件
H1 (AGENT-048/047 修复) 和 H2 (AGENT-004 修复) 已完成。

验证:
```bash
pytest tests/ -v --tb=short -q
# 所有测试通过
```

# 任务

## 第一步: openclaw 扫描

```bash
# 如果 /tmp/openclaw 已存在就跳过 clone
ls /tmp/openclaw || git clone --depth 1 https://github.com/openclaw/openclaw.git /tmp/openclaw

# 扫描
python -m agent_audit scan /tmp/openclaw --output json > /tmp/openclaw-v051.json 2>&1
python -m agent_audit scan /tmp/openclaw > /tmp/openclaw-v051.txt 2>&1
```

## 第二步: 验收标准检查

```python
import json

results = json.load(open("/tmp/openclaw-v051.json"))

# 1. BLOCK+WARN findings
block_warn = [f for f in results["findings"] if f.get("tier") in ("BLOCK", "WARN")]
print(f"BLOCK+WARN: {len(block_warn)} (target: ≤15)")

# 2. 按规则分布
from collections import Counter
by_rule = Counter(f["rule_id"] for f in block_warn)
print(f"By rule: {dict(by_rule)}")

# 3. AGENT-048 误报检查
f048 = [f for f in block_warn if f["rule_id"] == "AGENT-048"]
print(f"AGENT-048 WARN+: {len(f048)} (target: ≤3)")

# 4. AGENT-004 误报检查
f004 = [f for f in block_warn if f["rule_id"] == "AGENT-004"]
print(f"AGENT-004 WARN+: {len(f004)} (target: ≤6)")
# 逐个检查是否为 TP
for f in f004:
    print(f"  {f['location']['file']}:{f['location']['line']} "
          f"conf={f['confidence']:.2f} {f.get('reason', '')}")

# 5. postgres 连接串
postgres = [f for f in f004 if "postgres" in f.get("code_snippet", "").lower()]
print(f"Postgres connection strings: {len(postgres)} (target: ≥3)")

# 6. 权限规则 (AGENT-043~048)
priv = [f for f in block_warn if f["rule_id"].startswith("AGENT-04") 
        and int(f["rule_id"].split("-")[1]) >= 43]
print(f"Privilege rules WARN+: {len(priv)} (target: ≥2)")

# 7. Risk Score
score = results.get("summary", {}).get("risk_score", "N/A")
print(f"Risk Score: {score} (target: 3.0-8.0)")

# 8. readKeychainPassword 不报 AGENT-004
keychain_004 = [f for f in results["findings"]
                if f["rule_id"] == "AGENT-004" 
                and "keychain" in f.get("code_snippet", "").lower()]
print(f"readKeychainPassword as AGENT-004: {len(keychain_004)} (target: 0)")
```

### 硬性验收标准

| 指标 | 目标 | BLOCKER? |
|------|------|---------|
| BLOCK+WARN findings | ≤15 | ✅ Yes |
| BLOCK+WARN FP率 | <20% | ✅ Yes |
| AGENT-048 WARN+ | ≤3 | ✅ Yes |
| AGENT-004 WARN+ | ≤6 | ✅ Yes |
| postgres 检出 | ≥3 | ✅ Yes |
| 权限规则命中 | ≥2 | ✅ Yes |
| Risk Score | 3.0-8.0 | ✅ Yes |
| readKeychainPassword ≠ AGENT-004 | 0 | ✅ Yes |

## 第三步: 如果验收未通过 — 微调

### 场景 A: AGENT-004 WARN+ 仍然 >6

分析剩余误报，添加更多排除模式:

```python
# 常见漏网之鱼:
# 1. TypeScript enum 值: Secret.PASSWORD → member_expression
# 2. 函数默认参数: function foo(password = "") → 空字符串
# 3. 测试 mock: jest.fn().mockResolvedValue({ password: "test" })
# 4. 配置对象解构: const { password: dbPassword } = config

# 对每个漏网的误报:
# - 确认 tree-sitter 返回的 node type
# - 添加对应的排除逻辑
# - 添加测试用例
```

### 场景 B: AGENT-048 WARN+ 仍然 >3

```python
# 检查剩余的 AGENT-048 findings:
for f in f048:
    print(f"  {f['location']['file']}: {f.get('code_snippet', '')}")
    # 分析: 是真正的跨边界导入，还是边界判断有 bug？
```

### 场景 C: 权限规则命中 <2

```python
# 检查权限规则是否被意外抑制:
all_priv = [f for f in results["findings"] 
            if f["rule_id"].startswith("AGENT-04") 
            and int(f["rule_id"].split("-")[1]) >= 43]
print(f"All privilege findings (all tiers): {len(all_priv)}")
for f in all_priv:
    print(f"  {f['rule_id']} tier={f['tier']} conf={f['confidence']:.2f} "
          f"{f['location']['file']}")
```

## 第四步: Benchmark 回归

```bash
# Layer 1 + Agent-Vuln-Bench 样本
pytest tests/ -v --tb=short -q

# 确认 6/6 benchmark 样本仍然通过
pytest tests/ -k "known_001 or known_002 or known_003 or known_004 or wild_001 or wild_002" -v
```

## 第五步: 更新验证报告

更新 `docs/v050-validation-report.md`:

```markdown
# v0.5.1 Hotfix Validation Report (updated)

## openclaw Results (v0.5.0 → v0.5.1)
| 指标 | v0.5.0 | v0.5.1 | 目标 | 状态 |
|------|--------|--------|------|------|
| BLOCK+WARN | 842 | X | ≤15 | ✅/❌ |
| FP率 | ~99% | X% | <20% | ✅/❌ |
| AGENT-048 | 478 | X | ≤3 | ✅/❌ |
| AGENT-004 | 267 | X | ≤6 | ✅/❌ |
| postgres | 4 | X | ≥3 | ✅/❌ |
| 权限规则 | 519 | X | ≥2 | ✅/❌ |
| Risk Score | 10.0 | X | 3.0-8.0 | ✅/❌ |

## Benchmark Regression
| 样本 | v0.5.0 | v0.5.1 |
|------|--------|--------|
| KNOWN-001~004 | ✅ | ✅/❌ |
| WILD-001~002 | ✅ | ✅/❌ |
| Layer 1 (656 tests) | ✅ | ✅/❌ |
```

## 第六步: 版本号更新

如果所有验收标准通过:
```bash
# 更新版本号为 0.5.1
sed -i 's/version = "0.5.0"/version = "0.5.1"/' pyproject.toml
sed -i 's/__version__ = "0.5.0"/__version__ = "0.5.1"/' agent_audit/version.py
```

## 约束

- **不修改验收标准**来通过验证
- 如果需要微调 confidence 阈值，每次调整后都要重新运行完整测试套件
- 微调应该是精确的（针对特定模式），不是粗暴的（全局降低 confidence）
- 所有修改都要有对应测试用例

## 自验证

所有 8 项验收标准通过后，此 Prompt 才算完成。
```

---

## 执行总结

```
H1 (AGENT-048 + AGENT-047) ──→ H2 (AGENT-004 TS 语义) ──→ H3 (openclaw 验证 + 微调)
     消除 ~540 FP                   消除 ~260 FP                验证 + 尾部清理
     预计 45min                      预计 45min                  预计 30-60min

总预计: 2-3 小时，3 个 Claude Code Prompt

预期效果:
v0.5.0:  842 BLOCK+WARN, 99% FP, Risk Score 10.0
v0.5.1:  ≤15 BLOCK+WARN, <20% FP, Risk Score 3.0-8.0
```

### 误报消除瀑布图

```
842 findings (v0.5.0)
 │
 ├─ H1: AGENT-048 扩展边界修复     -470
 ├─ H1: AGENT-047 目录/命令降权     -70
 │                                  ────
 │                                  302 remaining
 │
 ├─ H2: AGENT-004 TS value_type     -188
 ├─ H2: AGENT-004 .md generic 降权   -75
 ├─ H2: Generic Secret conf 降权     -20
 │                                  ────
 │                                  ~19 remaining
 │
 ├─ H3: 尾部微调                    -5
 │                                  ────
 │                                  ~14 remaining (≤15 ✅)
 │
 └─ 其中 TP: ~10-14 (postgres, daemon, sudoers, CDP, Keychain)
    FP: ~0-4 (<20% ✅)
```
