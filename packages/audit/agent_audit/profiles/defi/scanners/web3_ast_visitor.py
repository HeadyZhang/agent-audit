"""Web3 AST Visitor — core DeFi AST analysis engine.

Analyzes Python AST for DeFi security issues including:
- AGENT-091: Transaction without amount limit
- AGENT-092: Transaction without human approval
- AGENT-095: Missing gas limit
- AGENT-096: Unlimited token approve
- AGENT-097: Missing nonce management
- AGENT-093: Prompt input to blockchain transaction (taint flow)
- AGENT-098: Missing MEV protection
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set

from agent_audit.profiles.defi.constants.defi_protocols import (
    UNLIMITED_APPROVE_VALUES,
    UNLIMITED_APPROVE_VARIABLE_NAMES,
)
from agent_audit.profiles.defi.constants.web3_apis import (
    AMOUNT_VARIABLE_NAMES,
    CONTRACT_TRANSACT_FUNCTIONS,
    HUMAN_APPROVAL_FUNCTION_PATTERNS,
    SWAP_FUNCTIONS_WITH_SLIPPAGE_PARAM,
    TRANSACTION_SEND_FUNCTIONS,
)
from agent_audit.profiles.defi.rules import DeFiFinding, make_finding


class Web3ASTVisitor(ast.NodeVisitor):
    """AST visitor for DeFi security analysis."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[DeFiFinding] = []

        # State tracking
        self._imported_names: Dict[str, str] = {}
        self._current_function: Optional[str] = None
        self._current_function_node: Optional[ast.FunctionDef] = None
        self._current_function_params: Set[str] = set()
        self._current_class: Optional[str] = None
        self._in_tool_function: bool = False

        # DeFi-specific state
        self._file_has_web3_import: bool = False
        self._file_has_swap_call: bool = False
        self._file_has_mev_protection: bool = False
        self._file_rpc_urls: List[str] = []

    def scan(self, source: str) -> List[DeFiFinding]:
        """Parse and scan source code."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return self.findings
        self.visit(tree)
        self._post_file_checks()
        return self.findings

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self._imported_names[name] = alias.name
            if 'web3' in alias.name.lower() or 'eth' in alias.name.lower():
                self._file_has_web3_import = True
            if 'flashbots' in alias.name.lower():
                self._file_has_mev_protection = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ''
        for alias in (node.names or []):
            name = alias.asname or alias.name
            self._imported_names[name] = f"{module}.{alias.name}"
            if 'web3' in module.lower() or 'eth' in module.lower():
                self._file_has_web3_import = True
            if 'flashbots' in module.lower() or alias.name.lower() == 'flashbot':
                self._file_has_mev_protection = True
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._enter_function(node)
        self.generic_visit(node)
        self._exit_function()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node)
        if func_name:
            self._check_transaction_no_amount_limit(node, func_name)
            self._check_swap_no_slippage(node, func_name)
            self._check_unlimited_approve(node, func_name)
            if self._in_tool_function:
                self._check_defi_no_human_approval_call(node, func_name)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        self._check_transaction_dict(node)
        self.generic_visit(node)

    # ================================================================
    # Function entry/exit tracking
    # ================================================================

    def _enter_function(self, node: ast.FunctionDef):
        self._current_function = node.name
        self._current_function_node = node
        self._current_function_params = {
            arg.arg for arg in node.args.args
        }
        self._in_tool_function = self._has_tool_decorator(node)

        if self._in_tool_function and self._contains_blockchain_tx(node):
            if not self._contains_approval_gate(node):
                confidence = 0.88
                if self._has_amount_threshold_branch(node):
                    confidence *= 0.60
                if confidence >= 0.30:
                    self.findings.append(make_finding(
                        rule_id='AGENT-092',
                        pattern_type='defi_tx_no_human_approval',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=confidence,
                        message=(
                            f'Tool function "{node.name}" sends blockchain '
                            f'transactions without human approval gate.'
                        ),
                    ))

        # AGENT-093: Taint analysis for @tool functions
        if self._in_tool_function and self._contains_blockchain_tx(node):
            from agent_audit.profiles.defi.analysis.defi_taint_extensions import (
                SimpleDeFiTaintTracker,
            )
            tracker = SimpleDeFiTaintTracker(self.file_path)
            taint_findings = tracker.analyze_function(node, is_tool=True)
            self.findings.extend(taint_findings)

    def _exit_function(self):
        self._current_function = None
        self._current_function_node = None
        self._current_function_params = set()
        self._in_tool_function = False

    # ================================================================
    # AGENT-091: Transaction without amount limit
    # ================================================================

    def _check_transaction_no_amount_limit(
        self, node: ast.Call, func_name: str,
    ):
        simple_name = func_name.split('.')[-1]
        is_tx_send = simple_name in TRANSACTION_SEND_FUNCTIONS
        is_contract_tx = simple_name in CONTRACT_TRANSACT_FUNCTIONS

        if not (is_tx_send or is_contract_tx):
            return

        # Skip approve() calls — they are handled by AGENT-096
        if is_contract_tx and self._is_approve_transact(node):
            return

        # Check if we're inside a function with amount limit checks
        if self._current_function_node:
            if self._has_amount_limit_check(
                self._current_function_node, node.lineno,
            ):
                return

        # Determine confidence based on context
        if self._in_tool_function:
            confidence = 0.92
        elif self._current_class:
            confidence = 0.85
        else:
            confidence = 0.65

        if self._is_test_context():
            confidence *= 0.20

        if confidence >= 0.30:
            self.findings.append(make_finding(
                rule_id='AGENT-091',
                pattern_type='defi_tx_no_amount_limit',
                file_path=self.file_path,
                line=node.lineno,
                confidence=confidence,
                message=(
                    f'Blockchain transaction "{simple_name}" called without '
                    f'amount limit validation.'
                ),
            ))

    def _has_amount_limit_check(
        self, func_node: ast.FunctionDef, tx_line: int,
    ) -> bool:
        """Check if function has amount validation before the tx call."""
        for child in ast.walk(func_node):
            if hasattr(child, 'lineno') and child.lineno >= tx_line:
                continue

            # Compare operations: amount > MAX, value <= LIMIT
            if isinstance(child, ast.Compare):
                if self._involves_amount_variable(child):
                    return True

            # Assert statements
            if isinstance(child, ast.Assert) and isinstance(
                child.test, ast.Compare,
            ):
                if self._involves_amount_variable(child.test):
                    return True

            # Function calls: validate_amount(), check_limit()
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and any(
                    kw in name.lower()
                    for kw in [
                        'limit', 'cap', 'max_amount', 'validate_amount',
                        'check_balance', 'within_budget',
                    ]
                ):
                    return True

        return False

    def _involves_amount_variable(self, node: ast.Compare) -> bool:
        """Check if a comparison involves amount-related variables."""
        nodes_to_check = [node.left] + list(node.comparators)
        for n in nodes_to_check:
            if isinstance(n, ast.Name):
                name_lower = n.id.lower()
                if n.id in AMOUNT_VARIABLE_NAMES:
                    return True
                if 'amount' in name_lower or 'value' in name_lower:
                    return True
        return False

    # ================================================================
    # AGENT-091b: Swap without slippage protection
    # ================================================================

    def _check_swap_no_slippage(self, node: ast.Call, func_name: str):
        simple_name = func_name.split('.')[-1]
        if simple_name not in SWAP_FUNCTIONS_WITH_SLIPPAGE_PARAM:
            return

        self._file_has_swap_call = True

        # Check amountOutMin parameter (typically 2nd arg for V2 swaps)
        if len(node.args) >= 2:
            amount_out_min = node.args[1]
            if isinstance(amount_out_min, ast.Constant) and amount_out_min.value == 0:
                confidence = 0.85 if self._in_tool_function else 0.70
                if self._is_test_context():
                    confidence *= 0.20
                if confidence >= 0.30:
                    self.findings.append(make_finding(
                        rule_id='AGENT-091',
                        pattern_type='defi_swap_no_slippage_protection',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=confidence,
                        message=(
                            f'Swap function "{simple_name}" called with '
                            f'amountOutMin=0 (no slippage protection).'
                        ),
                    ))

        # Check deadline parameter (typically last arg)
        if node.args:
            deadline = node.args[-1]
            if (
                isinstance(deadline, ast.Constant)
                and isinstance(deadline.value, int)
                and deadline.value > 10**9
            ):
                confidence = 0.65
                if self._is_test_context():
                    confidence *= 0.20
                if confidence >= 0.30:
                    self.findings.append(make_finding(
                        rule_id='AGENT-091',
                        pattern_type='defi_swap_no_slippage_protection',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=confidence,
                        message=(
                            f'Swap function "{simple_name}" called with '
                            f'excessively large deadline constant.'
                        ),
                    ))

    # ================================================================
    # AGENT-096: Unlimited token approve
    # ================================================================

    def _check_unlimited_approve(self, node: ast.Call, func_name: str):
        simple_name = func_name.split('.')[-1]
        if simple_name != 'approve':
            return

        # Check 2nd argument (amount) for unlimited values
        if len(node.args) < 2:
            return

        amount_node = node.args[1]

        is_unlimited = False

        # Direct large constant
        if isinstance(amount_node, ast.Constant) and isinstance(
            amount_node.value, int,
        ):
            if amount_node.value in UNLIMITED_APPROVE_VALUES:
                is_unlimited = True
            elif amount_node.value > 10**20:
                is_unlimited = True

        # Variable name like MAX_UINT256
        if isinstance(amount_node, ast.Name):
            if amount_node.id.upper() in UNLIMITED_APPROVE_VARIABLE_NAMES:
                is_unlimited = True

        # BinOp: 2**256 - 1
        if isinstance(amount_node, ast.BinOp) and isinstance(
            amount_node.op, ast.Sub,
        ):
            is_unlimited = True

        if is_unlimited:
            confidence = 0.88
            if self._is_test_context():
                confidence *= 0.20
            if confidence >= 0.30:
                self.findings.append(make_finding(
                    rule_id='AGENT-096',
                    pattern_type='defi_unlimited_token_approve',
                    file_path=self.file_path,
                    line=node.lineno,
                    confidence=confidence,
                    message=(
                        'Unlimited token approval (MAX_UINT256). '
                        'Approve only the exact amount needed.'
                    ),
                ))

    # ================================================================
    # AGENT-092: No human approval for transactions
    # ================================================================

    def _check_defi_no_human_approval_call(
        self, node: ast.Call, func_name: str,
    ):
        # Already handled at function level in _enter_function
        pass

    # ================================================================
    # AGENT-095 / AGENT-097: Transaction dict checks
    # ================================================================

    def _check_transaction_dict(self, node: ast.Dict):
        """Check transaction dictionary for missing gas/nonce fields."""
        if not self._is_transaction_dict(node):
            return

        keys_str = set()
        for k in node.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                keys_str.add(k.value)

        # AGENT-095: Missing gas limit
        if 'gas' not in keys_str and 'gasLimit' not in keys_str:
            confidence = 0.70
            if self._is_test_context():
                confidence *= 0.25
            if confidence >= 0.30:
                self.findings.append(make_finding(
                    rule_id='AGENT-095',
                    pattern_type='defi_missing_gas_limit',
                    file_path=self.file_path,
                    line=node.lineno,
                    confidence=confidence,
                    message='Transaction dictionary missing explicit gas limit.',
                ))
        else:
            # Check for excessive gas
            gas_key = 'gas' if 'gas' in keys_str else 'gasLimit'
            for k, v in zip(node.keys, node.values):
                if (
                    isinstance(k, ast.Constant)
                    and k.value == gas_key
                    and isinstance(v, ast.Constant)
                    and isinstance(v.value, int)
                    and v.value > 10_000_000
                ):
                    confidence = 0.75
                    if self._is_test_context():
                        confidence *= 0.25
                    if confidence >= 0.30:
                        self.findings.append(make_finding(
                            rule_id='AGENT-095',
                            pattern_type='defi_excessive_gas_limit',
                            file_path=self.file_path,
                            line=node.lineno,
                            confidence=confidence,
                            message=(
                                f'Excessive gas limit: {v.value}. '
                                f'Standard ETH transfer is 21,000.'
                            ),
                        ))

        # AGENT-097: Missing nonce
        if 'nonce' not in keys_str:
            confidence = 0.55
            if self._is_test_context():
                confidence *= 0.30
            if confidence >= 0.30:
                self.findings.append(make_finding(
                    rule_id='AGENT-097',
                    pattern_type='defi_missing_nonce_management',
                    file_path=self.file_path,
                    line=node.lineno,
                    confidence=confidence,
                    message=(
                        'Transaction dictionary missing nonce field. '
                        'Concurrent transactions may conflict.'
                    ),
                ))

    def _is_transaction_dict(self, node: ast.Dict) -> bool:
        """Heuristic: dict is likely a transaction if it has 'to' or 'value' keys."""
        tx_keys = {'to', 'value', 'from', 'data', 'gas', 'gasPrice',
                    'nonce', 'chainId', 'maxFeePerGas'}
        key_names = set()
        for k in node.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                key_names.add(k.value)
        return len(key_names & tx_keys) >= 2

    # ================================================================
    # Post-file checks (AGENT-098: MEV protection)
    # ================================================================

    def _post_file_checks(self):
        """Run checks that require file-level context."""
        if self._file_has_swap_call and not self._file_has_mev_protection:
            confidence = 0.60
            if self._is_test_context():
                confidence *= 0.30
            if confidence >= 0.30:
                self.findings.append(make_finding(
                    rule_id='AGENT-098',
                    pattern_type='defi_no_mev_protection',
                    file_path=self.file_path,
                    line=1,
                    confidence=confidence,
                    message=(
                        'File contains DEX swap calls without MEV protection '
                        '(no Flashbots or MEV Blocker detected).'
                    ),
                ))

    # ================================================================
    # Helpers
    # ================================================================

    def _is_approve_transact(self, node: ast.Call) -> bool:
        """Check if this is a .approve(...).transact() chain."""
        if isinstance(node.func, ast.Attribute):
            inner = node.func.value
            if isinstance(inner, ast.Call):
                inner_name = self._get_call_name(inner)
                if inner_name and inner_name.split('.')[-1] == 'approve':
                    return True
        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''

    def _has_tool_decorator(self, node: ast.FunctionDef) -> bool:
        """Check if function has @tool decorator."""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == 'tool':
                return True
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name) and dec.func.id == 'tool':
                    return True
                if isinstance(dec.func, ast.Attribute) and dec.func.attr == 'tool':
                    return True
        return False

    def _contains_blockchain_tx(self, node: ast.FunctionDef) -> bool:
        """Check if function body contains blockchain transaction calls."""
        all_tx_funcs = TRANSACTION_SEND_FUNCTIONS | CONTRACT_TRANSACT_FUNCTIONS
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and name.split('.')[-1] in all_tx_funcs:
                    return True
        return False

    def _contains_approval_gate(self, node: ast.FunctionDef) -> bool:
        """Check if function contains human approval patterns."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name:
                    name_lower = name.lower()
                    for pattern in HUMAN_APPROVAL_FUNCTION_PATTERNS:
                        if re.search(pattern, name_lower):
                            return True
            # input() call is also approval
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id == 'input':
                    return True
        return False

    def _has_amount_threshold_branch(self, node: ast.FunctionDef) -> bool:
        """Check if function has if-amount-threshold branching."""
        for child in ast.walk(node):
            if isinstance(child, ast.If):
                if isinstance(child.test, ast.Compare):
                    if self._involves_amount_variable(child.test):
                        return True
        return False

    def _is_test_context(self) -> bool:
        path_lower = self.file_path.lower()
        basename = path_lower.rsplit('/', 1)[-1] if '/' in path_lower else path_lower
        return (
            basename.startswith('test_')
            or basename.endswith('_test.py')
        )
