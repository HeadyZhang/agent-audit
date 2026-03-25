"""DeFi Taint Tracking — Prompt Input to Blockchain Transaction.

Simplified intra-procedural taint tracker for detecting when
@tool function parameters (prompt input) flow unsanitized into
blockchain transaction parameters.

AGENT-093: Tainted tx address/value
AGENT-093b: Tainted contract call / dynamic dispatch
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from agent_audit.profiles.defi.constants.web3_apis import (
    CONTRACT_TRANSACT_FUNCTIONS,
    TRANSACTION_SEND_FUNCTIONS,
)
from agent_audit.profiles.defi.rules import DeFiFinding, make_finding

# Transaction field names that are dangerous when tainted
_DANGEROUS_TX_FIELDS = {'to', 'value', 'data'}

# Sanitizer function patterns — if param passes through these,
# taint is considered neutralized
_SANITIZER_PATTERNS = [
    re.compile(r'is_address', re.I),
    re.compile(r'isAddress', re.I),
    re.compile(r'is_checksum_address', re.I),
    re.compile(r'validate_address', re.I),
    re.compile(r'validate_amount', re.I),
    re.compile(r'check_balance', re.I),
    re.compile(r'whitelist', re.I),
    re.compile(r'allowlist', re.I),
    re.compile(r'approved_recipients', re.I),
    re.compile(r'in\s+ALLOWED', re.I),
]

# Web3 signing/sending functions (sinks)
_TX_SINKS = TRANSACTION_SEND_FUNCTIONS | CONTRACT_TRANSACT_FUNCTIONS | {
    'sign_transaction', 'signTransaction',
    'build_transaction', 'buildTransaction',
}


class SimpleDeFiTaintTracker:
    """Simplified taint tracker for @tool param -> Web3 tx flow.

    Strategy:
    1. Mark all function parameters as tainted sources
    2. Propagate taint through assignments (a = param -> a is tainted)
    3. Propagate taint through dict construction (tx = {'to': param})
    4. Check if tainted vars reach Web3 signing/sending API calls
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[DeFiFinding] = []

    def analyze_function(
        self,
        func_node: ast.FunctionDef,
        is_tool: bool = False,
    ) -> List[DeFiFinding]:
        """Analyze a single function for prompt->tx taint flows."""
        if not is_tool:
            return []

        params = {arg.arg for arg in func_node.args.args} - {'self', 'cls'}
        if not params:
            return []

        # Build taint set: start with function parameters
        tainted: Set[str] = set(params)

        # Check for sanitization
        sanitized: Set[str] = set()
        self._find_sanitized_params(func_node, params, sanitized)

        # Propagate taint through assignments
        # Also track taint origins for sanitization propagation
        taint_origins: Dict[str, Set[str]] = {p: {p} for p in params}
        self._propagate_taint(func_node, tainted, taint_origins)

        # Propagate sanitization: if all origins of a variable are
        # sanitized, the variable itself is considered sanitized
        for var, origins in taint_origins.items():
            if origins and origins.issubset(sanitized):
                sanitized.add(var)

        # Check for dynamic contract dispatch (getattr)
        self._check_dynamic_dispatch(func_node, tainted, sanitized)

        # Check if tainted vars flow to tx sinks
        self._check_taint_to_sinks(func_node, tainted, sanitized)

        return self.findings

    def _propagate_taint(
        self,
        func_node: ast.FunctionDef,
        tainted: Set[str],
        taint_origins: Optional[Dict[str, Set[str]]] = None,
    ):
        """Propagate taint through simple assignments."""
        if taint_origins is None:
            taint_origins = {}

        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                rhs_names = self._extract_names(node.value)
                tainted_rhs = rhs_names & tainted
                if tainted_rhs:
                    # Collect origins from all tainted rhs vars
                    origins: Set[str] = set()
                    for rhs_var in tainted_rhs:
                        origins |= taint_origins.get(rhs_var, {rhs_var})

                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted.add(target.id)
                            taint_origins[target.id] = origins.copy()
                        elif isinstance(target, ast.Tuple):
                            for elt in target.elts:
                                if isinstance(elt, ast.Name):
                                    tainted.add(elt.id)
                                    taint_origins[elt.id] = origins.copy()

            # Dict construction: tx = {'to': tainted_var}
            if isinstance(node, ast.Assign) and isinstance(
                node.value, ast.Dict,
            ):
                dict_origins: Set[str] = set()
                has_taint = False
                for val in node.value.values:
                    val_names = self._extract_names(val)
                    tainted_vals = val_names & tainted
                    if tainted_vals:
                        has_taint = True
                        for tv in tainted_vals:
                            dict_origins |= taint_origins.get(tv, {tv})
                if has_taint:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted.add(target.id)
                            taint_origins[target.id] = dict_origins

    def _find_sanitized_params(
        self,
        func_node: ast.FunctionDef,
        params: Set[str],
        sanitized: Set[str],
    ):
        """Find parameters that pass through sanitization."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name and any(
                    pat.search(call_name)
                    for pat in _SANITIZER_PATTERNS
                ):
                    # All params used in the sanitizer call are sanitized
                    arg_names = set()
                    for arg in node.args:
                        arg_names |= self._extract_names(arg)
                    sanitized |= (arg_names & params)

            # Check for `if param in WHITELIST` / `if param not in ...`
            # and `if param > LIMIT` / `if param <= MAX` (bound checks)
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare):
                    for op in test.ops:
                        if isinstance(op, (ast.In, ast.NotIn)):
                            left_names = self._extract_names(test.left)
                            sanitized |= (left_names & params)
                        # Bound checks: >, >=, <, <=
                        if isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
                            all_names = self._extract_names(test)
                            sanitized |= (all_names & params)
                # Also handle `not func(param)` like `not is_address(recipient)`
                if isinstance(test, ast.UnaryOp) and isinstance(
                    test.op, ast.Not,
                ):
                    if isinstance(test.operand, ast.Call):
                        call_name = self._get_call_name(test.operand)
                        if call_name and any(
                            pat.search(call_name)
                            for pat in _SANITIZER_PATTERNS
                        ):
                            arg_names = set()
                            for arg in test.operand.args:
                                arg_names |= self._extract_names(arg)
                            sanitized |= (arg_names & params)

    def _check_taint_to_sinks(
        self,
        func_node: ast.FunctionDef,
        tainted: Set[str],
        sanitized: Set[str],
    ):
        """Check if tainted (unsanitized) vars reach tx sinks."""
        effective_tainted = tainted - sanitized

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._get_call_name(node)
            if not call_name:
                continue

            simple_name = call_name.split('.')[-1]
            if simple_name not in _TX_SINKS:
                continue

            # Check if any argument to the sink uses tainted vars
            for arg in node.args:
                arg_names = self._extract_names(arg)
                tainted_in_arg = arg_names & effective_tainted
                if tainted_in_arg:
                    param_str = ', '.join(sorted(tainted_in_arg))
                    confidence = 0.92
                    self.findings.append(make_finding(
                        rule_id='AGENT-093',
                        pattern_type='defi_tainted_tx_address',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=confidence,
                        message=(
                            f'Tainted parameter(s) [{param_str}] flow to '
                            f'blockchain sink "{simple_name}" without '
                            f'sanitization.'
                        ),
                    ))
                    return  # One finding per function is enough

            # Check keyword arguments
            for kw in node.keywords:
                kw_names = self._extract_names(kw.value)
                tainted_in_kw = kw_names & effective_tainted
                if tainted_in_kw:
                    param_str = ', '.join(sorted(tainted_in_kw))
                    self.findings.append(make_finding(
                        rule_id='AGENT-093',
                        pattern_type='defi_tainted_tx_value',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=0.90,
                        message=(
                            f'Tainted parameter(s) [{param_str}] flow to '
                            f'blockchain sink "{simple_name}" via keyword arg.'
                        ),
                    ))
                    return

    def _check_dynamic_dispatch(
        self,
        func_node: ast.FunctionDef,
        tainted: Set[str],
        sanitized: Set[str],
    ):
        """Check for getattr(contract.functions, user_input) patterns."""
        effective_tainted = tainted - sanitized

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Name) and node.func.id == 'getattr'
            ):
                continue

            # getattr(obj, tainted_name) — dynamic dispatch
            if len(node.args) >= 2:
                attr_arg = node.args[1]
                attr_names = self._extract_names(attr_arg)
                tainted_names = attr_names & effective_tainted
                if tainted_names:
                    param_str = ', '.join(sorted(tainted_names))
                    self.findings.append(make_finding(
                        rule_id='AGENT-093',
                        pattern_type='defi_dynamic_contract_function',
                        file_path=self.file_path,
                        line=node.lineno,
                        confidence=0.95,
                        message=(
                            f'Dynamic contract function dispatch using '
                            f'tainted parameter(s) [{param_str}]. '
                            f'Attacker can call arbitrary contract methods.'
                        ),
                    ))

    def _extract_names(self, node: ast.AST) -> Set[str]:
        """Extract all Name identifiers from an AST node."""
        names: Set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
        return names

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
