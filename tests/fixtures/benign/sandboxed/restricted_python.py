"""
BENIGN: RestrictedPython sandbox using AST-based safe evaluation.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
import ast
import operator
from langchain_core.tools import tool


# SAFE: AST-based calculator without using eval/exec
SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}


def _safe_eval_ast(node):
    """Safely evaluate AST node - no eval/exec used."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):  # Python 3.7 compatibility
        return node.n
    elif isinstance(node, ast.BinOp):
        left = _safe_eval_ast(node.left)
        right = _safe_eval_ast(node.right)
        op_func = SAFE_OPERATORS.get(type(node.op))
        if op_func and left is not None and right is not None:
            return op_func(left, right)
        return None
    elif isinstance(node, ast.UnaryOp):
        operand = _safe_eval_ast(node.operand)
        op_func = SAFE_OPERATORS.get(type(node.op))
        if op_func and operand is not None:
            return op_func(operand)
        return None
    return None


@tool
def restricted_eval(expression: str) -> str:
    """Evaluate math expression using safe AST parsing."""
    try:
        # SAFE: Pure AST-based evaluation, NO eval/exec
        tree = ast.parse(expression, mode='eval')
        result = _safe_eval_ast(tree.body)
        if result is not None:
            return str(result)
        return "Error: Expression contains unsupported operations"
    except Exception as e:
        return f"Error: {str(e)}"
