"""
BENIGN: Code execution in sandbox.
Expected: NO FINDINGS (any detection is FALSE POSITIVE)
"""
from langchain_core.tools import tool


@tool
def sandboxed_eval(expression: str) -> str:
    """Evaluate expression in restricted sandbox."""
    try:
        import ast
        import operator

        # SAFE: AST-based safe evaluation (NO eval/exec used)
        allowed_operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
        }

        def eval_expr(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                left = eval_expr(node.left)
                right = eval_expr(node.right)
                op = allowed_operators.get(type(node.op))
                if op is None:
                    return None  # Graceful handling
                return op(left, right)
            else:
                return None  # Graceful handling

        tree = ast.parse(expression, mode='eval')
        result = eval_expr(tree.body)
        return str(result) if result is not None else "Error: Invalid expression"
    except Exception as e:
        return f"Error: {str(e)}"
