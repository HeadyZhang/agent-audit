"""Fixed: ast.literal_eval + math expression parser."""
import ast
import operator

SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


class CalculatorTool:
    name = "calculator"
    description = "Evaluate mathematical expressions safely"

    def run(self, expression: str) -> str:
        try:
            tree = ast.parse(expression, mode="eval")
            result = self._eval_node(tree.body)
            return str(result)
        except Exception as e:
            return f"Error: {e}"

    def _eval_node(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            op = SAFE_OPS.get(type(node.op))
            if op is None:
                raise ValueError(f"Unsupported operator: {type(node.op)}")
            return op(left, right)
        raise ValueError(f"Unsupported expression: {type(node)}")
