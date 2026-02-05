"""
Benign: safe ast.literal_eval instead of eval.
Expected: AGENT-034 should not fire (or SUPPRESSED).
"""
import ast


def safe_parse(value_str: str):
    result = ast.literal_eval(value_str)
    return result
