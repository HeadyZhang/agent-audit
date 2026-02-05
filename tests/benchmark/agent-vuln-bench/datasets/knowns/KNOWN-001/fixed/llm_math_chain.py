"""
LangChain LLMMathChain — fixed version using numexpr
Source: langchain post-CVE-2023-29374 fix
Minimized for Agent-Vuln-Bench. Original code (c) LangChain contributors.

This module implements a chain that uses an LLM to solve math problems
by generating and evaluating mathematical expressions safely.

FIX: Uses numexpr for safe mathematical expression evaluation instead of eval().
numexpr only supports mathematical operations and cannot execute arbitrary code.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Safe math expression evaluator - only supports math operations
import numexpr


class BaseLLM:
    """Simplified LLM interface for demonstration."""

    def predict(self, prompt: str) -> str:
        """Generate text based on prompt."""
        raise NotImplementedError


class Chain:
    """Base chain class."""

    @property
    def input_keys(self) -> List[str]:
        return ["question"]

    @property
    def output_keys(self) -> List[str]:
        return ["answer"]

    def _call(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class LLMMathChain(Chain):
    """Chain for solving math problems using LLM + numexpr (safe).

    This chain takes a natural language math question, uses an LLM
    to translate it into a mathematical expression, and then evaluates
    the expression using numexpr.

    FIXED: Uses numexpr instead of eval() for safe expression evaluation.
    numexpr only supports mathematical operations and cannot execute
    arbitrary Python code.
    """

    llm: BaseLLM
    verbose: bool = False

    def __init__(self, llm: BaseLLM, verbose: bool = False):
        self.llm = llm
        self.verbose = verbose

    def _sanitize_expression(self, expression: str) -> str:
        """Basic sanitization of the expression.

        Args:
            expression: Raw expression from LLM.

        Returns:
            Sanitized expression safe for numexpr.
        """
        # Remove any non-math characters
        # Only allow: digits, operators, parentheses, decimal points, spaces
        allowed_chars = set("0123456789+-*/()., ")
        sanitized = "".join(c for c in expression if c in allowed_chars)
        return sanitized.strip()

    def _call(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Run the chain to solve a math problem.

        Args:
            inputs: Dict with 'question' key containing the math problem.

        Returns:
            Dict with 'answer' key containing the computed result.
        """
        question = inputs["question"]

        # Build prompt for the LLM
        prompt = f"""Translate this math question to a mathematical expression.
Only output numbers and basic operators (+, -, *, /).
Do not include any Python code or function calls.

Question: {question}
Expression:"""

        # Get LLM output
        llm_output = self.llm.predict(prompt)

        # Extract expression from LLM response
        expression = llm_output.strip()

        # Handle markdown code blocks
        if expression.startswith("```"):
            expression = expression.strip("`").strip()
            if expression.startswith("python"):
                expression = expression[6:].strip()

        # Additional sanitization
        expression = self._sanitize_expression(expression)

        if self.verbose:
            print(f"Expression: {expression}")

        # FIXED: Use numexpr instead of eval()
        # numexpr only evaluates mathematical expressions
        # It cannot execute arbitrary Python code
        try:
            output = str(numexpr.evaluate(expression))
        except Exception as e:
            output = f"Error evaluating expression: {e}"

        return {"answer": output}

    def run(self, question: str) -> str:
        """Convenience method to run the chain with a question."""
        result = self._call({"question": question})
        return result["answer"]
