"""
LangChain LLMMathChain — vulnerable version (CVE-2023-29374)
Source: langchain v0.0.64, chains/llm_math/base.py
Minimized for Agent-Vuln-Bench. Original code (c) LangChain contributors.

This module implements a chain that uses an LLM to solve math problems
by generating and evaluating Python expressions.

VULNERABILITY: Uses eval() on LLM output without sanitization.
An attacker can craft prompts that cause the LLM to return malicious
Python code, leading to arbitrary code execution.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


class BaseLLM:
    """Simplified LLM interface for demonstration."""

    def predict(self, prompt: str) -> str:
        """Generate text based on prompt."""
        # In real code, this calls an actual LLM
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
    """Chain for solving math problems using LLM + eval().

    This chain takes a natural language math question, uses an LLM
    to translate it into a Python expression, and then evaluates
    the expression using Python's eval().

    WARNING: This implementation is VULNERABLE to code injection.
    The LLM output is passed directly to eval() without any sanitization.
    """

    llm: BaseLLM
    verbose: bool = False

    def __init__(self, llm: BaseLLM, verbose: bool = False):
        self.llm = llm
        self.verbose = verbose

    def _call(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Run the chain to solve a math problem.

        Args:
            inputs: Dict with 'question' key containing the math problem.

        Returns:
            Dict with 'answer' key containing the computed result.
        """
        question = inputs["question"]

        # Build prompt for the LLM
        prompt = f"""Translate this math question to a Python expression.
Only output the expression, nothing else.

Question: {question}
Expression:"""

        # Get LLM output (SOURCE: LLM output - untrusted)
        llm_output = self.llm.predict(prompt)

        # Extract expression from LLM response
        expression = llm_output.strip()

        # Handle markdown code blocks that LLMs sometimes add
        if expression.startswith("```"):
            expression = expression.strip("`").strip()
            if expression.startswith("python"):
                expression = expression[6:].strip()

        if self.verbose:
            print(f"Expression: {expression}")

        # VULNERABILITY: eval() on LLM output without sanitization
        # CVE-2023-29374: LLM can return arbitrary Python code
        # An attacker can use prompt injection to make the LLM output:
        #   __import__('os').system('malicious_command')
        try:
            output = str(eval(expression))  # ← SINK: code execution
        except Exception as e:
            output = f"Error evaluating expression: {e}"

        return {"answer": output}

    def run(self, question: str) -> str:
        """Convenience method to run the chain with a question."""
        result = self._call({"question": question})
        return result["answer"]


# Example usage (DO NOT USE IN PRODUCTION)
if __name__ == "__main__":
    # This demonstrates the vulnerability
    # If an attacker controls the 'question' input, they can inject prompts
    # that cause the LLM to output malicious code

    class MockLLM(BaseLLM):
        def predict(self, prompt: str) -> str:
            # Simulating an LLM that has been tricked by prompt injection
            # to return malicious code instead of a math expression
            return "__import__('os').system('id')"

    # This would execute 'id' command on the system
    chain = LLMMathChain(llm=MockLLM(), verbose=True)
    # result = chain.run("What is 2 + 2?")  # Uncomment to test
