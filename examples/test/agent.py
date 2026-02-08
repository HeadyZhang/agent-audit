"""
Intentionally Vulnerable AI Agent - For Testing agent-audit
============================================================
DO NOT USE IN PRODUCTION. This file contains deliberate security flaws.

Each vulnerability is marked with the corresponding rule ID that should detect it.
"""

import os
import subprocess
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain.prompts import ChatPromptTemplate
from langchain.memory import ConversationBufferMemory

# =============================================================================
# AGENT-004: Hardcoded Credentials
# =============================================================================
# Hardcoded API key - should use environment variables instead
OPENAI_API_KEY = "sk-proj-EXAMPLE-KEY-DO-NOT-USE-1234567890abcdef"
ANTHROPIC_API_KEY = "sk-ant-api03-EXAMPLE-DO-NOT-USE-abcdefghijklmnop"


# =============================================================================
# AGENT-001 / AGENT-017: Code Execution with User Input
# =============================================================================
@tool
def calculate(expression: str) -> str:
    """Evaluate a mathematical expression."""
    # DANGEROUS: eval() with user input allows arbitrary code execution
    result = eval(expression)  # AGENT-001: Command injection via eval
    return str(result)


# =============================================================================
# AGENT-034: Tool Without Input Validation + Shell Execution
# =============================================================================
@tool
def run_command(command: str) -> str:
    """Run a shell command and return output."""
    # DANGEROUS: No input validation, shell=True with user input
    result = subprocess.run(
        command,
        shell=True,  # AGENT-034: Unvalidated input to dangerous operation
        capture_output=True,
        text=True
    )
    return result.stdout


# =============================================================================
# AGENT-041: SQL Injection
# =============================================================================
@tool
def search_users(name: str) -> str:
    """Search for users by name in database."""
    # DANGEROUS: SQL injection via string interpolation
    query = f"SELECT * FROM users WHERE name = '{name}'"  # AGENT-041: SQL injection
    # cursor.execute(query)  # Would execute the vulnerable query
    return f"Query: {query}"


# =============================================================================
# AGENT-010: System Prompt Injection
# =============================================================================
def create_agent(user_context: str):
    """Create an agent with user-provided context."""
    # DANGEROUS: User input directly in system prompt
    system_prompt = f"""You are a helpful assistant.
    User context: {user_context}
    Follow the user's instructions carefully."""  # AGENT-010: Prompt injection

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
    ])

    tools = [calculate, run_command, search_users]

    # =========================================================================
    # AGENT-021 / AGENT-028: Missing Iteration Limit
    # =========================================================================
    # DANGEROUS: No max_iterations - agent could loop forever
    executor = AgentExecutor(
        agent=None,  # Would be create_react_agent(llm, tools, prompt)
        tools=tools,
        memory=ConversationBufferMemory(),
        verbose=True,
        # Missing: max_iterations=10  # AGENT-021: No iteration limit
        # Missing: handle_parsing_errors=True
    )

    return executor


# =============================================================================
# AGENT-003: Data Exfiltration Chain
# =============================================================================
@tool
def get_secret(name: str) -> str:
    """Retrieve a secret by name."""
    # This tool accesses sensitive data
    return os.environ.get(name, "")


@tool
def send_webhook(url: str, data: str) -> str:
    """Send data to a webhook URL."""
    import requests
    # Combined with get_secret, this creates a data exfiltration path
    response = requests.post(url, json={"data": data})  # AGENT-003
    return f"Status: {response.status_code}"


if __name__ == "__main__":
    print("This is a vulnerable agent for testing agent-audit.")
    print("Run: agent-audit scan examples/vulnerable-agent/")
