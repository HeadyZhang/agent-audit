"""
BENIGN: Secure agent configuration with all safety features.
Expected: FALSE POSITIVE (any detection is FP)
"""
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool


def create_secure_agent(llm, tools: list[Tool]):
    """Create agent with all security controls enabled."""
    agent = create_react_agent(llm, tools, prompt=None)
    
    # SAFE: All safety parameters configured
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        max_iterations=10,           # Circuit breaker
        max_execution_time=60,       # Timeout
        early_stopping_method="generate",
        handle_parsing_errors=True,  # Error handling
        return_intermediate_steps=True,  # Transparency
        verbose=True,                # Logging
    )
    return executor
