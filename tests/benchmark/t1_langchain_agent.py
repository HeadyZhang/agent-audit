"""
Benchmark T1: LangChain AgentExecutor without safety parameters.

Expected findings:
- ASI-01 (Goal Hijack) via missing max_iterations
- ASI-06 (Memory Poisoning) or ASI-08 (Cascading Failures)

This simulates a typical vulnerable LangChain agent setup.
"""

from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Results for: {query}"


@tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    with open(path, 'w') as f:
        f.write(content)
    return f"Wrote to {path}"


# VULNERABLE: AgentExecutor without safety parameters
llm = ChatOpenAI()
agent = create_react_agent(llm, [search_web, write_file], prompt)
executor = AgentExecutor(agent=agent, tools=[search_web, write_file], verbose=True)

# VULNERABLE: Direct user input to agent without sanitization
result = executor.invoke({"input": user_query})
