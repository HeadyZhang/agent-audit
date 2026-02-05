"""
Benchmark T3: LangChain standard memory usage.

Expected findings:
- Should have 0 findings or only INFO severity
- Framework allowlist should suppress AGENT-018 for standard patterns

This tests false positive suppression for common LangChain memory patterns.
"""

from langchain.memory import ConversationBufferMemory
from langchain_core.messages import HumanMessage, AIMessage

# Standard LangChain memory usage - should NOT trigger high severity
memory = ConversationBufferMemory()
memory.save_context({"input": "hello"}, {"output": "hi"})

# Standard message history - should NOT trigger high severity
history = []
history.append(HumanMessage(content="Hello"))
history.append(AIMessage(content="Hi there!"))
