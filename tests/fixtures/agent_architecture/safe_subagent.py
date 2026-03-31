from some_framework import Agent

class SafeAgent:
    def spawn_child(self):
        child = Agent(tools=[search_tool], name="researcher")
        return child
