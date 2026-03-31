from some_framework import Agent

class ParentAgent:
    def __init__(self):
        self.tools = [tool1, tool2, tool3]

    def spawn_child(self):
        child = Agent(tools=self.tools, name="researcher")
        return child
