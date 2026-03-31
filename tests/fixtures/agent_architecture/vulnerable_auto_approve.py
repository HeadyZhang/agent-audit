from autogen import AssistantAgent

agent = AssistantAgent(
    name="coder",
    human_input_mode="NEVER",
    code_execution_config={"use_docker": False}
)
