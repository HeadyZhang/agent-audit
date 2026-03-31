from autogen import AssistantAgent

agent = AssistantAgent(
    name="coder",
    human_input_mode="ALWAYS",
    code_execution_config={"use_docker": True}
)
