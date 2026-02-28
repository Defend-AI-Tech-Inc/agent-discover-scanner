# DAI001 - AutoGen AssistantAgent
from autogen import AssistantAgent

assistant = AssistantAgent(
    name="assistant",
    system_message="You are a helpful assistant.",
    code_execution_config=False,
)


def run(query: str):
    return assistant.receive(query, assistant)
