"""
Test fixture: AutoGen agent with code execution explicitly disabled
Should trigger: DAI001 - warning (agent detected but safe)
"""
from autogen import AssistantAgent

# This should trigger a WARNING - agent exists but no code execution
safe_agent = AssistantAgent(
    name="safe_assistant",
    llm_config={"model": "gpt-4"},
    code_execution_config=False
)
