"""
Test fixture: AutoGen agent with code execution enabled (HIGH RISK)
Should trigger: DAI001 - error
"""

from autogen import AssistantAgent

# This should trigger an ERROR - code execution enabled
agent = AssistantAgent(
    name="code_executor",
    llm_config={"model": "gpt-4"},
    code_execution_config={"work_dir": "coding", "use_docker": True},
)

# Another pattern - code_execution_config with dict
risky_agent = AssistantAgent(name="risky", code_execution_config={"executor": "local"})
