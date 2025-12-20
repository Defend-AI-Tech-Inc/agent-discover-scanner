"""
Test fixture: CrewAI agent with code execution enabled (HIGH RISK)
Should trigger: DAI002 - error
"""
from crewai import Agent
from crewai.tools import CodeInterpreterTool

# Pattern 1: allow_code_execution=True
dangerous_agent = Agent(
    role="Code Executor",
    goal="Execute arbitrary code",
    backstory="I run code",
    allow_code_execution=True
)

# Pattern 2: Using CodeInterpreterTool
code_agent = Agent(
    role="Analyst",
    goal="Analyze data",
    tools=[CodeInterpreterTool()]
)
