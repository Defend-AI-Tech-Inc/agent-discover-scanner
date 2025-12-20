"""
Test fixture: CrewAI agent without code execution
Should trigger: DAI002 - warning (agent detected but safe)
"""
from crewai import Agent

# Safe agent - no code execution
safe_agent = Agent(
    role="Researcher",
    goal="Research topics",
    backstory="I search and analyze",
    allow_code_execution=False
)

# Agent without code execution specified (defaults to False)
default_agent = Agent(
    role="Writer",
    goal="Write content"
)
