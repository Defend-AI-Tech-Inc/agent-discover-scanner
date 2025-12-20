"""
Test fixture: LangChain agent patterns
Should trigger: DAI003 - warning
"""
from langchain.agents import initialize_agent, create_agent
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType

llm = ChatOpenAI()

# Legacy pattern
legacy_agent = initialize_agent(
    tools=[],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION
)

# Modern pattern
modern_agent = create_agent(
    llm=llm,
    tools=[]
)
