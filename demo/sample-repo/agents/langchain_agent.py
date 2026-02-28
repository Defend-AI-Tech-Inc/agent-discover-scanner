from langchain.agents import initialize_agent, Tool
from langchain.llms import OpenAI

llm = OpenAI(temperature=0)
tools = [Tool(name="search", func=lambda x: x, description="search")]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")


def run(query: str):
    return agent.run(query)
