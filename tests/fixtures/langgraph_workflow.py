"""
Test fixture: LangGraph StateGraph (complex workflow)
Should trigger: DAI003 - note (recommend AgentWatch tracing)
"""

from typing import TypedDict

from langgraph.graph import StateGraph


class AgentState(TypedDict):
    messages: list[str]
    next: str


# Complex stateful workflow
workflow = StateGraph(AgentState)
workflow.add_node("agent", lambda x: x)
workflow.add_node("tools", lambda x: x)
workflow.set_entry_point("agent")
