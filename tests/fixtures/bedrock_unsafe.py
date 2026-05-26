"""
Test fixture: AWS Bedrock + LangGraph multi-agent app.
Should trigger: DAI007 (BedrockSignature) and DAI003 (LangChain/LangGraph)
"""

import boto3
from langchain_aws import ChatBedrock
from langgraph.graph import StateGraph, MessagesState
from langgraph.prebuilt import ToolNode

# Layer 1 — boto3 direct invocation
bedrock_client = boto3.client("bedrock-runtime", region_name="us-east-1")
response = bedrock_client.invoke_model(
    modelId="anthropic.claude-3-sonnet-20240229-v1:0",
    body=b"...",
)

# Layer 1 — langchain_aws ChatBedrock
llm = ChatBedrock(
    model_id="mistral.mistral-large-2402-v1:0",
    region_name="us-east-1",
)

# Layer 1 — LangGraph multi-agent workflow with parallel workers
tool_node = ToolNode(tools=[])

workflow = StateGraph(MessagesState)
workflow.add_node("worker_1", lambda s: s)
workflow.add_node("worker_2", lambda s: s)
workflow.add_node("worker_3", lambda s: s)
workflow.add_edge("worker_1", "worker_2")
workflow.add_edge("worker_2", "worker_3")
workflow.set_entry_point("worker_1")
