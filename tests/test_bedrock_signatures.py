"""
Tests for BedrockSignature (DAI007) and LangGraph extensions (DAI003).
"""

import ast
from pathlib import Path

from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
from agent_discover_scanner.visitor import ContextAwareVisitor


def _visit(source: str, filename: str = "test.py") -> ContextAwareVisitor:
    tree = ast.parse(source, filename=filename)
    visitor = ContextAwareVisitor(filename, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    return visitor


def bedrock_findings(source: str):
    return [f for f in _visit(source).findings if f.rule_id == "DAI007"]


def langchain_findings(source: str):
    return [f for f in _visit(source).findings if f.rule_id == "DAI003"]


# ---------------------------------------------------------------------------
# DAI007 — BedrockSignature
# ---------------------------------------------------------------------------


class TestBedrockChatBedrockDetection:
    def test_chatbedrock_detected(self):
        code = """
from langchain_aws import ChatBedrock
llm = ChatBedrock(model_id="anthropic.claude-3-sonnet-20240229-v1:0")
"""
        findings = bedrock_findings(code)
        assert any("ChatBedrock" in f.message for f in findings)
        assert any(f.severity == "warning" for f in findings)

    def test_bedrockllm_detected(self):
        code = """
from langchain_community.llms.bedrock import BedrockLLM
llm = BedrockLLM(model_id="amazon.titan-text-express-v1")
"""
        findings = bedrock_findings(code)
        assert any("BedrockLLM" in f.message for f in findings)

    def test_bedrock_embeddings_detected(self):
        code = """
from langchain_aws import BedrockEmbeddings
embeddings = BedrockEmbeddings(model_id="amazon.titan-embed-text-v1")
"""
        findings = bedrock_findings(code)
        assert any("BedrockEmbeddings" in f.message for f in findings)


class TestBedrockBoto3Detection:
    def test_boto3_client_bedrock_runtime(self):
        code = """
import boto3
client = boto3.client("bedrock-runtime", region_name="us-east-1")
"""
        findings = bedrock_findings(code)
        assert any("boto3 client" in f.message for f in findings)
        assert any(f.severity == "warning" for f in findings)

    def test_boto3_client_bedrock_agent_runtime(self):
        code = """
import boto3
client = boto3.client("bedrock-agent-runtime")
"""
        findings = bedrock_findings(code)
        assert any("boto3 client" in f.message for f in findings)

    def test_boto3_client_non_bedrock_not_flagged(self):
        code = """
import boto3
s3 = boto3.client("s3")
"""
        findings = bedrock_findings(code)
        assert len(findings) == 0

    def test_boto3_keyword_service_name(self):
        code = """
import boto3
client = boto3.client(service_name="bedrock-runtime")
"""
        findings = bedrock_findings(code)
        assert any("boto3 client" in f.message for f in findings)


class TestBedrockInvokeModelDetection:
    def test_invoke_model_with_bedrock_import(self):
        code = """
import boto3
client = boto3.client("bedrock-runtime")
response = client.invoke_model(modelId="anthropic.claude-3-sonnet-20240229-v1:0", body=b"")
"""
        findings = bedrock_findings(code)
        invoke_findings = [f for f in findings if "invoke_model" in f.message]
        assert len(invoke_findings) >= 1

    def test_invoke_model_without_bedrock_import_not_flagged(self):
        code = """
class Foo:
    def invoke_model(self):
        pass
f = Foo()
f.invoke_model()
"""
        findings = bedrock_findings(code)
        invoke_findings = [f for f in findings if "invoke_model" in f.message]
        assert len(invoke_findings) == 0


class TestBedrockStringMarkers:
    def test_model_id_string_anthropic_claude(self):
        code = 'model = "anthropic.claude-3-sonnet-20240229-v1:0"'
        findings = bedrock_findings(code)
        assert any("anthropic.claude-" in f.message for f in findings)
        assert all(f.severity == "note" for f in findings)

    def test_model_id_string_amazon_titan(self):
        code = 'model = "amazon.titan-text-express-v1"'
        findings = bedrock_findings(code)
        assert any("amazon.titan-" in f.message for f in findings)

    def test_model_id_string_meta_llama(self):
        code = 'model = "meta.llama3-8b-instruct-v1:0"'
        findings = bedrock_findings(code)
        assert any("meta.llama" in f.message for f in findings)

    def test_model_id_string_mistral_large(self):
        code = 'service = "mistral.mistral-large-2402-v1:0"'
        findings = bedrock_findings(code)
        assert any("mistral.mistral-large" in f.message for f in findings)

    def test_model_id_string_cohere_command(self):
        code = 'model_id = "cohere.command-r-plus-v1:0"'
        findings = bedrock_findings(code)
        assert any("cohere.command" in f.message for f in findings)

    def test_bedrock_runtime_endpoint_string(self):
        code = 'url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/..."'
        findings = bedrock_findings(code)
        assert any("bedrock-runtime" in f.message for f in findings)

    def test_clean_string_not_flagged(self):
        code = 'msg = "hello world, no bedrock here"'
        findings = bedrock_findings(code)
        assert len(findings) == 0


class TestBedrockFixtures:
    def test_bedrock_unsafe_fixture(self):
        fixture = Path("tests/fixtures/bedrock_unsafe.py")
        source = fixture.read_text()
        tree = ast.parse(source, filename=str(fixture))
        visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
        visitor.visit(tree)

        dai007 = [f for f in visitor.findings if f.rule_id == "DAI007"]
        dai003 = [f for f in visitor.findings if f.rule_id == "DAI003"]

        assert len(dai007) >= 2, f"Expected >=2 DAI007 findings, got {len(dai007)}"
        assert len(dai003) >= 1, f"Expected >=1 DAI003 findings, got {len(dai003)}"

    def test_bedrock_safe_fixture_no_dai007(self):
        fixture = Path("tests/fixtures/bedrock_safe.py")
        source = fixture.read_text()
        tree = ast.parse(source, filename=str(fixture))
        visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
        visitor.visit(tree)

        dai007 = [f for f in visitor.findings if f.rule_id == "DAI007"]
        # The safe fixture has no langchain/boto3 bedrock imports — no DAI007
        assert len(dai007) == 0

        # add_node / add_edge in the safe fixture should NOT be flagged
        # because langgraph is NOT imported
        dai003 = [f for f in visitor.findings if f.rule_id == "DAI003"]
        assert len(dai003) == 0


# ---------------------------------------------------------------------------
# DAI003 — LangGraph extensions
# ---------------------------------------------------------------------------


class TestLangGraphToolNode:
    def test_toolnode_detected(self):
        code = """
from langgraph.prebuilt import ToolNode
tool_node = ToolNode(tools=[])
"""
        findings = langchain_findings(code)
        assert any("ToolNode" in f.message for f in findings)
        assert all(f.severity == "note" for f in findings)


class TestLangGraphAddNodeAddEdge:
    def test_add_node_with_langgraph_import(self):
        code = """
from langgraph.graph import StateGraph
workflow = StateGraph(dict)
workflow.add_node("agent", lambda s: s)
"""
        findings = langchain_findings(code)
        add_node_findings = [f for f in findings if "add_node" in f.message]
        assert len(add_node_findings) >= 1
        assert all(f.severity == "note" for f in add_node_findings)

    def test_add_edge_with_langgraph_import(self):
        code = """
from langgraph.graph import StateGraph
workflow = StateGraph(dict)
workflow.add_edge("a", "b")
"""
        findings = langchain_findings(code)
        add_edge_findings = [f for f in findings if "add_edge" in f.message]
        assert len(add_edge_findings) >= 1

    def test_add_node_without_langgraph_import_not_flagged(self):
        """Generic add_node with no langgraph import must not produce DAI003."""
        code = """
class Graph:
    def add_node(self, name, fn):
        pass

g = Graph()
g.add_node("step", lambda x: x)
"""
        findings = langchain_findings(code)
        add_node_findings = [f for f in findings if "add_node" in f.message]
        assert len(add_node_findings) == 0


class TestExistingLangGraphFixtureStillPasses:
    def test_langgraph_workflow_fixture(self):
        """Existing fixture now produces StateGraph + 2 add_node findings."""
        fixture = Path("tests/fixtures/langgraph_workflow.py")
        source = fixture.read_text()
        tree = ast.parse(source, filename=str(fixture))
        visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
        visitor.visit(tree)

        lg_findings = [f for f in visitor.findings if f.rule_id == "DAI003"]
        assert len(lg_findings) >= 1
        assert any("StateGraph" in f.message for f in lg_findings)
        assert all(f.severity == "note" for f in lg_findings)
