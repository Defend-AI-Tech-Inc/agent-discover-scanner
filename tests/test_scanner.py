"""
Test suite for AgentDiscover Scanner.
"""
import ast
from pathlib import Path

from agent_discover_scanner.scanner import Scanner
from agent_discover_scanner.visitor import ContextAwareVisitor
from agent_discover_scanner.signatures import SIGNATURE_REGISTRY


def test_autogen_unsafe_detection():
    """Test detection of AutoGen with code execution."""
    fixture = Path("tests/fixtures/autogen_unsafe.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 2 high-risk AutoGen agents
    autogen_findings = [f for f in visitor.findings if f.rule_id == "DAI001"]
    assert len(autogen_findings) == 2
    assert all(f.severity == "error" for f in autogen_findings)
    assert all("HIGH RISK" in f.message for f in autogen_findings)


def test_autogen_safe_detection():
    """Test detection of safe AutoGen agent."""
    fixture = Path("tests/fixtures/autogen_safe.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 1 warning (agent exists but safe)
    autogen_findings = [f for f in visitor.findings if f.rule_id == "DAI001"]
    assert len(autogen_findings) == 1
    assert autogen_findings[0].severity == "warning"


def test_crewai_unsafe_detection():
    """Test detection of CrewAI with code execution."""
    fixture = Path("tests/fixtures/crewai_unsafe.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 2 high-risk CrewAI agents
    crew_findings = [f for f in visitor.findings if f.rule_id == "DAI002"]
    assert len(crew_findings) == 2
    assert all(f.severity == "error" for f in crew_findings)


def test_crewai_safe_detection():
    """Test detection of safe CrewAI agents."""
    fixture = Path("tests/fixtures/crewai_safe.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 2 warnings (agents exist but safe)
    crew_findings = [f for f in visitor.findings if f.rule_id == "DAI002"]
    assert len(crew_findings) == 2
    assert all(f.severity == "warning" for f in crew_findings)


def test_langchain_detection():
    """Test detection of LangChain agents."""
    fixture = Path("tests/fixtures/langchain_agents.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 2 LangChain agent initializations
    lc_findings = [f for f in visitor.findings if f.rule_id == "DAI003"]
    assert len(lc_findings) == 2
    assert all(f.severity == "warning" for f in lc_findings)


def test_langgraph_detection():
    """Test detection of LangGraph StateGraph."""
    fixture = Path("tests/fixtures/langgraph_workflow.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 1 StateGraph with note severity
    lg_findings = [f for f in visitor.findings if f.rule_id == "DAI003"]
    assert len(lg_findings) == 1
    assert lg_findings[0].severity == "note"
    assert "AgentWatch" in lg_findings[0].message


def test_shadow_ai_openai():
    """Test detection of unmanaged OpenAI clients."""
    fixture = Path("tests/fixtures/shadow_openai.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 2 unmanaged OpenAI clients
    shadow_findings = [f for f in visitor.findings if f.rule_id == "DAI004"]
    assert len(shadow_findings) == 2
    assert all(f.severity == "error" for f in shadow_findings)
    assert all("Shadow AI" in f.message for f in shadow_findings)


def test_shadow_ai_anthropic():
    """Test detection of unmanaged Anthropic clients."""
    fixture = Path("tests/fixtures/shadow_anthropic.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find 1 unmanaged Anthropic client
    shadow_findings = [f for f in visitor.findings if f.rule_id == "DAI004"]
    assert len(shadow_findings) == 1
    assert shadow_findings[0].severity == "error"


def test_safe_with_gateway():
    """Test that DefendAI Gateway usage is not flagged."""
    fixture = Path("tests/fixtures/safe_with_gateway.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find NO shadow AI findings
    shadow_findings = [f for f in visitor.findings if f.rule_id == "DAI004"]
    assert len(shadow_findings) == 0


def test_clean_code():
    """Test that clean code produces no findings."""
    fixture = Path("tests/fixtures/clean_code.py")
    source = fixture.read_text()
    tree = ast.parse(source, filename=str(fixture))
    
    visitor = ContextAwareVisitor(fixture, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Should find NOTHING
    assert len(visitor.findings) == 0


def test_scanner_ignores_venv():
    """Test that scanner respects ignore patterns."""
    scanner = Scanner(".")
    
    # Should ignore .venv directories
    assert scanner.should_ignore(Path(".venv/lib/python3.12/site-packages/foo.py"))
    assert scanner.should_ignore(Path("venv/lib/foo.py"))
    assert scanner.should_ignore(Path("__pycache__/foo.pyc"))
    
    # Should NOT ignore regular files
    assert not scanner.should_ignore(Path("src/agent_discover_scanner/cli.py"))


def test_import_resolution():
    """Test that import aliasing is resolved correctly."""
    code = """
import langchain as lc
from autogen import AssistantAgent as AA

agent1 = lc.agents.initialize_agent()
agent2 = AA()
"""
    tree = ast.parse(code)
    visitor = ContextAwareVisitor("test.py", signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    
    # Check import map
    assert visitor.import_map["lc"] == "langchain"
    assert visitor.import_map["AA"] == "autogen.AssistantAgent"
    
    # Check resolved names
    assert visitor.resolve_name("lc.agents.initialize_agent") == "langchain.agents.initialize_agent"
    assert visitor.resolve_name("AA") == "autogen.AssistantAgent"
