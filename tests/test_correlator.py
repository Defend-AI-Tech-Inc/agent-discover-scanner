"""
Tests for correlation engine.
"""

import json
from datetime import datetime
from pathlib import Path

from agent_discover_scanner.correlator import AgentInventoryItem, CorrelationEngine


def test_agent_inventory_item_creation():
    """Test basic AgentInventoryItem creation."""
    item = AgentInventoryItem(
        agent_id="test:1",
        classification="confirmed",
        risk_level="high",
        code_file="test.py",
        framework="LangChain",
    )

    assert item.agent_id == "test:1"
    assert item.classification == "confirmed"
    assert item.risk_level == "high"
    assert item.discovered_at is not None  # Auto-generated


def test_extract_framework_from_rule():
    """Test framework extraction from rule IDs."""
    assert CorrelationEngine.extract_framework_from_rule("DAI001") == "AutoGen"
    assert CorrelationEngine.extract_framework_from_rule("DAI002") == "CrewAI"
    assert CorrelationEngine.extract_framework_from_rule("DAI003") == "LangChain/LangGraph"
    assert CorrelationEngine.extract_framework_from_rule("DAI004") == "Shadow AI"
    assert CorrelationEngine.extract_framework_from_rule("UNKNOWN") == "Unknown"


def test_correlate_with_no_network_findings():
    """Test correlation when no network activity detected."""
    code_findings = [
        {
            "rule_id": "DAI001",
            "file_path": "test.py",
            "line": 10,
            "message": "AutoGen AssistantAgent detected",
            "level": "warning",
        }
    ]
    network_findings = []

    inventory = CorrelationEngine.correlate(code_findings, network_findings)

    # Should be classified as UNKNOWN (code exists, no network traffic)
    assert len(inventory["unknown"]) == 1
    assert len(inventory["confirmed"]) == 0
    assert len(inventory["ghost"]) == 0
    assert inventory["unknown"][0].framework == "AutoGen"


def test_correlate_with_matching_traffic():
    """Test correlation when code and network match."""
    code_findings = [
        {
            "rule_id": "DAI004",
            "file_path": "agent.py",
            "line": 5,
            "message": "Unmanaged OpenAI client detected (Shadow AI)",
            "level": "error",
        }
    ]
    network_findings = [
        {
            "timestamp": datetime.now().isoformat(),
            "provider": "openai",
            "process_name": "python",
            "destination": "api.openai.com",
        }
    ]

    inventory = CorrelationEngine.correlate(code_findings, network_findings)

    # Should be classified as CONFIRMED (code + network)
    assert len(inventory["confirmed"]) == 1
    assert len(inventory["unknown"]) == 0
    assert inventory["confirmed"][0].network_provider == "openai"
    assert inventory["confirmed"][0].classification == "confirmed"


def test_correlate_ghost_agents():
    """Test detection of Ghost Agents (network but no code)."""
    code_findings = []
    network_findings = [
        {
            "timestamp": datetime.now().isoformat(),
            "provider": "anthropic",
            "process_name": "mystery_script.py",
            "destination": "api.anthropic.com",
        }
    ]

    inventory = CorrelationEngine.correlate(code_findings, network_findings)

    # Should detect a GHOST (network traffic with no code)
    assert len(inventory["ghost"]) == 1
    assert inventory["ghost"][0].classification == "ghost"
    assert inventory["ghost"][0].risk_level == "critical"
    assert inventory["ghost"][0].network_provider == "anthropic"


def test_correlate_risk_classification():
    """Test risk level assignment."""
    code_findings = [
        {
            "rule_id": "DAI001",
            "file_path": "test1.py",
            "line": 1,
            "message": "AutoGen AssistantAgent detected with CODE EXECUTION enabled (HIGH RISK)",
            "level": "error",
        },
        {
            "rule_id": "DAI004",
            "file_path": "test2.py",
            "line": 1,
            "message": "Unmanaged OpenAI client detected (Shadow AI)",
            "level": "error",
        },
        {
            "rule_id": "DAI003",
            "file_path": "test3.py",
            "line": 1,
            "message": "LangChain agent detected",
            "level": "warning",
        },
    ]
    network_findings = []

    inventory = CorrelationEngine.correlate(code_findings, network_findings)

    # Check risk levels
    items = inventory["unknown"]
    assert len(items) == 3

    # FIX: Check by has_code_execution attribute, not agent_id
    code_exec_item = next(i for i in items if i.has_code_execution)
    assert code_exec_item.risk_level == "high"

    # Shadow AI = critical risk
    shadow_item = next(i for i in items if i.code_file == "test2.py")
    assert shadow_item.risk_level == "critical"

    # Regular agent = medium risk
    regular_item = next(i for i in items if i.code_file == "test3.py")
    assert regular_item.risk_level == "medium"


def test_generate_report(tmp_path):
    """Test report generation with statistics."""
    inventory = {
        "confirmed": [
            AgentInventoryItem(
                agent_id="c1",
                classification="confirmed",
                risk_level="high",
                code_file="test.py",
                framework="AutoGen",
            )
        ],
        "unknown": [
            AgentInventoryItem(
                agent_id="u1",
                classification="unknown",
                risk_level="medium",
                code_file="test2.py",
                framework="LangChain",
            ),
            AgentInventoryItem(
                agent_id="u2",
                classification="unknown",
                risk_level="critical",
                code_file="test3.py",
                framework="Shadow AI",
            ),
        ],
        "zombie": [],
        "ghost": [
            AgentInventoryItem(
                agent_id="g1",
                classification="ghost",
                risk_level="critical",
                network_provider="openai",
            )
        ],
    }

    output_file = tmp_path / "test-report.json"
    report = CorrelationEngine.generate_report(inventory, output_file)

    # Check summary
    assert report["summary"]["total_agents"] == 4
    assert report["summary"]["confirmed"] == 1
    assert report["summary"]["unknown"] == 2
    assert report["summary"]["zombie"] == 0
    assert report["summary"]["ghost"] == 1

    # Check risk breakdown
    assert report["risk_breakdown"]["critical"] == 2
    assert report["risk_breakdown"]["high"] == 1
    assert report["risk_breakdown"]["medium"] == 1

    # Check file was written
    assert output_file.exists()

    # Verify file contents
    with open(output_file) as f:
        saved_report = json.load(f)
    assert saved_report["summary"]["total_agents"] == 4


def test_load_code_findings_from_sarif(tmp_path):
    """Test loading code findings from SARIF file."""
    sarif_file = tmp_path / "test.sarif"

    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "DAI001",
                        "level": "warning",
                        "message": {"text": "AutoGen detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    with open(sarif_file, "w") as f:
        json.dump(sarif_data, f)

    findings = CorrelationEngine.load_code_findings(sarif_file)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DAI001"
    assert findings[0]["file_path"] == "test.py"
    assert findings[0]["line"] == 10


def test_load_network_findings_from_json(tmp_path):
    """Test loading network findings from JSON file."""
    network_file = tmp_path / "network.json"

    network_data = {
        "findings": [
            {"timestamp": "2025-12-20T12:00:00Z", "provider": "openai", "process_name": "python"}
        ]
    }

    with open(network_file, "w") as f:
        json.dump(network_data, f)

    findings = CorrelationEngine.load_network_findings(network_file)

    assert len(findings) == 1
    assert findings[0]["provider"] == "openai"
    assert findings[0]["timestamp"] == "2025-12-20T12:00:00Z"


def test_load_missing_files():
    """Test graceful handling of missing files."""
    # Should return empty list, not crash
    assert CorrelationEngine.load_code_findings(Path("/fake/path.sarif")) == []
    assert CorrelationEngine.load_network_findings(Path("/fake/path.json")) == []
