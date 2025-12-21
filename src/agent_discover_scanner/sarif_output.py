"""
SARIF (Static Analysis Results Interchange Format) output generator.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from agent_discover_scanner.visitor import Finding


class SARIFGenerator:
    """Generate SARIF 2.1.0 compliant output."""

    TOOL_NAME = "AgentDiscover Scanner"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://defendai.ai/agentdiscover"

    # Rule definitions
    RULES = {
        "DAI001": {
            "id": "DAI001",
            "name": "AutoGenAgentDetection",
            "shortDescription": {"text": "AutoGen AssistantAgent detected"},
            "fullDescription": {
                "text": "Detects AutoGen AssistantAgent instances. High risk if code execution is enabled."
            },
            "defaultConfiguration": {"level": "warning"},
            "help": {
                "text": "AutoGen agents with code execution capabilities can execute arbitrary code. Ensure proper sandboxing and monitoring."
            },
        },
        "DAI002": {
            "id": "DAI002",
            "name": "CrewAIAgentDetection",
            "shortDescription": {"text": "CrewAI Agent detected"},
            "fullDescription": {
                "text": "Detects CrewAI Agent instances. High risk if code execution is enabled via allow_code_execution or CodeInterpreterTool."
            },
            "defaultConfiguration": {"level": "warning"},
            "help": {
                "text": "CrewAI agents with code execution should be monitored and contained using DefendAI ContainIQ."
            },
        },
        "DAI003": {
            "id": "DAI003",
            "name": "LangChainAgentDetection",
            "shortDescription": {"text": "LangChain/LangGraph agent pattern detected"},
            "fullDescription": {
                "text": "Detects LangChain agent initialization and LangGraph StateGraph workflows."
            },
            "defaultConfiguration": {"level": "warning"},
            "help": {
                "text": "LangChain agents should be cataloged in AgentWatch. StateGraph workflows benefit from deep tracing."
            },
        },
        "DAI004": {
            "id": "DAI004",
            "name": "ShadowAIDetection",
            "shortDescription": {"text": "Unmanaged LLM client detected (Shadow AI)"},
            "fullDescription": {
                "text": "Detects direct instantiation of OpenAI or Anthropic clients without DefendAI Gateway routing."
            },
            "defaultConfiguration": {"level": "error"},
            "help": {
                "text": "All LLM access should route through DefendAI Gateway for policy enforcement, observability, and cost tracking."
            },
        },
    }

    @classmethod
    def generate(cls, findings: List[Finding], scan_root: Path) -> dict:
        """
        Generate SARIF report from findings.

        Args:
            findings: List of Finding objects
            scan_root: Root path that was scanned

        Returns:
            SARIF report as dictionary
        """
        # Convert findings to SARIF results
        results = []
        for finding in findings:
            result = cls._finding_to_sarif_result(finding, scan_root)
            results.append(result)

        # Build SARIF structure
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": cls.TOOL_NAME,
                            "version": cls.TOOL_VERSION,
                            "informationUri": cls.TOOL_URI,
                            "rules": list(cls.RULES.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        return sarif

    @classmethod
    def _finding_to_sarif_result(cls, finding: Finding, scan_root: Path) -> dict:
        """Convert a Finding to SARIF result format."""
        # Make path relative to scan root for portability
        try:
            relative_path = Path(finding.file_path).relative_to(scan_root)
        except ValueError:
            # If path is not relative to scan_root, use absolute
            relative_path = Path(finding.file_path)

        # Map severity
        level_map = {"error": "error", "warning": "warning", "note": "note"}

        result = {
            "ruleId": finding.rule_id,
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(relative_path), "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": finding.lineno,
                            "startColumn": finding.col_offset + 1,  # SARIF uses 1-based columns
                        },
                    }
                }
            ],
        }

        return result

    @classmethod
    def write_sarif(cls, findings: List[Finding], scan_root: Path, output_path: Path):
        """Generate and write SARIF report to file."""
        sarif = cls.generate(findings, scan_root)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
