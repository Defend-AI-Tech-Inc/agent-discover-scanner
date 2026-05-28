"""
Regression tests for Layer 5 (Cloud Audit) / correlator integration.

Covers the three bugs fixed in v2.7.1:

  Bug 1 — Coverage table missing Layer 5:
    Layer 5 findings were merged into network_findings before correlate(), so
    matched code findings reported "layer1,layer2" instead of "layer1,layer5".
    Fix: split network_findings into l2_network/l5_cloud_audit inside correlate().

  Bug 2 — CONFIRMED not firing when Layer 1 + Layer 5:
    _is_known_executor(None) returns False for CloudTrail findings (process_name=None),
    blocking the Layer 2 match path. No separate Layer 5 path existed.
    Fix: add dedicated Layer 5 matching that bypasses the executor check.

  Bug 3 — SHADOW→GHOST misattribution:
    L5 CloudTrail findings (process_name=None) were appended to network_findings
    and overwrote Chrome→Bedrock in active_providers. is_known_desktop_app(None)
    returns False → GHOST instead of Shadow AI.
    Fix: active_providers is built from l2_network only.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_discover_scanner.correlator import CorrelationEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc).isoformat()


def _l5_bedrock_finding(
    *,
    timestamp: str = _NOW,
    username: str = "arn:aws:iam::123456789012:role/MyRole",
    source: str = "cloudtrail_historical",
) -> dict:
    """Minimal Layer 5 CloudTrail Bedrock finding dict as produced by scan_runner."""
    return {
        "provider": "bedrock",
        "process_name": None,
        "timestamp": timestamp,
        "source": source,
        "event_name": "InvokeModel",
        "username": username,
        "source_ip": "10.0.0.1",
        "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "framework": "boto3",
        "detection_layer": "layer5_cloud_audit",
    }


def _l2_bedrock_finding(*, process_name: str = "python3", timestamp: str = _NOW) -> dict:
    """Minimal Layer 2 network finding for Bedrock (no detection_layer key)."""
    return {
        "provider": "bedrock",
        "process_name": process_name,
        "timestamp": timestamp,
        "source": "layer2_network",
    }


def _l2_bedrock_chrome(*, timestamp: str = _NOW) -> dict:
    """Layer 2 Bedrock finding from a Chrome browser process (Shadow AI)."""
    return {
        "provider": "bedrock",
        "process_name": "Chrome",
        "timestamp": timestamp,
        "source": "layer2_network",
    }


def _cf_bedrock(*, file_path: str = "src/agent.py", line: int = 10) -> dict:
    """Minimal Layer 1 (code) finding for AWS Bedrock (DAI007)."""
    return {
        "rule_id": "DAI007",
        "file_path": file_path,
        "line": line,
        "message": "boto3 bedrock runtime call detected",
        "level": "warning",
    }


def _cf_openai(*, file_path: str = "src/other.py", line: int = 5) -> dict:
    """Minimal Layer 1 code finding for OpenAI (not Bedrock)."""
    return {
        "rule_id": "DAI005",
        "file_path": file_path,
        "line": line,
        "message": "openai API call detected",
        "level": "warning",
    }


# ---------------------------------------------------------------------------
# Bug 1 — Coverage table uses "layer5" not "layer2"
# ---------------------------------------------------------------------------


class TestBug1CoverageTableLayer5:
    """Layer 5 findings merged into network_findings must produce detection_layers=['layer1','layer5']."""

    def test_detection_layers_contains_layer5_not_layer2(self):
        """
        Regression: before the fix, detection_layers was ['layer1', 'layer2'] because
        the L5 finding was treated as a Layer 2 network finding.
        """
        cf = _cf_bedrock()
        l5 = _l5_bedrock_finding()

        # Simulate the merge scan_runner does before calling correlate()
        merged_network = [l5]

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=merged_network,
        )

        confirmed = inventory["confirmed"]
        assert len(confirmed) == 1, "Expected one CONFIRMED item"
        item = confirmed[0]
        assert "layer5" in item.detection_layers, (
            f"Expected 'layer5' in detection_layers; got {item.detection_layers}"
        )
        assert "layer2" not in item.detection_layers, (
            f"'layer2' should not be present when only L5 matched; got {item.detection_layers}"
        )
        assert item.detection_layers == ["layer1", "layer5"]

    def test_coverage_dict_key_is_layer1_layer5(self):
        """generate_report detection_coverage key must be 'layer1,layer5'."""
        cf = _cf_bedrock()
        l5 = _l5_bedrock_finding()
        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l5],
        )
        report = CorrelationEngine.generate_report(inventory)
        coverage = report["summary"]["detection_coverage"]
        assert "layer1,layer5" in coverage, (
            f"Expected key 'layer1,layer5' in coverage; got {list(coverage.keys())}"
        )
        assert coverage["layer1,layer5"] == 1
        # Old incorrect key must not be present
        assert "layer1,layer2" not in coverage

    def test_l1_only_remains_unknown_when_no_l5(self):
        """Sanity: code-only finding without any runtime data stays UNKNOWN."""
        cf = _cf_bedrock()
        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[],
        )
        assert len(inventory["unknown"]) == 1
        assert inventory["unknown"][0].detection_layers == ["layer1"]

    def test_layer1_layer2_still_works_when_l2_matches(self):
        """L2 (python3 process) still produces 'layer1,layer2' for non-Bedrock findings."""
        cf = _cf_openai()
        l2 = {"provider": "openai", "process_name": "python3", "timestamp": _NOW}
        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l2],
        )
        confirmed = inventory["confirmed"]
        assert len(confirmed) == 1
        assert "layer2" in confirmed[0].detection_layers
        assert "layer5" not in confirmed[0].detection_layers


# ---------------------------------------------------------------------------
# Bug 2 — CONFIRMED not firing for Layer 1 + Layer 5
# ---------------------------------------------------------------------------


class TestBug2ConfirmedL1L5:
    """L1 Bedrock code finding + L5 CloudTrail finding → CONFIRMED."""

    def test_l1_plus_l5_gives_confirmed(self):
        """
        Regression: before the fix, _is_known_executor(None) returned False,
        so the L2 match path was blocked and the item stayed UNKNOWN.
        """
        cf = _cf_bedrock()
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l5],
        )

        assert len(inventory["confirmed"]) == 1, (
            f"Expected CONFIRMED; got confirmed={inventory['confirmed']}, "
            f"unknown={inventory['unknown']}"
        )
        assert len(inventory["unknown"]) == 0

    def test_l1_langgraph_bedrock_plus_l5_gives_confirmed(self):
        """LangGraph/LangChain DAI003 findings with 'bedrock' in message also match Layer 5."""
        cf = {
            "rule_id": "DAI003",
            "file_path": "src/graph.py",
            "line": 42,
            "message": "LangGraph StateGraph using Amazon Bedrock as the LLM backend",
            "level": "warning",
        }
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l5],
        )

        assert len(inventory["confirmed"]) == 1
        item = inventory["confirmed"][0]
        assert "layer5" in item.detection_layers

    def test_l1_bedrock_without_runtime_stays_unknown(self):
        """Code finding with no runtime evidence (L2 or L5) stays UNKNOWN."""
        cf = _cf_bedrock()
        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[],
        )
        assert len(inventory["unknown"]) == 1
        assert len(inventory["confirmed"]) == 0

    def test_l1_plus_l5_network_provider_is_bedrock(self):
        """CONFIRMED item's network_provider must be 'bedrock'."""
        inventory = CorrelationEngine.correlate(
            code_findings=[_cf_bedrock()],
            network_findings=[_l5_bedrock_finding()],
        )
        item = inventory["confirmed"][0]
        assert item.network_provider == "bedrock"

    def test_l1_plus_l5_last_seen_populated(self):
        """last_seen is populated from the CloudTrail timestamp."""
        ts = "2026-01-15T08:30:00+00:00"
        inventory = CorrelationEngine.correlate(
            code_findings=[_cf_bedrock()],
            network_findings=[_l5_bedrock_finding(timestamp=ts)],
        )
        item = inventory["confirmed"][0]
        assert item.last_seen == ts

    def test_l1_plus_l5_process_name_is_iam_principal(self):
        """process_name carries the IAM principal from CloudTrail (no L2 process)."""
        arn = "arn:aws:iam::123456789012:role/BedrockAgentRole"
        inventory = CorrelationEngine.correlate(
            code_findings=[_cf_bedrock()],
            network_findings=[_l5_bedrock_finding(username=arn)],
        )
        item = inventory["confirmed"][0]
        assert item.process_name == arn

    def test_l1_plus_l2_plus_l5_all_three_layers(self):
        """When both L2 and L5 match, detection_layers contains all three."""
        cf = _cf_bedrock()
        l2 = _l2_bedrock_finding(process_name="python3")
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l2, l5],
        )

        item = inventory["confirmed"][0]
        assert "layer1" in item.detection_layers
        assert "layer2" in item.detection_layers
        assert "layer5" in item.detection_layers

    def test_l2_process_name_wins_when_both_l2_and_l5_match(self):
        """When both L2 and L5 match, the L2 process_name is used (not IAM principal)."""
        l2 = _l2_bedrock_finding(process_name="python3")
        l5 = _l5_bedrock_finding(username="arn:aws:iam::123:role/Role")

        inventory = CorrelationEngine.correlate(
            code_findings=[_cf_bedrock()],
            network_findings=[l2, l5],
        )
        item = inventory["confirmed"][0]
        # L2 process_name should take precedence over IAM principal
        assert item.process_name == "python3"

    def test_non_bedrock_code_finding_not_matched_by_l5_bedrock(self):
        """OpenAI code finding must NOT be matched by Bedrock CloudTrail data."""
        cf = _cf_openai()
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l5],
        )
        # OpenAI finding has no runtime evidence → UNKNOWN
        assert len(inventory["unknown"]) == 1
        assert len(inventory["confirmed"]) == 0


# ---------------------------------------------------------------------------
# Bug 3 — SHADOW→GHOST misattribution
# ---------------------------------------------------------------------------


class TestBug3ShadowGhostMisattribution:
    """Chrome→Bedrock (Shadow AI) must not be reclassified as GHOST by Layer 5."""

    def test_chrome_bedrock_stays_shadow_ai_when_l5_present(self):
        """
        Regression: before the fix, L5 finding (process_name=None) overwrote
        active_providers["bedrock"], then is_known_desktop_app(None) returned False
        → GHOST instead of Shadow AI.
        """
        l2_chrome = _l2_bedrock_chrome()
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l2_chrome, l5],
        )

        shadow = inventory["shadow_ai_usage"]
        ghost = inventory["ghost"]

        assert len(shadow) == 1, (
            f"Chrome→Bedrock should be Shadow AI; shadow={shadow}, ghost={ghost}"
        )
        assert shadow[0].process_name == "Chrome"

        # Ghost list may have a Layer 5 entry for the CloudTrail activity,
        # but it must NOT be from the Chrome process (Bug 3 regression guard).
        for g in ghost:
            assert g.process_name != "Chrome", (
                "Chrome process must never appear as a GHOST"
            )

    def test_l5_only_gives_ghost_when_no_l2(self):
        """L5 Bedrock with no L2 activity and no code finding → GHOST with layer5."""
        l5 = _l5_bedrock_finding(username="arn:aws:iam::123456789012:role/LambdaRole")

        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l5],
        )

        ghost = inventory["ghost"]
        assert len(ghost) == 1, f"Expected one ghost; got {ghost}"
        item = ghost[0]
        assert item.detection_layers == ["layer5"]
        assert item.network_provider == "bedrock"
        assert "LambdaRole" in (item.process_name or "")

    def test_l5_ghost_agent_id_format(self):
        """Layer 5 ghost agent_id has the expected 'ghost:bedrock:cloudtrail:' prefix."""
        principal = "arn:aws:iam::123456789012:role/LambdaRole"
        l5 = _l5_bedrock_finding(username=principal)

        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l5],
        )
        item = inventory["ghost"][0]
        assert item.agent_id.startswith("ghost:bedrock:cloudtrail:")

    def test_l5_ghost_risk_is_critical(self):
        """Unmatched CloudTrail Bedrock activity is classified as critical risk."""
        l5 = _l5_bedrock_finding()
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l5],
        )
        assert inventory["ghost"][0].risk_level == "critical"

    def test_l5_ghost_not_created_when_bedrock_confirmed_via_l1(self):
        """No Layer 5 ghost when Bedrock is already CONFIRMED (L1+L5)."""
        cf = _cf_bedrock()
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[cf],
            network_findings=[l5],
        )

        assert len(inventory["confirmed"]) == 1
        assert len(inventory["ghost"]) == 0

    def test_l5_ghost_not_created_when_bedrock_shadow_from_l2(self):
        """No Layer 5 ghost when Bedrock is already classified as Shadow AI (Chrome→L2)."""
        l2_chrome = _l2_bedrock_chrome()
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l2_chrome, l5],
        )

        # Shadow AI from Chrome→Bedrock (L2) means bedrock is "seen";
        # the L5 ghost loop must not fire a second Bedrock ghost.
        bedrock_ghosts = [g for g in inventory["ghost"] if g.network_provider == "bedrock"]
        assert len(bedrock_ghosts) == 0, (
            f"No bedrock ghost expected when shadow_ai already accounts for it; "
            f"got {bedrock_ghosts}"
        )

    def test_active_providers_not_polluted_by_l5_process_none(self):
        """
        Core invariant: active_providers must never contain a 'process': None entry
        from a Layer 5 finding when a Layer 2 process is present.

        Validated indirectly: if active_providers were polluted, Chrome's Shadow AI
        classification would flip to GHOST (is_known_desktop_app(None) → False).
        This test confirms the fix works end-to-end.
        """
        # Two L2 findings for different providers
        l2_chrome_bedrock = _l2_bedrock_chrome()
        l2_python_openai = {
            "provider": "openai",
            "process_name": "python3",
            "timestamp": _NOW,
        }
        # L5 Bedrock overwrites in the buggy version
        l5 = _l5_bedrock_finding()

        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l2_chrome_bedrock, l2_python_openai, l5],
        )

        # Chrome→Bedrock must still be Shadow AI
        shadow_providers = {item.network_provider for item in inventory["shadow_ai_usage"]}
        ghost_providers = {item.network_provider for item in inventory["ghost"]}

        assert "bedrock" in shadow_providers, (
            f"Chrome→Bedrock should be shadow_ai; shadow={shadow_providers}, ghost={ghost_providers}"
        )
        # OpenAI (python3 with no code finding) should be GHOST
        assert "openai" in ghost_providers


# ---------------------------------------------------------------------------
# _is_bedrock_finding helper
# ---------------------------------------------------------------------------


class TestIsBedrockFinding:
    """Unit tests for the _is_bedrock_finding classmethod."""

    def test_dai007_is_bedrock(self):
        cf = {"rule_id": "DAI007", "message": ""}
        assert CorrelationEngine._is_bedrock_finding(cf) is True

    def test_message_contains_bedrock(self):
        cf = {"rule_id": "DAI003", "message": "LangGraph with Amazon Bedrock backend"}
        assert CorrelationEngine._is_bedrock_finding(cf) is True

    def test_message_bedrock_case_insensitive(self):
        cf = {"rule_id": "DAI003", "message": "BEDROCK runtime call"}
        assert CorrelationEngine._is_bedrock_finding(cf) is True

    def test_openai_finding_is_not_bedrock(self):
        cf = {"rule_id": "DAI005", "message": "openai API call"}
        assert CorrelationEngine._is_bedrock_finding(cf) is False

    def test_missing_fields_is_not_bedrock(self):
        assert CorrelationEngine._is_bedrock_finding({}) is False

    def test_none_values_is_not_bedrock(self):
        cf = {"rule_id": None, "message": None}
        assert CorrelationEngine._is_bedrock_finding(cf) is False
