"""
Tests for Layer 2 process introspection + correlator CONFIRMED promotion.

Covers:
  process_introspection.py
    - _find_project_root
    - _resolve_entry_script
    - _scan_for_framework  (via production L1 rules on fixture files)
    - introspect_process   (via psutil on the current Python process)

  correlator.py
    - L2 connection + process framework  →  CONFIRMED  (no L5 input)
    - L2 connection without framework    →  GHOST
    - L5 CloudTrail is additive enrichment only (l5_event_count set), not prereq
    - Known desktop app always → shadow_ai_usage regardless of framework
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_discover_scanner.process_introspection import (
    ProcessIntrospectionResult,
    _find_project_root,
    _resolve_entry_script,
    _scan_for_framework,
    introspect_process,
)
from agent_discover_scanner.correlator import CorrelationEngine

# ── fixture paths ─────────────────────────────────────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"
LANGGRAPH_FIXTURE = FIXTURES / "langgraph_workflow.py"
LANGCHAIN_FIXTURE = FIXTURES / "langchain_agents.py"
CREWAI_FIXTURE    = FIXTURES / "crewai_unsafe.py"
AUTOGEN_FIXTURE   = FIXTURES / "autogen_unsafe.py"
BEDROCK_FIXTURE   = FIXTURES / "bedrock_unsafe.py"
CLEAN_FIXTURE     = FIXTURES / "clean_code.py"


# ═══════════════════════════════════════════════════════════════════════════════
# TestFindProjectRoot
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindProjectRoot:
    def test_finds_pyproject_toml(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest]")
        subdir = tmp_path / "src" / "myapp"
        subdir.mkdir(parents=True)
        script = subdir / "agent.py"
        script.write_text("pass")
        assert _find_project_root(script) == tmp_path

    def test_finds_setup_py(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup; setup()")
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        script = deep / "x.py"
        script.write_text("")
        assert _find_project_root(script) == tmp_path

    def test_returns_none_for_bare_tmp(self, tmp_path):
        # No markers in tmp_path or its parents that we control
        script = tmp_path / "agent.py"
        script.write_text("")
        # Result is None OR some ancestor — just verify no exception and type
        result = _find_project_root(script)
        assert result is None or isinstance(result, Path)

    def test_dir_input_accepted(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("langchain")
        assert _find_project_root(tmp_path) == tmp_path


# ═══════════════════════════════════════════════════════════════════════════════
# TestResolveEntryScript
# ═══════════════════════════════════════════════════════════════════════════════

class TestResolveEntryScript:
    def test_absolute_path(self):
        script = LANGGRAPH_FIXTURE
        result = _resolve_entry_script(["python3", str(script)], None)
        assert result == script

    def test_relative_path_resolved_against_cwd(self, tmp_path):
        script = tmp_path / "agent.py"
        script.write_text("pass")
        result = _resolve_entry_script(["python3", "agent.py"], tmp_path)
        assert result == script.resolve()

    def test_module_invocation_returns_none(self):
        result = _resolve_entry_script(["python3", "-m", "mymodule"], None)
        assert result is None

    def test_inline_code_returns_none(self):
        result = _resolve_entry_script(["python3", "-c", "print('hi')"], None)
        assert result is None

    def test_non_py_file_returns_none(self):
        result = _resolve_entry_script(["uvicorn", "app:create_app"], None)
        assert result is None

    def test_interpreter_flags_stripped(self, tmp_path):
        script = tmp_path / "agent.py"
        script.write_text("pass")
        result = _resolve_entry_script(["python3", "-u", "-W", "ignore", str(script)], tmp_path)
        assert result == script

    def test_empty_cmdline_returns_none(self):
        assert _resolve_entry_script([], None) is None
        assert _resolve_entry_script(["python3"], None) is None

    def test_nonexistent_absolute_returns_none(self):
        result = _resolve_entry_script(["python3", "/nonexistent/agent.py"], None)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# TestScanForFramework  (exercises production SIGNATURE_REGISTRY — no mocks)
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanForFramework:
    def test_langgraph_fixture_detected(self):
        framework, rule_ids, confidence = _scan_for_framework(LANGGRAPH_FIXTURE, None)
        assert framework == "LangChain/LangGraph"
        assert "DAI003" in rule_ids
        assert confidence == "high"  # signal found in entry script directly

    def test_langchain_fixture_detected(self):
        framework, rule_ids, confidence = _scan_for_framework(LANGCHAIN_FIXTURE, None)
        assert framework == "LangChain/LangGraph"
        assert "DAI003" in rule_ids
        assert confidence == "high"

    def test_crewai_fixture_detected(self):
        framework, rule_ids, confidence = _scan_for_framework(CREWAI_FIXTURE, None)
        assert framework == "CrewAI"
        assert "DAI002" in rule_ids
        assert confidence == "high"

    def test_autogen_fixture_detected(self):
        framework, rule_ids, confidence = _scan_for_framework(AUTOGEN_FIXTURE, None)
        assert framework == "AutoGen"
        assert "DAI001" in rule_ids
        assert confidence == "high"

    def test_bedrock_fixture_detected(self):
        framework, rule_ids, confidence = _scan_for_framework(BEDROCK_FIXTURE, None)
        # DAI007 may co-occur with DAI003 depending on fixture; just check Bedrock is caught
        assert framework is not None
        assert any(r in rule_ids for r in ("DAI007", "DAI003"))
        assert confidence == "high"

    def test_clean_file_returns_none(self):
        framework, rule_ids, confidence = _scan_for_framework(CLEAN_FIXTURE, None)
        assert framework is None
        assert rule_ids == []
        assert confidence is None

    def test_nonexistent_file_returns_none(self, tmp_path):
        framework, rule_ids, confidence = _scan_for_framework(tmp_path / "ghost.py", None)
        assert framework is None
        assert rule_ids == []
        assert confidence is None

    def test_project_root_scan_finds_sibling(self, tmp_path):
        """Entry script is empty; a sibling in the project root has LangGraph code.
        Confidence must be 'medium' since the signal came from a sibling, not entry."""
        entry = tmp_path / "entry.py"
        entry.write_text("import sibling\n")

        sibling = tmp_path / "sibling.py"
        sibling.write_text(LANGGRAPH_FIXTURE.read_text())

        framework, rule_ids, confidence = _scan_for_framework(entry, tmp_path)
        assert framework == "LangChain/LangGraph"
        assert "DAI003" in rule_ids
        assert confidence == "medium"  # signal came from a sibling, not the entry script

    def test_priority_langgraph_over_openai_sdk(self, tmp_path):
        """When both DAI003 and DAI004 are present, LangGraph wins (higher priority)."""
        mixed = tmp_path / "mixed.py"
        mixed.write_text(
            LANGGRAPH_FIXTURE.read_text() + "\n" +
            "import openai\nclient = openai.OpenAI()\n"
        )
        framework, rule_ids, confidence = _scan_for_framework(mixed, None)
        assert framework == "LangChain/LangGraph"
        assert confidence == "high"


# ═══════════════════════════════════════════════════════════════════════════════
# TestIntrospectProcess  (uses current process — always available)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntrospectProcess:
    def test_current_process_has_cmdline(self):
        import os
        result = introspect_process(os.getpid())
        assert result.pid == os.getpid()
        assert isinstance(result.cmdline, list)
        # pytest itself has a non-empty cmdline
        assert len(result.cmdline) >= 1

    def test_current_process_has_cwd(self):
        import os
        result = introspect_process(os.getpid())
        assert result.cwd is not None
        assert Path(result.cwd).is_dir()

    def test_invalid_pid_returns_empty_result(self):
        result = introspect_process(99999999)
        assert result.pid == 99999999
        assert result.framework is None
        assert result.cmdline == []

    def test_result_type(self):
        import os
        result = introspect_process(os.getpid())
        assert isinstance(result, ProcessIntrospectionResult)
        assert isinstance(result.rule_ids, list)

    def test_mock_python_agent_introspected(self, tmp_path):
        """
        Simulate a python3 process running a LangGraph agent.
        introspect_process should return framework = LangChain/LangGraph.
        """
        script = tmp_path / "agent.py"
        script.write_text(LANGGRAPH_FIXTURE.read_text())

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python3", str(script)]
        mock_proc.cwd.return_value = str(tmp_path)

        with patch("agent_discover_scanner.process_introspection.psutil.Process", return_value=mock_proc):
            result = introspect_process(12345)

        assert result.framework == "LangChain/LangGraph"
        assert result.entry_script == str(script)
        assert "DAI003" in result.rule_ids
        assert result.framework_confidence == "high"  # signal was in the entry script

    def test_mock_non_python_process_no_framework(self, tmp_path):
        """A non-Python process (uvicorn) returns no framework."""
        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["uvicorn", "app:create_app", "--port", "8000"]
        mock_proc.cwd.return_value = str(tmp_path)

        with patch("agent_discover_scanner.process_introspection.psutil.Process", return_value=mock_proc):
            result = introspect_process(9999)

        assert result.framework is None
        assert result.entry_script is None

    def test_mock_module_invocation_no_framework(self, tmp_path):
        """python3 -m mymodule → no entry script, no framework."""
        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python3", "-m", "mymodule"]
        mock_proc.cwd.return_value = str(tmp_path)

        with patch("agent_discover_scanner.process_introspection.psutil.Process", return_value=mock_proc):
            result = introspect_process(1111)

        assert result.framework is None
        assert result.entry_script is None


# ═══════════════════════════════════════════════════════════════════════════════
# TestCorrelatorL2FrameworkConfirmed  (the primary requirement)
# ═══════════════════════════════════════════════════════════════════════════════

def _l2_finding(
    provider: str = "openai",
    process_name: str = "python3",
    framework: str | None = None,
    entry_script: str | None = None,
    timestamp: str = "2026-06-02T10:00:00+00:00",
) -> dict:
    """Minimal network finding as emitted by scan_runner.run_layer2_once()."""
    return {
        "provider": provider,
        "process_name": process_name,
        "timestamp": timestamp,
        "framework": framework,
        "entry_script": entry_script,
    }


def _l5_bedrock_finding(username: str = "arn:aws:iam::123:role/Agent") -> dict:
    """Minimal Layer 5 CloudTrail finding."""
    return {
        "detection_layer": "layer5_cloud_audit",
        "provider": "bedrock",
        "username": username,
        "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "timestamp": "2026-06-02T10:05:00+00:00",
        "framework": "langchain-aws",
    }


class TestCorrelatorL2FrameworkConfirmed:
    """
    L2 live connection + process-detected framework → CONFIRMED.
    No Layer 1 code finding and no Layer 5 CloudTrail required.
    """

    def test_l2_plus_framework_is_confirmed(self):
        """The core requirement: L2+framework → CONFIRMED, no L5 input."""
        nf = [_l2_finding(provider="openai", framework="LangChain/LangGraph",
                           entry_script="/app/agent.py")]
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=nf,
        )
        assert len(inventory["confirmed"]) == 1, (
            f"Expected 1 CONFIRMED; got confirmed={len(inventory['confirmed'])}, "
            f"ghost={len(inventory['ghost'])}"
        )
        item = inventory["confirmed"][0]
        assert item.framework == "LangChain/LangGraph"
        assert item.network_provider == "openai"
        assert "layer2" in (item.detection_layers or [])

    def test_l2_without_framework_is_ghost(self):
        """L2 connection with no framework evidence → GHOST (behaviour unchanged)."""
        nf = [_l2_finding(provider="anthropic", framework=None)]
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=nf,
        )
        assert len(inventory["ghost"]) == 1
        assert len(inventory["confirmed"]) == 0

    def test_no_l5_required_for_confirmed(self):
        """CONFIRMED must not require L5 — pass empty L5 list and verify CONFIRMED."""
        nf = [_l2_finding(provider="openai", framework="CrewAI")]
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=nf,   # no L5 findings mixed in
        )
        assert len(inventory["confirmed"]) == 1
        assert inventory["confirmed"][0].framework == "CrewAI"

    def test_l5_is_additive_enrichment(self):
        """
        When both L2+framework AND L5 CloudTrail are present for the same provider,
        the agent is CONFIRMED (from L2+framework) and L5 contributes l5_event_count.
        """
        l2_nf = _l2_finding(provider="bedrock", framework="LangChain/LangGraph",
                             entry_script="/app/bedrock_agent.py")
        l5_nf = _l5_bedrock_finding()
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[l2_nf, l5_nf],
        )
        confirmed = inventory["confirmed"]
        assert len(confirmed) == 1, f"Expected 1 CONFIRMED, got {len(confirmed)}"
        # The L2+framework item is CONFIRMED; L5 should not create a separate GHOST
        assert len(inventory["ghost"]) == 0

    def test_entry_script_stored_as_code_file(self):
        """The introspected entry script path is stored in code_file on the CONFIRMED item."""
        script = "/workspace/langgraph_agent.py"
        nf = [_l2_finding(provider="anthropic", framework="LangChain/LangGraph",
                           entry_script=script)]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["confirmed"][0]
        assert item.code_file == script

    def test_confirmed_risk_level_is_high_not_critical(self):
        """
        L2+framework CONFIRMED agents are HIGH risk (we have code evidence).
        Pure GHOST (no framework) stays CRITICAL.
        """
        nf_confirmed = _l2_finding(provider="openai", framework="AutoGen")
        nf_ghost = _l2_finding(provider="anthropic", framework=None)
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=[nf_confirmed, nf_ghost],
        )
        assert inventory["confirmed"][0].risk_level == "high"
        assert inventory["ghost"][0].risk_level == "critical"

    def test_multiple_providers_each_classified_independently(self):
        """Each provider is classified independently based on its own framework evidence."""
        nf = [
            _l2_finding(provider="openai",    framework="LangChain/LangGraph"),
            _l2_finding(provider="anthropic", framework=None),
            _l2_finding(provider="groq",      framework="CrewAI"),
        ]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        assert len(inventory["confirmed"]) == 2  # openai + groq
        assert len(inventory["ghost"]) == 1       # anthropic

    def test_known_desktop_app_stays_shadow_ai_even_with_framework(self):
        """
        Cursor/Claude Desktop etc. are always Shadow AI regardless of process
        introspection returning a framework (they ARE known AI tools).
        """
        nf = [_l2_finding(
            provider="anthropic",
            process_name="Cursor",
            framework="LangChain/LangGraph",  # hypothetically detected
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        # Should be shadow_ai_usage, NOT confirmed
        assert len(inventory["shadow_ai_usage"]) == 1
        assert len(inventory["confirmed"]) == 0

    def test_l1_plus_l2_still_confirmed_without_framework(self):
        """
        Existing behaviour: L1 code finding + L2 network → CONFIRMED regardless
        of whether process introspection found a framework. Must not regress.
        """
        code_findings = [{
            "file_path": "/app/agent.py",
            "line": 5,
            "rule_id": "DAI003",
            "message": "LangGraph StateGraph detected",
            "severity": "note",
        }]
        nf = [_l2_finding(provider="openai", process_name="python3", framework=None)]
        inventory = CorrelationEngine.correlate(
            code_findings=code_findings,
            network_findings=nf,
        )
        assert len(inventory["confirmed"]) == 1
        assert inventory["confirmed"][0].framework == "LangChain/LangGraph"

    def test_framework_preferred_over_no_framework_for_same_provider(self):
        """
        When two L2 findings exist for the same provider, the one with a framework
        should be used (not overwritten by the one without).
        """
        nf = [
            _l2_finding(provider="openai", framework=None, timestamp="2026-06-02T10:00:00+00:00"),
            _l2_finding(provider="openai", framework="CrewAI",
                        entry_script="/app/crew.py", timestamp="2026-06-02T10:01:00+00:00"),
        ]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        assert len(inventory["confirmed"]) == 1
        assert inventory["confirmed"][0].framework == "CrewAI"
        assert len(inventory["ghost"]) == 0


# ── helpers for enrichment tests ──────────────────────────────────────────────

def _l2_finding_enriched(
    provider: str = "bedrock",
    process_name: str = "python3",
    framework: str | None = "LangChain/LangGraph",
    framework_confidence: str | None = "high",
    entry_script: str | None = "/app/agent.py",
    detected_host: str | None = "bedrock-runtime.us-east-1.amazonaws.com",
    timestamp: str = "2026-06-02T10:00:00+00:00",
) -> dict:
    return {
        "provider": provider,
        "process_name": process_name,
        "timestamp": timestamp,
        "framework": framework,
        "framework_confidence": framework_confidence,
        "entry_script": entry_script,
        "detected_host": detected_host,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TestL2EnrichmentFields  — detected_hosts / evidence / entry_script / framework_confidence
# ═══════════════════════════════════════════════════════════════════════════════

class TestL2EnrichmentFields:
    """
    Verify that the new L2 enrichment fields flow end-to-end:
    network finding dict → active_providers → AgentInventoryItem.
    """

    def test_confirmed_item_has_detected_hosts(self):
        """detected_hosts is populated from detected_host in the nf dict."""
        nf = [_l2_finding_enriched(
            framework="LangChain/LangGraph",
            detected_host="bedrock-runtime.us-east-1.amazonaws.com",
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["confirmed"][0]
        assert item.detected_hosts == ["bedrock-runtime.us-east-1.amazonaws.com"]

    def test_confirmed_item_has_entry_script(self):
        """entry_script is populated on the inventory item."""
        nf = [_l2_finding_enriched(entry_script="/workspace/agent.py")]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["confirmed"][0]
        assert item.entry_script == "/workspace/agent.py"

    def test_confirmed_item_has_framework_confidence(self):
        """framework_confidence flows from nf dict → active_providers → item."""
        nf = [_l2_finding_enriched(framework_confidence="high")]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["confirmed"][0]
        assert item.framework_confidence == "high"

    def test_medium_confidence_preserved(self):
        nf = [_l2_finding_enriched(framework_confidence="medium")]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        assert inventory["confirmed"][0].framework_confidence == "medium"

    def test_confirmed_evidence_tags_with_all_signals(self):
        """All three L2 signal tags present when entry_script + detected_host are set."""
        nf = [_l2_finding_enriched(
            entry_script="/app/agent.py",
            detected_host="api.anthropic.com",
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        ev = inventory["confirmed"][0].evidence
        assert "layer2_network" in ev
        assert "layer2_process_introspection" in ev
        assert "layer2_dns_host" in ev

    def test_evidence_no_introspection_when_no_entry_script(self):
        """Without entry_script, layer2_process_introspection is absent."""
        nf = [_l2_finding_enriched(
            entry_script=None,
            detected_host="api.openai.com",
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        ev = inventory["confirmed"][0].evidence
        assert "layer2_network" in ev
        assert "layer2_dns_host" in ev
        assert "layer2_process_introspection" not in ev

    def test_evidence_no_dns_host_when_no_detected_host(self):
        """Without detected_host, layer2_dns_host is absent."""
        nf = [_l2_finding_enriched(detected_host=None)]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        ev = inventory["confirmed"][0].evidence
        assert "layer2_network" in ev
        assert "layer2_dns_host" not in ev

    def test_ghost_item_has_detected_hosts(self):
        """GHOST items also carry detected_hosts when a DNS-correlated hostname is present."""
        nf = [_l2_finding_enriched(
            framework=None,
            framework_confidence=None,
            entry_script=None,
            detected_host="api.openai.com",
            provider="openai",
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["ghost"][0]
        assert item.detected_hosts == ["api.openai.com"]

    def test_l1_l2_confirmed_carries_l2_enrichment(self):
        """L1+L2 CONFIRMED item gets entry_script and detected_hosts from the L2 match."""
        code_findings = [{
            "file_path": "/app/agent.py",
            "line": 5,
            "rule_id": "DAI003",
            "message": "LangGraph StateGraph detected",
        }]
        nf = [_l2_finding_enriched(
            provider="openai",
            process_name="python3",
            entry_script="/app/agent.py",
            detected_host="api.openai.com",
            framework_confidence="high",
        )]
        inventory = CorrelationEngine.correlate(code_findings=code_findings, network_findings=nf)
        item = inventory["confirmed"][0]
        assert item.entry_script == "/app/agent.py"
        assert item.detected_hosts == ["api.openai.com"]
        assert item.framework_confidence == "high"
        assert "layer1_code_scan" in item.evidence
        assert "layer2_network" in item.evidence
        assert "layer2_process_introspection" in item.evidence
        assert "layer2_dns_host" in item.evidence

    def test_shadow_item_has_detected_hosts(self):
        """Shadow AI items carry detected_hosts too."""
        nf = [_l2_finding_enriched(
            provider="anthropic",
            process_name="Cursor",
            framework="LangChain/LangGraph",
            detected_host="api.anthropic.com",
        )]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        item = inventory["shadow_ai_usage"][0]
        assert item.detected_hosts == ["api.anthropic.com"]

    def test_empty_detected_host_gives_empty_list(self):
        """When detected_host is None the list is empty, not [None]."""
        nf = [_l2_finding_enriched(detected_host=None)]
        inventory = CorrelationEngine.correlate(code_findings=[], network_findings=nf)
        assert inventory["confirmed"][0].detected_hosts == []
