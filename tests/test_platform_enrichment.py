"""
Tests for platform.py enrichment functions added in v2.8.0 / v2.9.0:
  - build_cloud_audit_summary
  - build_network_summary
  - _l5_events_for_agent
  - _build_evidence_tags  (v2.9.0)
  - format_agents_for_upload  (L5 enrichment + credential_files_found + L2 enrichment)
"""

import pytest

from agent_discover_scanner.platform import (
    _build_evidence_tags,
    _l5_events_for_agent,
    build_cloud_audit_summary,
    build_network_summary,
    format_agents_for_upload,
)


# ── helpers ─────────────────────────────────────────────────────────────────

def _l5_finding(
    provider="bedrock",
    model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
    username="alice@corp.com",
    event_name="InvokeModel",
    timestamp="2026-05-29T13:00:00+00:00",
    framework="langchain-aws",
):
    return {
        "detection_layer": "layer5_cloud_audit",
        "provider": provider,
        "model_id": model_id,
        "username": username,
        "event_name": event_name,
        "timestamp": timestamp,
        "framework": framework,
    }


def _l2_finding(provider="openai", process_name="chrome.exe", service=None):
    f = {"provider": provider, "process_name": process_name}
    if service:
        f["service"] = service
    return f


def _minimal_report(classification="confirmed", network_provider="bedrock", caller_identity=None):
    item = {
        "agent_id": "src/app.py:10",
        "classification": classification,
        "risk_level": "high",
        "code_file": "src/app.py",
        "framework": "LangChain/LangGraph",
        "network_provider": network_provider,
        "detection_layers": ["layer1", "layer5"],
        "l5_event_count": 1,
    }
    if caller_identity:
        item["caller_identity"] = caller_identity
    return {"inventory": {classification: [item]}}


# ── TestBuildCloudAuditSummary ───────────────────────────────────────────────

class TestBuildCloudAuditSummary:
    def test_empty_returns_empty_dict(self):
        assert build_cloud_audit_summary([]) == {}

    def test_none_list_treated_as_empty(self):
        # caller guards with `or []`, but test the function directly
        assert build_cloud_audit_summary([]) == {}

    def test_single_finding(self):
        f = _l5_finding()
        result = build_cloud_audit_summary([f])
        assert result["total_invocations"] == 1
        assert result["providers"] == ["bedrock"]
        assert result["models_used"] == ["anthropic.claude-3-5-sonnet-20241022-v2:0"]
        assert result["iam_users"] == ["alice@corp.com"]
        assert result["event_types"] == {"InvokeModel": 1}
        assert result["findings"] == [f]

    def test_multiple_findings_counted_correctly(self):
        findings = [
            _l5_finding(username="alice@corp.com", event_name="InvokeModel",
                        model_id="us.anthropic.claude-opus-4-7"),
            _l5_finding(username="bob@corp.com", event_name="InvokeModelWithResponseStream",
                        model_id="us.anthropic.claude-sonnet-4-6"),
            _l5_finding(username="alice@corp.com", event_name="InvokeModel",
                        model_id="us.anthropic.claude-opus-4-7"),
        ]
        result = build_cloud_audit_summary(findings)
        assert result["total_invocations"] == 3
        assert result["iam_users"] == ["alice@corp.com", "bob@corp.com"]  # sorted, deduped
        assert len(result["models_used"]) == 2
        assert result["event_types"]["InvokeModel"] == 2
        assert result["event_types"]["InvokeModelWithResponseStream"] == 1

    def test_models_used_sorted_deduped(self):
        findings = [
            _l5_finding(model_id="z-model"),
            _l5_finding(model_id="a-model"),
            _l5_finding(model_id="a-model"),
        ]
        result = build_cloud_audit_summary(findings)
        assert result["models_used"] == ["a-model", "z-model"]

    def test_missing_model_id_not_in_models_used(self):
        findings = [_l5_finding(model_id=None), _l5_finding(model_id="some-model")]
        result = build_cloud_audit_summary(findings)
        assert result["models_used"] == ["some-model"]

    def test_missing_username_not_in_iam_users(self):
        findings = [_l5_finding(username=None), _l5_finding(username="user@x.com")]
        result = build_cloud_audit_summary(findings)
        assert result["iam_users"] == ["user@x.com"]

    def test_unknown_event_name_when_missing(self):
        f = _l5_finding()
        f.pop("event_name")
        result = build_cloud_audit_summary([f])
        assert result["event_types"] == {"Unknown": 1}

    def test_multiple_providers(self):
        findings = [_l5_finding(provider="bedrock"), _l5_finding(provider="azure_openai")]
        result = build_cloud_audit_summary(findings)
        assert "azure_openai" in result["providers"]
        assert "bedrock" in result["providers"]


# ── TestBuildNetworkSummary ─────────────────────────────────────────────────

class TestBuildNetworkSummary:
    def test_empty_returns_empty_dict(self):
        assert build_network_summary([]) == {}

    def test_l2_only_finding(self):
        f = _l2_finding(provider="openai", process_name="chrome.exe", service="OpenAI")
        result = build_network_summary([f])
        assert result["total_connections"] == 1
        assert "OpenAI" in result["services_detected"]
        assert result["processes"]["chrome.exe"] == 1
        assert result["findings"] == [f]

    def test_l5_findings_excluded(self):
        l2 = _l2_finding()
        l5 = {**_l5_finding(), "detection_layer": "layer5_cloud_audit"}
        sse = {**_l5_finding(), "detection_layer": "layer5_sse_proxy"}
        result = build_network_summary([l2, l5, sse])
        assert result["total_connections"] == 1
        assert result["findings"] == [l2]

    def test_returns_empty_when_only_l5_data(self):
        l5 = {**_l5_finding(), "detection_layer": "layer5_cloud_audit"}
        assert build_network_summary([l5]) == {}

    def test_process_count_aggregated(self):
        findings = [
            _l2_finding(process_name="python3"),
            _l2_finding(process_name="python3"),
            _l2_finding(process_name="chrome.exe"),
        ]
        result = build_network_summary(findings)
        assert result["processes"]["python3"] == 2
        assert result["processes"]["chrome.exe"] == 1

    def test_services_detected_uses_service_field_first(self):
        f = {"provider": "openai", "service": "GitHub Copilot", "process_name": "chrome.exe"}
        result = build_network_summary([f])
        assert "GitHub Copilot" in result["services_detected"]
        assert "openai" not in result["services_detected"]

    def test_services_falls_back_to_provider(self):
        f = _l2_finding(provider="anthropic")  # no service field
        result = build_network_summary([f])
        assert "anthropic" in result["services_detected"]

    def test_services_sorted_deduped(self):
        findings = [
            _l2_finding(provider="openai"),
            _l2_finding(provider="openai"),
            _l2_finding(provider="anthropic"),
        ]
        result = build_network_summary(findings)
        assert result["services_detected"] == ["anthropic", "openai"]


# ── TestL5EventsForAgent ────────────────────────────────────────────────────

class TestL5EventsForAgent:
    def test_empty_findings_returns_empty(self):
        item = {"caller_identity": "arn:aws:iam::123:user/alice", "network_provider": "bedrock"}
        assert _l5_events_for_agent(item, []) == []

    def test_exact_caller_identity_match(self):
        arn = "arn:aws:iam::123:role/MyRole"
        item = {"caller_identity": arn, "network_provider": "bedrock"}
        f_match = _l5_finding(username=arn)
        f_other = _l5_finding(username="other@user.com")
        result = _l5_events_for_agent(item, [f_match, f_other])
        assert result == [f_match]

    def test_falls_back_to_provider_when_no_caller(self):
        item = {"caller_identity": None, "network_provider": "bedrock"}
        f1 = _l5_finding(provider="bedrock")
        f2 = _l5_finding(provider="azure")
        result = _l5_events_for_agent(item, [f1, f2])
        assert result == [f1]

    def test_no_match_when_no_provider_and_no_caller(self):
        item = {"caller_identity": None, "network_provider": None}
        result = _l5_events_for_agent(item, [_l5_finding()])
        assert result == []

    def test_caller_identity_match_beats_provider_match(self):
        arn = "arn:aws:iam::123:role/Alice"
        item = {"caller_identity": arn, "network_provider": "bedrock"}
        f_alice = _l5_finding(username=arn)
        f_bedrock = _l5_finding(username="bob@corp.com", provider="bedrock")
        result = _l5_events_for_agent(item, [f_alice, f_bedrock])
        # Exact match: only Alice's event
        assert result == [f_alice]
        assert len(result) == 1

    def test_provider_match_case_insensitive(self):
        item = {"caller_identity": None, "network_provider": "Bedrock"}
        f = _l5_finding(provider="bedrock")
        assert _l5_events_for_agent(item, [f]) == [f]


# ── TestFormatAgentsL5Enrichment ────────────────────────────────────────────

class TestFormatAgentsL5Enrichment:
    """format_agents_for_upload: per-agent L5 stats + credential_files_found."""

    def _format(self, classification="confirmed", caller_identity=None,
                 cloud_audit_findings=None, network_provider="bedrock"):
        report = _minimal_report(
            classification=classification,
            network_provider=network_provider,
            caller_identity=caller_identity,
        )
        return format_agents_for_upload(
            report,
            cloud_audit_findings=cloud_audit_findings,
        )

    def test_no_l5_findings_no_enrichment(self):
        agents = self._format(cloud_audit_findings=[])
        assert agents  # at least one agent
        meta = agents[0]["metadata"]
        assert "bedrock_invocations" not in meta
        assert "models_called" not in meta

    def test_bedrock_invocations_added_to_metadata(self):
        findings = [_l5_finding(), _l5_finding()]
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        assert meta["bedrock_invocations"] == 2

    def test_models_called_plural_list(self):
        findings = [
            _l5_finding(model_id="model-A"),
            _l5_finding(model_id="model-B"),
            _l5_finding(model_id="model-A"),
        ]
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        assert set(meta["models_called"]) == {"model-A", "model-B"}

    def test_iam_users_plural_list(self):
        findings = [
            _l5_finding(username="alice@corp.com"),
            _l5_finding(username="bob@corp.com"),
        ]
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        assert set(meta["iam_users"]) == {"alice@corp.com", "bob@corp.com"}

    def test_last_invocation_is_latest_timestamp(self):
        findings = [
            _l5_finding(timestamp="2026-05-29T10:00:00+00:00"),
            _l5_finding(timestamp="2026-05-29T13:46:45+00:00"),
            _l5_finding(timestamp="2026-05-29T08:00:00+00:00"),
        ]
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        assert meta["last_invocation"] == "2026-05-29T13:46:45+00:00"

    def test_credential_files_found_populated_with_iam_prefix(self):
        findings = [_l5_finding(username="alice@corp.com"), _l5_finding(username="crewai-user")]
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        saas = meta.get("saas_connections") or {}
        cred = saas.get("credential_files_found") or []
        assert "IAM:alice@corp.com" in cred
        assert "IAM:crewai-user" in cred

    def test_credential_files_found_no_duplicates(self):
        findings = [_l5_finding(username="alice@corp.com")] * 3
        agents = self._format(cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        saas = meta.get("saas_connections") or {}
        cred = saas.get("credential_files_found") or []
        assert cred.count("IAM:alice@corp.com") == 1

    def test_exact_caller_identity_limits_attribution(self):
        arn = "arn:aws:iam::123:role/AgentRole"
        findings = [
            _l5_finding(username=arn),       # matches this agent
            _l5_finding(username="other@x"),  # different user
        ]
        agents = self._format(caller_identity=arn, cloud_audit_findings=findings)
        meta = agents[0]["metadata"]
        # Only 1 event attributed (exact IAM match)
        assert meta["bedrock_invocations"] == 1
        assert meta["iam_users"] == [arn]

    def test_ghost_agent_enriched_by_provider_fallback(self):
        """A GHOST agent with no caller_identity gets enriched via provider match."""
        findings = [_l5_finding(provider="bedrock", username="lambda-role")]
        agents = self._format(
            classification="ghost",
            caller_identity=None,
            cloud_audit_findings=findings,
            network_provider="bedrock",
        )
        meta = agents[0]["metadata"]
        assert meta["bedrock_invocations"] == 1
        assert "IAM:lambda-role" in (
            (meta.get("saas_connections") or {}).get("credential_files_found") or []
        )

    def test_non_bedrock_agent_not_enriched_with_bedrock_findings(self):
        findings = [_l5_finding(provider="bedrock")]
        agents = self._format(cloud_audit_findings=findings, network_provider="openai")
        meta = agents[0]["metadata"]
        # openai agent should not get bedrock L5 enrichment
        assert "bedrock_invocations" not in meta

    def test_no_cloud_audit_param_is_same_as_empty(self):
        agents_no_param = self._format()
        agents_empty = self._format(cloud_audit_findings=[])
        # Neither should have L5 enrichment
        for agent in agents_no_param + agents_empty:
            assert "bedrock_invocations" not in agent["metadata"]


# ── TestFormatAgentsCloudAuditInPayload ─────────────────────────────────────

class TestCloudAuditSummaryIntegration:
    """Verify cloud_audit/network summaries flow through upload_scan_results payload."""

    def test_build_cloud_audit_summary_keys(self):
        findings = [_l5_finding(), _l5_finding(username="bob@corp.com", event_name="InvokeModelWithResponseStream")]
        s = build_cloud_audit_summary(findings)
        assert set(s.keys()) >= {"total_invocations", "providers", "models_used", "iam_users", "event_types", "findings"}

    def test_build_network_summary_keys(self):
        findings = [_l2_finding(), _l2_finding(process_name="python3")]
        s = build_network_summary(findings)
        assert set(s.keys()) >= {"total_connections", "services_detected", "processes", "findings"}

    def test_cloud_audit_summary_findings_are_same_objects(self):
        """findings[] in summary is the same list passed in — no copy overhead."""
        findings = [_l5_finding()]
        s = build_cloud_audit_summary(findings)
        assert s["findings"] is findings

    def test_network_summary_findings_are_l2_subset(self):
        l2 = _l2_finding()
        l5 = {**_l5_finding(), "detection_layer": "layer5_cloud_audit"}
        s = build_network_summary([l2, l5])
        assert l2 in s["findings"]
        assert l5 not in s["findings"]


# ── TestBuildEvidenceTags ─────────────────────────────────────────────────────

class TestBuildEvidenceTags:
    """_build_evidence_tags: pre-built list passthrough and derivation fallback."""

    def test_prebuilt_evidence_returned_as_is(self):
        item = {"evidence": ["layer1_code_scan", "layer2_network"]}
        assert _build_evidence_tags(item) == ["layer1_code_scan", "layer2_network"]

    def test_empty_prebuilt_triggers_derivation(self):
        item = {"evidence": [], "detection_layers": ["layer1"]}
        tags = _build_evidence_tags(item)
        assert "layer1_code_scan" in tags

    def test_layer1_only(self):
        item = {"detection_layers": ["layer1"]}
        assert _build_evidence_tags(item) == ["layer1_code_scan"]

    def test_layer2_network_only(self):
        item = {"detection_layers": ["layer2"]}
        tags = _build_evidence_tags(item)
        assert tags == ["layer2_network"]

    def test_layer2_with_entry_script(self):
        item = {"detection_layers": ["layer2"], "entry_script": "/app/agent.py"}
        tags = _build_evidence_tags(item)
        assert "layer2_network" in tags
        assert "layer2_process_introspection" in tags

    def test_layer2_with_detected_hosts(self):
        item = {"detection_layers": ["layer2"], "detected_hosts": ["api.openai.com"]}
        tags = _build_evidence_tags(item)
        assert "layer2_network" in tags
        assert "layer2_dns_host" in tags

    def test_layer2_all_signals(self):
        item = {
            "detection_layers": ["layer2"],
            "entry_script": "/app/agent.py",
            "detected_hosts": ["bedrock-runtime.us-east-1.amazonaws.com"],
        }
        tags = _build_evidence_tags(item)
        assert "layer2_network" in tags
        assert "layer2_process_introspection" in tags
        assert "layer2_dns_host" in tags

    def test_layer1_plus_layer2_all_signals(self):
        item = {
            "detection_layers": ["layer1", "layer2"],
            "entry_script": "/app/agent.py",
            "detected_hosts": ["api.anthropic.com"],
        }
        tags = _build_evidence_tags(item)
        assert tags == [
            "layer1_code_scan",
            "layer2_network",
            "layer2_process_introspection",
            "layer2_dns_host",
        ]

    def test_layer3(self):
        item = {"detection_layers": ["layer1", "layer3"]}
        tags = _build_evidence_tags(item)
        assert "layer3_k8s_runtime" in tags

    def test_layer4(self):
        item = {"detection_layers": ["layer4"]}
        assert "layer4_endpoint" in _build_evidence_tags(item)

    def test_layer5_cloudtrail(self):
        item = {"detection_layers": ["layer5"]}
        assert "layer5_cloudtrail" in _build_evidence_tags(item)

    def test_layer5_sse(self):
        item = {"detection_layers": ["layer5_sse"]}
        assert "layer5_sse_proxy" in _build_evidence_tags(item)

    def test_no_layers_gives_empty_list(self):
        assert _build_evidence_tags({}) == []

    def test_framework_confidence_alone_triggers_introspection_tag(self):
        """framework_confidence without entry_script still implies introspection ran."""
        item = {"detection_layers": ["layer2"], "framework_confidence": "medium"}
        tags = _build_evidence_tags(item)
        assert "layer2_process_introspection" in tags


# ── TestFormatAgentsL2Enrichment ─────────────────────────────────────────────

def _l2_enriched_report(
    classification: str = "confirmed",
    entry_script: str | None = "/app/agent.py",
    detected_hosts: list | None = None,
    framework_confidence: str | None = "high",
    evidence: list | None = None,
) -> dict:
    item: dict = {
        "agent_id": "src/app.py:10",
        "classification": classification,
        "risk_level": "high",
        "code_file": "src/app.py",
        "framework": "LangChain/LangGraph",
        "network_provider": "openai",
        "detection_layers": ["layer2"],
    }
    if entry_script is not None:
        item["entry_script"] = entry_script
    if detected_hosts is not None:
        item["detected_hosts"] = detected_hosts
    if framework_confidence is not None:
        item["framework_confidence"] = framework_confidence
    if evidence is not None:
        item["evidence"] = evidence
    return {"inventory": {classification: [item]}}


class TestFormatAgentsL2Enrichment:
    """format_agents_for_upload emits detected_hosts, evidence, entry_script,
    framework_confidence at the top level of each agent record (v2.9.0)."""

    def _fmt(self, report):
        return format_agents_for_upload(report)

    def test_detected_hosts_emitted(self):
        report = _l2_enriched_report(detected_hosts=["api.openai.com"])
        agent = self._fmt(report)[0]
        assert agent["detected_hosts"] == ["api.openai.com"]

    def test_empty_detected_hosts_default(self):
        report = _l2_enriched_report(detected_hosts=None)
        agent = self._fmt(report)[0]
        assert agent["detected_hosts"] == []

    def test_entry_script_emitted(self):
        report = _l2_enriched_report(entry_script="/workspace/langgraph_agent.py")
        agent = self._fmt(report)[0]
        assert agent["entry_script"] == "/workspace/langgraph_agent.py"

    def test_entry_script_none_when_absent(self):
        report = _l2_enriched_report(entry_script=None)
        agent = self._fmt(report)[0]
        assert agent["entry_script"] is None

    def test_framework_confidence_emitted(self):
        report = _l2_enriched_report(framework_confidence="high")
        agent = self._fmt(report)[0]
        assert agent["framework_confidence"] == "high"

    def test_framework_confidence_medium(self):
        report = _l2_enriched_report(framework_confidence="medium")
        agent = self._fmt(report)[0]
        assert agent["framework_confidence"] == "medium"

    def test_evidence_prebuilt_passthrough(self):
        prebuilt = ["layer2_network", "layer2_process_introspection", "layer2_dns_host"]
        report = _l2_enriched_report(evidence=prebuilt)
        agent = self._fmt(report)[0]
        assert agent["evidence"] == prebuilt

    def test_evidence_derived_from_detection_layers(self):
        """When evidence is absent, _build_evidence_tags derives from detection_layers."""
        report = _l2_enriched_report(evidence=None)
        agent = self._fmt(report)[0]
        assert "layer2_network" in agent["evidence"]

    def test_evidence_includes_introspection_tag_when_entry_script_present(self):
        report = _l2_enriched_report(
            entry_script="/app/agent.py",
            detected_hosts=["api.openai.com"],
            evidence=None,  # force derivation
        )
        agent = self._fmt(report)[0]
        assert "layer2_process_introspection" in agent["evidence"]
        assert "layer2_dns_host" in agent["evidence"]

    def test_evidence_key_always_present(self):
        """evidence key must exist on every agent record, even when empty."""
        report = _l2_enriched_report(evidence=None, entry_script=None, detected_hosts=None)
        agent = self._fmt(report)[0]
        assert "evidence" in agent
        assert isinstance(agent["evidence"], list)
