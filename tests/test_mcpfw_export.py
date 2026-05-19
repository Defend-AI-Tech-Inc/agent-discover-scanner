"""Tests for MCP governance policy exporter."""
from __future__ import annotations

import pytest

from agent_discover_scanner.exporters.mcpfw_policy import (
    VALID_STANCES,
    export_mcpfw_policy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _server(
    name: str,
    risk: str = "medium",
    publisher_verified: bool = True,
    capability: str | None = None,
    is_local_script: bool = False,
    is_remote: bool = False,
    saas: str | None = None,
    source: str | None = None,
    package: str | None = None,
) -> dict:
    return {
        "server_name": name,
        "package": package or name,
        "vendor": "Anthropic" if publisher_verified else "Community",
        "publisher_verified": publisher_verified,
        "risk": risk,
        "saas": saas,
        "capability": capability,
        "is_local_script": is_local_script,
        "is_remote": is_remote,
        "client": "Claude Desktop",
        "source": source,
        "note": None,
    }


def _scan_result(servers: list[dict], saas_list: list[str] | None = None, network_detected: bool = False) -> dict:
    return {
        "mcp": {
            "servers": servers,
            "saas_via_mcp": saas_list or [],
            "capabilities": [],
            "has_unverified_servers": any(not s["publisher_verified"] for s in servers),
            "has_local_scripts": any(s["is_local_script"] for s in servers),
            "has_remote_servers": any(s["is_remote"] for s in servers),
            "has_filesystem_access": any(s.get("capability") == "filesystem" for s in servers),
            "has_database_access": any(s.get("capability") == "database" for s in servers),
            "has_code_execution": any(s.get("capability") == "code_execution" for s in servers),
            "has_browser_access": any(s.get("capability") == "browser" for s in servers),
            "highest_risk": max((s["risk"] for s in servers), key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(r, 0), default=None) if servers else None,
            "clients_with_mcp": ["Claude Desktop"],
            "network_detected": network_detected,
            "source_summary": "Claude Desktop",
        },
        "scan_path": "/tmp/test-repo",
    }


# ---------------------------------------------------------------------------
# Basic structure tests
# ---------------------------------------------------------------------------


class TestPolicyStructure:
    def test_returns_dict_with_required_keys(self):
        result = export_mcpfw_policy(_scan_result([]))
        assert "version" in result
        assert "default_action" in result
        assert "response_rules" in result
        assert "servers" in result

    def test_version_is_1(self):
        result = export_mcpfw_policy(_scan_result([]))
        assert result["version"] == 1

    def test_empty_mcp_returns_minimal_stub(self):
        result = export_mcpfw_policy({"mcp": {}, "scan_path": "."})
        assert result["servers"] == []
        assert len(result["response_rules"]) > 0

    def test_none_mcp_key_returns_minimal_stub(self):
        result = export_mcpfw_policy({"scan_path": "."})
        assert result["servers"] == []

    def test_never_raises_on_garbage_input(self):
        result = export_mcpfw_policy({})
        assert isinstance(result, dict)
        assert result["version"] == 1

    def test_never_raises_on_none(self):
        result = export_mcpfw_policy(None)  # type: ignore
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Stance tests
# ---------------------------------------------------------------------------


class TestStances:
    def test_all_stances_valid(self):
        sr = _scan_result([_server("github", risk="medium", publisher_verified=True)])
        for stance in VALID_STANCES:
            result = export_mcpfw_policy(sr, stance=stance)
            assert result["default_action"] in ("allow", "block")

    def test_strict_global_default_is_block(self):
        result = export_mcpfw_policy(_scan_result([]), stance="strict")
        assert result["default_action"] == "block"

    def test_balanced_global_default_is_allow(self):
        result = export_mcpfw_policy(_scan_result([]), stance="balanced")
        assert result["default_action"] == "allow"

    def test_monitor_global_default_is_allow(self):
        result = export_mcpfw_policy(_scan_result([]), stance="monitor")
        assert result["default_action"] == "allow"

    def test_unknown_stance_falls_back_to_balanced(self):
        result = export_mcpfw_policy(_scan_result([]), stance="extreme")
        assert result["default_action"] == "allow"

    def test_strict_sets_verify_server_tools(self):
        result = export_mcpfw_policy(_scan_result([]), stance="strict")
        assert result["verify_server_tools"] is True

    def test_balanced_does_not_set_verify_server_tools(self):
        result = export_mcpfw_policy(_scan_result([]), stance="balanced")
        assert result["verify_server_tools"] is False


# ---------------------------------------------------------------------------
# Critical / always-block packages
# ---------------------------------------------------------------------------


class TestAlwaysBlock:
    def test_server_everything_blocked_in_all_stances(self):
        s = _server(
            "everything",
            risk="critical",
            capability="code_execution",
            package="@modelcontextprotocol/server-everything",
        )
        for stance in VALID_STANCES:
            result = export_mcpfw_policy(_scan_result([s]), stance=stance)
            server_policy = next(
                (p for p in result["servers"] if p.get("server") == "everything"), None
            )
            assert server_policy is not None, f"No policy for 'everything' in {stance}"
            assert server_policy["default_action"] == "block"

    def test_critical_risk_server_blocked_in_strict(self):
        s = _server("dangerous", risk="critical", publisher_verified=False)
        result = export_mcpfw_policy(_scan_result([s]), stance="strict")
        sp = next(p for p in result["servers"] if p["server"] == "dangerous")
        assert sp["default_action"] == "block"

    def test_critical_risk_server_blocked_in_balanced(self):
        s = _server("dangerous", risk="critical", publisher_verified=False)
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "dangerous")
        assert sp["default_action"] == "block"


# ---------------------------------------------------------------------------
# Per-capability rules
# ---------------------------------------------------------------------------


class TestCapabilityRules:
    def test_filesystem_server_gets_allow_paths_in_strict(self):
        s = _server("fs", capability="filesystem", risk="high", publisher_verified=False)
        result = export_mcpfw_policy(_scan_result([s]), stance="strict")
        sp = next(p for p in result["servers"] if p["server"] == "fs")
        tool_rules = sp.get("tool_rules") or []
        path_rules = [r for r in tool_rules if r.get("allow_paths")]
        assert len(path_rules) > 0

    def test_filesystem_server_gets_log_rule_in_monitor(self):
        s = _server("fs", capability="filesystem", risk="medium")
        result = export_mcpfw_policy(_scan_result([s]), stance="monitor")
        sp = next(p for p in result["servers"] if p["server"] == "fs")
        tool_rules = sp.get("tool_rules") or []
        log_rules = [r for r in tool_rules if r.get("action") == "log"]
        assert len(log_rules) > 0

    def test_database_server_gets_rate_limit(self):
        s = _server("db", capability="database", risk="high")
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "db")
        tool_rules = sp.get("tool_rules") or []
        rl_rules = [r for r in tool_rules if r.get("rate_limit")]
        assert len(rl_rules) > 0

    def test_code_execution_gets_blocked_tools_in_strict(self):
        s = _server("runner", capability="code_execution", risk="high")
        result = export_mcpfw_policy(_scan_result([s]), stance="strict")
        sp = next(p for p in result["servers"] if p["server"] == "runner")
        blocked = sp.get("blocked_tools") or []
        assert "execute_command" in blocked or "shell" in blocked

    def test_browser_server_gets_block_pattern_in_strict(self):
        s = _server("browser", capability="browser", risk="medium")
        result = export_mcpfw_policy(_scan_result([s]), stance="strict")
        sp = next(p for p in result["servers"] if p["server"] == "browser")
        tool_rules = sp.get("tool_rules") or []
        pattern_rules = [r for r in tool_rules if r.get("block_patterns")]
        assert len(pattern_rules) > 0

    def test_web_search_gets_block_pattern_in_balanced(self):
        s = _server("search", capability="web_search", risk="medium")
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "search")
        tool_rules = sp.get("tool_rules") or []
        pattern_rules = [r for r in tool_rules if r.get("block_patterns")]
        assert len(pattern_rules) > 0

    def test_monitor_stance_no_block_patterns(self):
        s = _server("browser", capability="browser", risk="medium")
        result = export_mcpfw_policy(_scan_result([s]), stance="monitor")
        sp = next(p for p in result["servers"] if p["server"] == "browser")
        tool_rules = sp.get("tool_rules") or []
        block_rules = [r for r in tool_rules if r.get("action") == "block"]
        assert len(block_rules) == 0


# ---------------------------------------------------------------------------
# Unverified / shadow servers
# ---------------------------------------------------------------------------


class TestUnverifiedServers:
    def test_unverified_high_risk_gets_allowlist_in_balanced(self):
        s = _server("mystery", risk="high", publisher_verified=False, capability="web_search")
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "mystery")
        assert sp.get("allowed_tools") is not None

    def test_verified_medium_risk_no_allowlist_in_balanced(self):
        s = _server("safe", risk="medium", publisher_verified=True, capability="web_search")
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "safe")
        assert sp.get("allowed_tools") is None

    def test_local_script_gets_blocked_tools(self):
        s = _server("myscript", is_local_script=True, risk="high", publisher_verified=False)
        result = export_mcpfw_policy(_scan_result([s]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "myscript")
        blocked = sp.get("blocked_tools") or []
        assert len(blocked) > 0


# ---------------------------------------------------------------------------
# Global DLP rules
# ---------------------------------------------------------------------------


class TestGlobalDLP:
    def test_base_dlp_rules_always_present(self):
        result = export_mcpfw_policy(_scan_result([]))
        names = {r["name"] for r in result["response_rules"]}
        assert "detect-openai-key" in names
        assert "detect-aws-credentials" in names
        assert "detect-private-key" in names
        assert "detect-prompt-injection" in names

    def test_monitor_stance_dlp_action_is_log(self):
        result = export_mcpfw_policy(_scan_result([]), stance="monitor")
        for rule in result["response_rules"]:
            if rule["name"] in ("detect-openai-key", "detect-aws-credentials"):
                assert rule["action"] == "log", f"Expected log for {rule['name']} in monitor stance"

    def test_strict_stance_dlp_action_is_block(self):
        result = export_mcpfw_policy(_scan_result([]), stance="strict")
        for rule in result["response_rules"]:
            if rule["name"] == "detect-openai-key":
                assert rule["action"] == "block"

    def test_retry_injection_always_log_not_block(self):
        for stance in VALID_STANCES:
            result = export_mcpfw_policy(_scan_result([]), stance=stance)
            for rule in result["response_rules"]:
                if rule["name"] == "detect-retry-injection":
                    assert rule["action"] == "log", f"retry-injection should always be log in {stance}"

    def test_stripe_saas_adds_stripe_dlp(self):
        s = _server("stripe", risk="high", saas="stripe", publisher_verified=True)
        result = export_mcpfw_policy(_scan_result([s], saas_list=["stripe"]))
        names = {r["name"] for r in result["response_rules"]}
        assert "detect-stripe-key" in names

    def test_github_saas_adds_github_dlp(self):
        s = _server("github", risk="medium", saas="github", publisher_verified=True)
        result = export_mcpfw_policy(_scan_result([s], saas_list=["github"]))
        names = {r["name"] for r in result["response_rules"]}
        assert "detect-github-token" in names

    def test_no_duplicate_dlp_rule_names(self):
        s1 = _server("s1", saas="stripe")
        s2 = _server("s2", saas="stripe")
        result = export_mcpfw_policy(_scan_result([s1, s2], saas_list=["stripe"]))
        names = [r["name"] for r in result["response_rules"]]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_duplicate_server_names_deduplicated(self):
        s1 = _server("fs", risk="medium", publisher_verified=True)
        s2 = _server("fs", risk="high", publisher_verified=False)
        result = export_mcpfw_policy(_scan_result([s1, s2]))
        server_names = [p["server"] for p in result["servers"]]
        assert server_names.count("fs") == 1

    def test_dedup_keeps_highest_risk(self):
        s1 = _server("fs", risk="low", publisher_verified=True)
        s2 = _server("fs", risk="high", publisher_verified=False, capability="web_search")
        result = export_mcpfw_policy(_scan_result([s1, s2]), stance="balanced")
        sp = next(p for p in result["servers"] if p["server"] == "fs")
        # High risk + unverified → should have allowed_tools set
        assert sp.get("allowed_tools") is not None


# ---------------------------------------------------------------------------
# Network-only detection
# ---------------------------------------------------------------------------


class TestNetworkDetection:
    def test_network_server_names_excluded_from_server_policies(self):
        servers = [{"server_name": "network:mcp.stripe.com", "risk": "high",
                    "publisher_verified": False, "capability": None, "is_local_script": False,
                    "is_remote": True, "saas": "stripe", "source": None, "package": "mcp.stripe.com",
                    "vendor": "Stripe", "client": "Network", "note": None}]
        result = export_mcpfw_policy(_scan_result(servers, network_detected=True))
        for sp in result["servers"]:
            assert not sp["server"].startswith("network:")

    def test_empty_mcp_with_network_detected(self):
        result = export_mcpfw_policy({"mcp": {"servers": [], "network_detected": True}, "scan_path": "."})
        assert result["version"] == 1


# ---------------------------------------------------------------------------
# YAML output validity
# ---------------------------------------------------------------------------


class TestYAMLValidity:
    def test_output_serializes_to_yaml(self):
        import yaml

        from agent_discover_scanner.exporters.mcpfw_policy import (
            _strip_internal_keys as strip,
        )

        s = _server("github", risk="high", capability="web_search")
        result = export_mcpfw_policy(_scan_result([s]))
        strip(result)
        dumped = yaml.dump(result, default_flow_style=False)
        reloaded = yaml.safe_load(dumped)
        assert reloaded["version"] == 1
        assert "response_rules" in reloaded

    def test_no_internal_underscore_keys_in_output(self):
        from agent_discover_scanner.exporters.mcpfw_policy import (
            _strip_internal_keys as strip,
        )

        s = _server("db", capability="database", risk="medium")
        result = export_mcpfw_policy(_scan_result([s]))
        strip(result)

        def has_internal(obj):
            if isinstance(obj, dict):
                if any(k.startswith("_") for k in obj):
                    return True
                return any(has_internal(v) for v in obj.values())
            if isinstance(obj, list):
                return any(has_internal(item) for item in obj)
            return False

        assert not has_internal(result)
