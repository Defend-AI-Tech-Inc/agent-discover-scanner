"""
Convert AgentDiscover Scanner MCP findings into a runnable mcpfw policy dict.

Entry point: export_mcpfw_policy(scan_result, stance) -> dict
The returned dict serializes directly to valid mcpfw YAML.
Never raises — returns a minimal valid policy on any error.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_STANCES = ("strict", "balanced", "monitor")

_RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Servers that must be blocked at default_action level regardless of stance.
_ALWAYS_BLOCK_PACKAGES = {
    "@modelcontextprotocol/server-everything",
}

# Capability → narrow tool allowlist for strict/balanced stances.
_CAPABILITY_TOOL_ALLOWLIST: dict[str, list[str]] = {
    "filesystem": ["read_file", "list_directory", "write_file"],
    "database": ["query", "read", "select", "list_tables", "describe"],
    "code_execution": [],   # empty → all tools blocked under strict; DLP only under balanced
    "browser": ["navigate", "screenshot", "get_content", "search"],
    "web_search": ["search", "query"],
    "unknown": [],           # cannot derive a tool list
}

# Capability → rate limits (advisory; mcpfw enforces in v0.2.0).
_CAPABILITY_RATE_LIMITS: dict[str, dict] = {
    "database":       {"max_calls": 3,  "window_seconds": 60},
    "code_execution": {"max_calls": 10, "window_seconds": 60},
    "filesystem":     {"max_calls": 30, "window_seconds": 60},
    "browser":        {"max_calls": 30, "window_seconds": 60},
    "web_search":     {"max_calls": 60, "window_seconds": 60},
}

# SaaS → response DLP patterns (appended to global rules when that SaaS is present).
_SAAS_DLP: dict[str, list[dict]] = {
    "stripe": [
        {
            "name": "detect-stripe-key",
            "detect_patterns": [r"sk_live_[0-9a-zA-Z]{24,}", r"rk_live_[0-9a-zA-Z]{24,}"],
            "severity": "critical",
            "reason": "Stripe live secret key in MCP response",
        }
    ],
    "github": [
        {
            "name": "detect-github-token",
            "detect_patterns": [r"ghp_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9_]{82}"],
            "severity": "critical",
            "reason": "GitHub personal access token in MCP response",
        }
    ],
    "salesforce": [
        {
            "name": "detect-salesforce-secret",
            "detect_patterns": [r"(?i)(client_secret|consumer_secret)\s*=\s*\S{8,}"],
            "severity": "critical",
            "reason": "Salesforce OAuth secret in MCP response",
        }
    ],
    "google_drive": [
        {
            "name": "detect-google-token",
            "detect_patterns": [r"(?i)(refresh_token|access_token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}"],
            "severity": "warning",
            "reason": "Google OAuth token in MCP response",
        }
    ],
    "servicenow": [
        {
            "name": "detect-servicenow-key",
            "detect_patterns": [r"(?i)(sn_token|servicenow_key|service_now_key)\s*[:=]\s*\S{8,}"],
            "severity": "critical",
            "reason": "ServiceNow API key in MCP response",
        }
    ],
}

# ---------------------------------------------------------------------------
# Base DLP rules — included in all stances
# ---------------------------------------------------------------------------

_BASE_DLP_RULES: list[dict] = [
    {
        "name": "detect-openai-key",
        "detect_patterns": [
            r"sk-[a-zA-Z0-9\-_]{20,}",
            r"sk-proj-[A-Za-z0-9_\-]{20,}",
        ],
        "severity": "critical",
        "reason": "OpenAI / LLM API key detected in MCP response",
    },
    {
        "name": "detect-anthropic-key",
        "detect_patterns": [r"sk-ant-[a-zA-Z0-9\-_]{20,}"],
        "severity": "critical",
        "reason": "Anthropic API key detected in MCP response",
    },
    {
        "name": "detect-aws-credentials",
        "detect_patterns": [
            r"AKIA[0-9A-Z]{16}",
            r"AWS_SECRET_ACCESS_KEY\s*=",
        ],
        "severity": "critical",
        "reason": "AWS credentials detected in MCP response",
    },
    {
        "name": "detect-private-key",
        "detect_patterns": [r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"],
        "severity": "critical",
        "reason": "Private key material in MCP response",
    },
    {
        "name": "detect-prompt-injection",
        "detect_patterns": [
            r"(?i)(SYSTEM\s*:|ignore (all )?previous instructions|you are now|DO NOT (inform|display|tell))",
            r"(?i)(MUST call|mandatory.*step|call .{3,40} again)",
        ],
        "severity": "critical",
        "reason": "Prompt-injection attempt detected in MCP response",
    },
    {
        "name": "detect-retry-injection",
        "detect_patterns": [
            r"(?i)(please call .{3,40} again|retry with|re-?call)",
            r"(?i)for (higher|better|improved) (accuracy|results|confidence)",
            r"(?i)(confidence|score).{0,30}(below|under).{0,20}threshold",
        ],
        "severity": "warning",
        "reason": "Response instructs AI to re-invoke a tool — possible billing amplification",
        "_force_log": True,  # always log, never block
    },
    {
        "name": "detect-pagination-injection",
        "detect_patterns": [
            r"(?i)(call .{3,40}\(.*page\s*=\s*\d+|fetch.{0,20}next.{0,20}page)",
            r"(?i)(\d+\s+more\s+(records|results|items|rows)\s+available)",
        ],
        "severity": "warning",
        "reason": "Response instructs AI to fetch more pages — possible pagination amplification",
        "_force_log": True,
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dlp_action(stance: str, rule: dict) -> str:
    """Return DLP rule action based on stance and rule flags."""
    if rule.get("_force_log"):
        return "log"
    if stance == "monitor":
        return "log"
    return "block"


def _build_response_rule(rule_def: dict, stance: str) -> dict:
    return {
        "name": rule_def["name"],
        "detect_patterns": rule_def["detect_patterns"],
        "action": _dlp_action(stance, rule_def),
        "severity": rule_def["severity"],
        "reason": rule_def["reason"],
    }


def _effective_risk(server: dict) -> int:
    return _RISK_ORDER.get(server.get("risk", "low"), 1)


def _is_shadow(server: dict) -> bool:
    """True if this server looks ungoverned / shadow-classified."""
    return (
        (not server.get("publisher_verified") and _effective_risk(server) >= _RISK_ORDER["high"])
        or server.get("source") == "process"
        or (server.get("is_local_script") and server.get("capability") == "unknown")
    )


def _is_always_block(server: dict) -> bool:
    pkg = server.get("package") or ""
    return any(b in pkg for b in _ALWAYS_BLOCK_PACKAGES)


# ---------------------------------------------------------------------------
# Server policy builders
# ---------------------------------------------------------------------------


def _build_server_policy_strict(server: dict) -> dict:
    """Build a strict (deny-by-default) server policy."""
    name = server["server_name"]
    cap = server.get("capability")
    is_local = server.get("is_local_script", False)

    if _is_always_block(server) or _effective_risk(server) >= _RISK_ORDER["critical"]:
        return {
            "server": name,
            "default_action": "block",
            "reason": f"Blocked: risk={server.get('risk', 'unknown')}, package={server.get('package')}",
        }

    sp: dict = {
        "server": name,
        "default_action": "block",
    }

    allowed = _CAPABILITY_TOOL_ALLOWLIST.get(cap, []) if cap else []
    if allowed:
        sp["allowed_tools"] = allowed

    blocked = []
    if is_local or cap == "code_execution":
        blocked = ["execute_command", "run_script", "shell", "eval", "run_code"]
    if blocked:
        sp["blocked_tools"] = blocked

    tool_rules = _build_tool_rules(server, "strict")
    if tool_rules:
        sp["tool_rules"] = tool_rules

    return sp


def _build_server_policy_balanced(server: dict) -> dict:
    """Build a balanced (allow+log+DLP) server policy."""
    name = server["server_name"]
    cap = server.get("capability")
    is_local = server.get("is_local_script", False)
    risk = _effective_risk(server)

    if _is_always_block(server) or risk >= _RISK_ORDER["critical"]:
        return {
            "server": name,
            "default_action": "block",
            "reason": f"Blocked: risk={server.get('risk', 'unknown')}, package={server.get('package')}",
        }

    sp: dict = {
        "server": name,
        "default_action": "allow",
    }

    # Unverified or high-risk servers get an allowlist
    if not server.get("publisher_verified") or risk >= _RISK_ORDER["high"]:
        allowed = _CAPABILITY_TOOL_ALLOWLIST.get(cap, []) if cap else []
        if allowed:
            sp["allowed_tools"] = allowed

    blocked = []
    if is_local or cap == "code_execution":
        blocked = ["execute_command", "run_script", "shell", "eval", "run_code"]
    if blocked:
        sp["blocked_tools"] = blocked

    tool_rules = _build_tool_rules(server, "balanced")
    if tool_rules:
        sp["tool_rules"] = tool_rules

    return sp


def _build_server_policy_monitor(server: dict) -> dict:
    """Build a monitor-only (log everything, block nothing) server policy."""
    name = server["server_name"]

    if _is_always_block(server):
        return {
            "server": name,
            "default_action": "block",
            "reason": "server-everything always blocked regardless of stance",
        }

    sp: dict = {
        "server": name,
        "default_action": "allow",
    }

    tool_rules = _build_tool_rules(server, "monitor")
    if tool_rules:
        sp["tool_rules"] = tool_rules

    return sp


def _build_tool_rules(server: dict, stance: str) -> list[dict]:
    """Build tool_rules for a single server based on its capabilities."""
    cap = server.get("capability")
    scan_path = server.get("_scan_path", "~")
    rules: list[dict] = []

    if cap == "filesystem":
        if stance == "monitor":
            rules.append({
                "name": "log-filesystem-access",
                "tools": ["read_file", "write_file", "list_directory", "delete_file"],
                "action": "log",
                "severity": "info",
                "reason": "Logging filesystem tool calls for audit",
            })
        else:
            rules.append({
                "name": "restrict-file-paths",
                "tools": ["read_file", "write_file", "list_directory"],
                "action": "allow",
                "allow_paths": [scan_path, "/tmp"],
                "severity": "critical",
                "reason": "File access restricted to scanned project directory and /tmp",
            })

    if cap == "database":
        rl = _CAPABILITY_RATE_LIMITS["database"]
        note = "# rate_limit enforcement planned for mcpfw v0.2.0"
        rules.append({
            "name": "rate-limit-database",
            "tools": ["query", "execute", "select", "read"],
            "action": "allow",
            "rate_limit": rl,
            "_comment": note,
            "reason": f"Database calls capped at {rl['max_calls']}/min to prevent amplification",
        })

    if cap == "browser":
        if stance != "monitor":
            rules.append({
                "name": "block-c2-webhook-urls",
                "tools": ["navigate", "fetch", "request", "post"],
                "action": "block" if stance == "strict" else "log",
                "block_patterns": [
                    r"(?i)(c2\.|ngrok\.io|requestbin|webhook\.site|burpcollaborator)",
                    r"(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                ],
                "severity": "critical",
                "reason": "Browser URL matches untrusted / C2 domain pattern",
            })

    if cap == "web_search":
        if stance != "monitor":
            rules.append({
                "name": "block-credential-in-search",
                "tools": ["search", "query"],
                "action": "block" if stance == "strict" else "log",
                "block_patterns": [
                    r"AKIA[0-9A-Z]{16}",
                    r"(?i)aws_secret|aws_access_key",
                    r"[A-Za-z0-9+/]{40,}={0,2}",
                    r"-----BEGIN",
                ],
                "severity": "warning",
                "reason": "Search query contains credential-like pattern — possible side-channel exfil",
            })

    return rules


# ---------------------------------------------------------------------------
# Main exporter
# ---------------------------------------------------------------------------


def export_mcpfw_policy(scan_result: dict, stance: str = "balanced") -> dict:
    """
    Convert scanner MCP findings into a mcpfw policy dict.

    Parameters
    ----------
    scan_result:
        Full return value of execute_scan_all(). Reads scan_result["mcp"].
    stance:
        "strict" | "balanced" | "monitor". Unknown values default to "balanced".

    Returns
    -------
    dict matching the mcpfw YAML schema — pass to ruamel.yaml.dump().
    Never raises.
    """
    try:
        if stance not in VALID_STANCES:
            logger.warning("Unknown stance %r — defaulting to 'balanced'", stance)
            stance = "balanced"

        mcp: dict = scan_result.get("mcp") or {}
        servers: list[dict] = mcp.get("servers") or []
        saas_list: list[str] = mcp.get("saas_via_mcp") or []
        network_detected: bool = mcp.get("network_detected", False)

        # Annotate each server with the scan path for allow_paths generation.
        scan_path = str(scan_result.get("scan_path") or "~")
        for s in servers:
            s["_scan_path"] = scan_path

        # Deduplicate by server_name, keeping highest risk.
        seen: dict[str, dict] = {}
        for s in servers:
            sn = s.get("server_name", "unknown")
            if sn not in seen or _effective_risk(s) > _effective_risk(seen[sn]):
                seen[sn] = s
        deduped = list(seen.values())

        # Build server policies.
        server_policies: list[dict] = []
        for s in deduped:
            sn = s.get("server_name", "")
            if sn.startswith("network:"):
                # Network-only detection — no tool list known; skip per-server entry,
                # handled by wildcard below.
                continue
            if stance == "strict":
                sp = _build_server_policy_strict(s)
            elif stance == "monitor":
                sp = _build_server_policy_monitor(s)
            else:
                sp = _build_server_policy_balanced(s)

            # Remove internal annotation before output.
            sp.pop("_scan_path", None)
            server_policies.append(sp)

        # If network-detected servers with no config, add a cautious wildcard entry.
        if network_detected and not any(s.get("server_name", "").startswith("network:") is False for s in deduped):
            server_policies.append({
                "server": "*",
                "default_action": "block" if stance == "strict" else "allow",
                "_comment": "network-only MCP activity detected with no local config file",
            })

        # Build global DLP rules.
        global_dlp = [_build_response_rule(r, stance) for r in _BASE_DLP_RULES]

        # Add SaaS-specific DLP.
        seen_dlp_names: set[str] = {r["name"] for r in global_dlp}
        for saas in saas_list:
            for rule_def in _SAAS_DLP.get(saas, []):
                if rule_def["name"] not in seen_dlp_names:
                    global_dlp.append(_build_response_rule(rule_def, stance))
                    seen_dlp_names.add(rule_def["name"])

        policy: dict = {
            "version": 1,
            "default_action": "block" if stance == "strict" else "allow",
            "verify_server_tools": stance == "strict",
            "response_rules": global_dlp,
            "servers": server_policies,
        }

        return policy

    except Exception:
        logger.exception("export_mcpfw_policy failed — returning minimal stub")
        return {
            "version": 1,
            "default_action": "allow",
            "verify_server_tools": False,
            "response_rules": [_build_response_rule(r, "balanced") for r in _BASE_DLP_RULES],
            "servers": [],
        }


def _strip_internal_keys(obj: object) -> None:
    """Remove internal-only keys (prefixed with _) before YAML serialization."""
    if isinstance(obj, dict):
        for key in [k for k in list(obj.keys()) if k.startswith("_")]:
            obj.pop(key)
        for v in obj.values():
            _strip_internal_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            _strip_internal_keys(item)
