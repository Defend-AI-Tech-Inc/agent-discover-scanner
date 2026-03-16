"""
MCP (Model Context Protocol) server detection across all AI clients.

Detects MCP configurations from Claude Desktop, Cursor, Gemini, Codex, VS Code,
project-level configs, package.json/requirements.txt, and network traffic.
Network detection catches non-developer users (e.g. ChatGPT Teams) with no
local config files. Never reads credentials or API keys.
"""

import json
import os
import re

VERIFIED_MCP_PUBLISHERS = {
    "@salesforce/mcp-server": {
        "vendor": "Salesforce",
        "risk": "medium",
        "saas": "salesforce",
        "publisher_verified": True,
    },
    "@salesforce/agentforce-mcp": {
        "vendor": "Salesforce",
        "risk": "medium",
        "saas": "salesforce",
        "publisher_verified": True,
    },
    "@microsoft/graph-mcp": {
        "vendor": "Microsoft",
        "risk": "medium",
        "saas": "microsoft365",
        "publisher_verified": True,
    },
    "microsoft/playwright-mcp": {
        "vendor": "Microsoft",
        "risk": "medium",
        "capability": "browser",
        "publisher_verified": True,
    },
    "@atlassian/jira-mcp": {
        "vendor": "Atlassian",
        "risk": "medium",
        "saas": "jira",
        "publisher_verified": True,
    },
    "@atlassian/confluence-mcp": {
        "vendor": "Atlassian",
        "risk": "medium",
        "saas": "confluence",
        "publisher_verified": True,
    },
    "@github/mcp-server": {
        "vendor": "GitHub",
        "risk": "medium",
        "saas": "github",
        "publisher_verified": True,
    },
    "@stripe/mcp-server": {
        "vendor": "Stripe",
        "risk": "high",
        "saas": "stripe",
        "publisher_verified": True,
    },
    "@notion/mcp": {
        "vendor": "Notion",
        "risk": "medium",
        "saas": "notion",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-filesystem": {
        "vendor": "Anthropic",
        "risk": "high",
        "capability": "filesystem",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-postgres": {
        "vendor": "Anthropic",
        "risk": "high",
        "capability": "database",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-sqlite": {
        "vendor": "Anthropic",
        "risk": "high",
        "capability": "database",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-everything": {
        "vendor": "Anthropic",
        "risk": "critical",
        "capability": "code_execution",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-puppeteer": {
        "vendor": "Anthropic",
        "risk": "medium",
        "capability": "browser",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-brave-search": {
        "vendor": "Anthropic",
        "risk": "low",
        "capability": "web_search",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-github": {
        "vendor": "Anthropic",
        "risk": "medium",
        "saas": "github",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-slack": {
        "vendor": "Anthropic",
        "risk": "medium",
        "saas": "slack",
        "publisher_verified": True,
    },
    "@modelcontextprotocol/server-gdrive": {
        "vendor": "Anthropic",
        "risk": "high",
        "saas": "google_drive",
        "publisher_verified": True,
    },
    "echelon-ai-labs/servicenow-mcp": {
        "vendor": "Community",
        "risk": "high",
        "saas": "servicenow",
        "publisher_verified": False,
        "note": "Not published by ServiceNow — community implementation",
    },
    "mcp-server-servicenow": {
        "vendor": "Community",
        "risk": "high",
        "saas": "servicenow",
        "publisher_verified": False,
    },
}

KNOWN_MCP_NETWORK_ENDPOINTS = {
    "googleapis.com/mcp": {"vendor": "Google", "risk": "medium"},
    "bigquery.googleapis.com": {
        "vendor": "Google",
        "risk": "high",
        "capability": "database",
    },
    "compute.googleapis.com": {"vendor": "Google", "risk": "high"},
    "mcp.cloudflare.com": {"vendor": "Cloudflare", "risk": "medium"},
    "mcp.stripe.com": {"vendor": "Stripe", "risk": "high", "saas": "stripe"},
    ".salesforce.com/mcp": {
        "vendor": "Salesforce",
        "risk": "medium",
        "saas": "salesforce",
    },
    ".force.com/mcp": {
        "vendor": "Salesforce",
        "risk": "medium",
        "saas": "salesforce",
    },
    ".service-now.com": {
        "vendor": "ServiceNow",
        "risk": "high",
        "saas": "servicenow",
    },
    "/mcp": {"vendor": "Unknown", "risk": "medium", "note": "Generic MCP endpoint"},
}

MCP_CONFIG_LOCATIONS = [
    {
        "client": "Claude Desktop",
        "paths": [
            "~/Library/Application Support/Claude/claude_desktop_config.json",
            "~/AppData/Roaming/Claude/claude_desktop_config.json",
            "~/.config/claude/claude_desktop_config.json",
        ],
        "format": "json",
        "key": "mcpServers",
    },
    {
        "client": "Cursor",
        "paths": [
            "~/.cursor/mcp.json",
            "~/Library/Application Support/Cursor/mcp.json",
            "~/AppData/Roaming/Cursor/mcp.json",
        ],
        "format": "json",
        "key": "mcpServers",
    },
    {
        "client": "Gemini CLI",
        "paths": [
            "~/.gemini/settings.json",
            ".gemini/settings.json",
        ],
        "format": "json",
        "key": "mcpServers",
    },
    {
        "client": "OpenAI Codex",
        "paths": [
            "~/.codex/config.toml",
            ".codex/config.toml",
        ],
        "format": "toml",
        "key": "mcp_servers",
    },
    {
        "client": "VS Code Copilot",
        "paths": [
            ".vscode/mcp.json",
            "~/Library/Application Support/Code/User/mcp.json",
            "~/AppData/Roaming/Code/User/mcp.json",
        ],
        "format": "json",
        "key": "servers",
    },
    {
        "client": "Project MCP",
        "paths": ["mcp.json", ".mcp/config.json", ".mcp.json"],
        "format": "json",
        "key": "mcpServers",
    },
]


def _read_json_mcp_config(path: str, key: str, base_dir: str | None = None) -> dict:
    """Read JSON-format MCP config. Return {} on any error. Never reads credentials."""
    try:
        expanded = os.path.expanduser(path)
        if not os.path.isabs(expanded) and base_dir:
            expanded = os.path.join(base_dir, path)
        if not os.path.exists(expanded):
            return {}
        with open(expanded, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data.get(key, {}) if isinstance(data, dict) else {}
    except Exception:
        return {}


def _read_toml_mcp_config(path: str, key: str, base_dir: str | None = None) -> dict:
    """
    Read TOML-format MCP config (OpenAI Codex uses config.toml).
    Use tomllib (Python 3.11+) or simple manual parsing.
    Return {} on any error. Never raises.
    """
    try:
        expanded = os.path.expanduser(path)
        if not os.path.isabs(expanded) and base_dir:
            expanded = os.path.join(base_dir, path)
        if not os.path.exists(expanded):
            return {}

        try:
            import tomllib
            with open(expanded, "rb") as f:
                data = tomllib.load(f)
            return data.get(key, {}) if isinstance(data, dict) else {}
        except ImportError:
            pass

        servers = {}
        with open(expanded, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        pattern = rf"\[{re.escape(key)}\.([^\]]+)\]"
        for match in re.finditer(pattern, content):
            server_name = match.group(1).strip()
            servers[server_name] = {}
        return servers
    except Exception:
        return {}


def _extract_package_name(server_config: dict) -> str | None:
    """
    Extract npm package or python module name from MCP server config.
    Handles: npx @package, python -m module, local script paths.
    Never reads env values, credentials, or URL auth details.
    """
    try:
        command = server_config.get("command", "") or ""
        args = server_config.get("args", []) or []
        url = server_config.get("url") or server_config.get("httpUrl")

        if url:
            return str(url)

        if command in ("npx", "bunx", "pnpm", "dlx") and args:
            for arg in args:
                if isinstance(arg, str) and (
                    arg.startswith("@") or (arg and not arg.startswith("-"))
                ):
                    return arg
            return args[0] if args else None

        if command in ("python", "python3", "uv", "uvx") and args:
            for i, arg in enumerate(args):
                if arg == "-m" and i + 1 < len(args):
                    return args[i + 1]

        if isinstance(command, str) and (
            command.startswith(("/", "~", ".", "$HOME"))
            or command.endswith((".sh", ".py", ".js", ".ts"))
        ):
            return os.path.basename(os.path.expanduser(command))

        return command or None
    except Exception:
        return None


def _classify_server(
    server_name: str,
    package_name: str | None,
    server_config: dict,
    client_name: str,
) -> dict:
    """
    Classify an MCP server against the verified publisher registry.
    Returns classification dict with risk, vendor, capabilities.
    """
    try:
        if package_name:
            for registry_key, info in VERIFIED_MCP_PUBLISHERS.items():
                if package_name == registry_key or registry_key in str(package_name):
                    return {
                        "server_name": server_name,
                        "package": package_name,
                        "vendor": info["vendor"],
                        "publisher_verified": info.get("publisher_verified", True),
                        "risk": info["risk"],
                        "saas": info.get("saas"),
                        "capability": info.get("capability"),
                        "is_local_script": False,
                        "is_remote": "://" in (package_name or ""),
                        "client": client_name,
                        "note": info.get("note"),
                    }

        url = server_config.get("url") or server_config.get("httpUrl", "")
        if url:
            for endpoint, info in KNOWN_MCP_NETWORK_ENDPOINTS.items():
                if endpoint in str(url):
                    return {
                        "server_name": server_name,
                        "package": url,
                        "vendor": info["vendor"],
                        "publisher_verified": False,
                        "risk": info["risk"],
                        "saas": info.get("saas"),
                        "capability": info.get("capability"),
                        "is_local_script": False,
                        "is_remote": True,
                        "client": client_name,
                    }

        command = server_config.get("command", "") or ""
        cmd_str = str(command)
        is_local = (
            cmd_str.startswith(("/", "~", "./", "$HOME"))
            or cmd_str.endswith((".sh", ".py", ".js", ".ts"))
        )
        if is_local:
            return {
                "server_name": server_name,
                "package": package_name or command,
                "vendor": "Unknown",
                "publisher_verified": False,
                "risk": "high",
                "saas": None,
                "capability": "unknown",
                "is_local_script": True,
                "is_remote": False,
                "client": client_name,
                "note": "Local script — no package audit possible",
            }

        return {
            "server_name": server_name,
            "package": package_name,
            "vendor": "Community/Unknown",
            "publisher_verified": False,
            "risk": "high",
            "saas": None,
            "capability": "unknown",
            "is_local_script": False,
            "is_remote": False,
            "client": client_name,
            "note": "Not in verified publisher registry",
        }
    except Exception:
        return {
            "server_name": server_name,
            "package": package_name,
            "vendor": "Unknown",
            "publisher_verified": False,
            "risk": "high",
            "saas": None,
            "capability": "unknown",
            "is_local_script": False,
            "is_remote": False,
            "client": client_name,
            "note": "Classification error",
        }


def detect_mcp_servers(
    scan_dir: str | None = None,
    file_path: str | None = None,
    network_findings: list | None = None,
    layer4_findings: list | None = None,
) -> dict:
    """
    Detect MCP server configurations from ALL AI clients.

    Detection priority:
    1. Config files (Claude Desktop, Cursor, Gemini, Codex, VS Code)
    2. package.json / requirements.txt in scan_dir
    3. Network connections to known MCP endpoints (catches non-developers with no config)

    Returns dict with servers, saas_via_mcp, capabilities, flags, highest_risk,
    clients_with_mcp, network_detected, source_summary. Never raises.
    """
    all_servers = []
    clients_found = []
    network_detected = False
    base_dir = (os.path.expanduser(scan_dir) if scan_dir else None) or os.getcwd()

    try:
        for location in MCP_CONFIG_LOCATIONS:
            for path in location["paths"]:
                expanded = os.path.expanduser(path)
                if not os.path.isabs(expanded):
                    expanded = os.path.join(base_dir, path)
                if not os.path.exists(expanded):
                    continue

                use_base = None if path.startswith("~") else base_dir
                if location["format"] == "json":
                    mcp_servers = _read_json_mcp_config(path, location["key"], use_base)
                else:
                    mcp_servers = _read_toml_mcp_config(path, location["key"], use_base)

                if not mcp_servers or not isinstance(mcp_servers, dict):
                    continue

                if location["client"] not in clients_found:
                    clients_found.append(location["client"])

                for server_name, server_config in mcp_servers.items():
                    if not isinstance(server_config, dict):
                        server_config = {}
                    package = _extract_package_name(server_config)
                    classification = _classify_server(
                        server_name, package, server_config, location["client"]
                    )
                    all_servers.append(classification)
                break
    except Exception:
        pass

    try:
        if scan_dir:
            pkg_path = os.path.join(os.path.expanduser(scan_dir), "package.json")
            if os.path.exists(pkg_path):
                with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.load(f)
                deps = {
                    **pkg.get("dependencies", {}),
                    **pkg.get("devDependencies", {}),
                }
                for dep, _ver in deps.items():
                    if "mcp" in dep.lower():
                        cl = _classify_server(dep, dep, {}, "package.json")
                        cl["source"] = "package.json"
                        all_servers.append(cl)
    except Exception:
        pass

    try:
        if scan_dir:
            req_path = os.path.join(os.path.expanduser(scan_dir), "requirements.txt")
            if os.path.exists(req_path):
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        pkg = line.strip().split(">=")[0].split("==")[0].strip()
                        if pkg and "mcp" in pkg.lower():
                            cl = _classify_server(pkg, pkg, {}, "requirements.txt")
                            cl["source"] = "requirements.txt"
                            all_servers.append(cl)
    except Exception:
        pass

    try:
        all_network = list(network_findings or []) + list(layer4_findings or [])
        for item in all_network:
            if not isinstance(item, dict):
                continue
            host = (
                item.get("remote_host")
                or item.get("destination")
                or item.get("remote_address")
                or item.get("url")
                or ""
            )
            host = str(host).lower()

            for endpoint, info in KNOWN_MCP_NETWORK_ENDPOINTS.items():
                if endpoint in host:
                    network_detected = True
                    existing = [
                        s
                        for s in all_servers
                        if info.get("saas") and s.get("saas") == info.get("saas")
                    ]
                    if not existing:
                        all_servers.append({
                            "server_name": f"network:{endpoint}",
                            "package": host,
                            "vendor": info["vendor"],
                            "publisher_verified": False,
                            "risk": info["risk"],
                            "saas": info.get("saas"),
                            "capability": info.get("capability"),
                            "is_local_script": False,
                            "is_remote": True,
                            "client": "Network (ChatGPT/browser/unknown)",
                            "note": (
                                "Detected via network traffic — "
                                "likely configured via AI client UI "
                                "with no local config file"
                            ),
                        })
                    break
    except Exception:
        pass

    if not all_servers:
        return {
            "servers": [],
            "saas_via_mcp": [],
            "capabilities": [],
            "has_unverified_servers": False,
            "has_local_scripts": False,
            "has_remote_servers": False,
            "has_filesystem_access": False,
            "has_database_access": False,
            "has_code_execution": False,
            "has_browser_access": False,
            "highest_risk": None,
            "clients_with_mcp": [],
            "network_detected": False,
            "source_summary": "none",
        }

    try:
        saas_via_mcp = sorted({s["saas"] for s in all_servers if s.get("saas")})
        capabilities = sorted({s["capability"] for s in all_servers if s.get("capability")})
    except Exception:
        saas_via_mcp = []
        capabilities = []

    try:
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        highest_risk = max(
            all_servers,
            key=lambda s: risk_order.get(s.get("risk", "low"), 0),
        ).get("risk")
    except Exception:
        highest_risk = "high"

    try:
        sources = {s.get("client", "") for s in all_servers if s.get("client")}
        source_summary = ", ".join(sorted(sources)) or "none"
    except Exception:
        source_summary = "none"

    return {
        "servers": all_servers,
        "saas_via_mcp": saas_via_mcp,
        "capabilities": capabilities,
        "has_unverified_servers": any(
            not s.get("publisher_verified") for s in all_servers
        ),
        "has_local_scripts": any(s.get("is_local_script") for s in all_servers),
        "has_remote_servers": any(s.get("is_remote") for s in all_servers),
        "has_filesystem_access": "filesystem" in capabilities,
        "has_database_access": "database" in capabilities,
        "has_code_execution": "code_execution" in capabilities,
        "has_browser_access": "browser" in capabilities,
        "highest_risk": highest_risk,
        "clients_with_mcp": sorted(clients_found),
        "network_detected": network_detected,
        "source_summary": source_summary,
    }
