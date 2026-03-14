"""
SaaS connection and credential presence detector.

CRITICAL PRIVACY RULE:
    Never capture, log, store, or transmit credential VALUES.
    Only detect and report the PRESENCE of credential keys/patterns.
"""

from __future__ import annotations

import os
from typing import Dict, List

SAAS_ENV_PATTERNS: Dict[str, List[str]] = {
    "salesforce": ["SFDC_", "SALESFORCE_", "SF_ACCESS_TOKEN", "SF_CLIENT_"],
    "slack": ["SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK", "SLACK_SIGNING_"],
    "github": ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "GITHUB_APP_"],
    "gitlab": ["GITLAB_TOKEN", "GITLAB_PAT", "CI_JOB_TOKEN"],
    "jira": ["JIRA_TOKEN", "JIRA_API_KEY", "ATLASSIAN_TOKEN", "ATLASSIAN_API_"],
    "hubspot": ["HUBSPOT_", "HS_API_KEY", "HS_ACCESS_TOKEN"],
    "notion": ["NOTION_TOKEN", "NOTION_API_KEY", "NOTION_SECRET"],
    "airtable": ["AIRTABLE_API_KEY", "AIRTABLE_TOKEN"],
    "stripe": ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_WEBHOOK_"],
    "twilio": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"],
    "sendgrid": ["SENDGRID_API_KEY", "SENDGRID_"],
    "snowflake": [
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_PASSWORD",
        "SNOWFLAKE_WAREHOUSE",
        "SNOWFLAKE_DATABASE",
    ],
    "databricks": ["DATABRICKS_TOKEN", "DATABRICKS_HOST", "DATABRICKS_CLUSTER_"],
    "openai": ["OPENAI_API_KEY", "OPENAI_ORG_ID"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "aws": [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
    ],
    "gcp": [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCLOUD_PROJECT",
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
    ],
    "azure": [
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
    ],
    "postgres": [
        "DATABASE_URL",
        "POSTGRES_URL",
        "POSTGRES_PASSWORD",
        "PG_PASSWORD",
        "DB_PASSWORD",
    ],
    "mysql": ["MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_URL"],
    "redis": ["REDIS_URL", "REDIS_PASSWORD", "REDIS_HOST"],
    "mongodb": ["MONGODB_URI", "MONGO_URL", "MONGO_PASSWORD"],
}


SAAS_IMPORT_PATTERNS: Dict[str, List[str]] = {
    "salesforce": ["simple_salesforce", "salesforce_bulk", "pysftp"],
    "slack": ["slack_sdk", "slack_bolt", "slackclient"],
    "github": ["github", "PyGithub", "ghapi"],
    "gitlab": ["gitlab"],
    "jira": ["jira", "atlassian"],
    "hubspot": ["hubspot"],
    "notion": ["notion_client"],
    "airtable": ["airtable"],
    "stripe": ["stripe"],
    "twilio": ["twilio"],
    "sendgrid": ["sendgrid"],
    "snowflake": ["snowflake.connector", "snowflake.sqlalchemy"],
    "databricks": ["databricks.sdk", "databricks_cli", "databricks"],
    "openai": ["openai"],
    "anthropic": ["anthropic"],
    "aws": ["boto3", "botocore"],
    "gcp": ["google.cloud", "googleapiclient", "google.auth"],
    "azure": ["azure.identity", "azure.mgmt", "azure.core"],
    "postgres": ["psycopg2", "asyncpg", "sqlalchemy"],
    "redis": ["redis", "aioredis"],
    "mongodb": ["pymongo", "motor"],
}


ENV_FILE_NAMES: List[str] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.staging",
    ".env.production",
    ".env.test",
    "config/secrets.yml",
    "config/secrets.yaml",
    "config/credentials.yml",
    "config/credentials.yaml",
    ".secrets",
    "secrets.env",
]

SAAS_DOMAINS: Dict[str, List[str]] = {
    "openai": ["api.openai.com", "openai.com"],
    "anthropic": ["api.anthropic.com", "claude.ai"],
    "google_ai": [
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com",
        "bard.google.com",
    ],
    "github": [
        "github.com",
        "api.github.com",
        "copilot.github.com",
        "lb-140-82-114",
        "lb-140-82-116",
    ],
    "gitlab": ["gitlab.com", "api.gitlab.com"],
    "slack": ["slack.com", "api.slack.com", "hooks.slack.com"],
    "salesforce": ["salesforce.com", "force.com", "lightning.force.com"],
    "hubspot": ["api.hubspot.com", "hubspot.com"],
    "jira": ["atlassian.net", "atlassian.com", "jira.com"],
    "notion": ["notion.so", "api.notion.com"],
    "airtable": ["airtable.com", "api.airtable.com"],
    "stripe": ["api.stripe.com", "stripe.com"],
    "twilio": ["twilio.com", "api.twilio.com"],
    "sendgrid": ["sendgrid.com", "api.sendgrid.com"],
    "snowflake": ["snowflakecomputing.com"],
    "databricks": ["databricks.com", "azuredatabricks.net"],
    "aws": ["amazonaws.com", "aws.amazon.com", "s3.amazonaws.com"],
    "gcp": ["googleapis.com", "google.com", "gcloud.google.com"],
    "azure": [
        "azure.com",
        "microsoft.com",
        "azurewebsites.net",
        "microsoftonline.com",
    ],
    "postgres": [],
    "redis": [],
    "mongodb": ["mongodb.com"],
}

SAAS_PORTS: Dict[int, str] = {
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
    1433: "mssql",
    3306: "mysql",
}

SAAS_DESKTOP_APPS: Dict[str, List[str]] = {
    "slack": ["Slack"],
    "notion": ["Notion"],
    "github": ["GitHub Desktop"],
    "figma": ["Figma"],
    "linear": ["Linear"],
    "discord": ["Discord"],
}

# Generic desktop/extension SaaS: attribute to all agents (any agent could use them)
GENERIC_DESKTOP_SAAS = frozenset({"slack", "notion", "figma", "linear", "discord"})

# Layer 2 connection "service" display name -> saas slug
SERVICE_TO_SAAS: Dict[str, str] = {
    "openai": "openai",
    "google ai": "google_ai",
    "github copilot": "github",
    "claude": "anthropic",
    "anthropic": "anthropic",
}

SAAS_BUNDLE_IDENTIFIERS: Dict[str, List[str]] = {
    "anthropic": ["com.anthropic"],
    "github": ["com.github.GitHubDesktop", "com.github.Electron"],
    "slack": ["com.tinyspeck.slackmacgap"],
    "notion": ["notion.id"],
    "figma": ["com.figma"],
    "discord": ["com.hnc.Discord"],
    "linear": ["com.linear"],
    "cursor": ["com.todesktop.230313mzl4w4u92"],
    "openai": ["com.openai"],
}

SAAS_VSCODE_EXTENSIONS: Dict[str, List[str]] = {
    "github": ["github.copilot", "github.vscode-pull-request-github"],
    "gitlab": ["gitlab.gitlab-workflow"],
    "azure": ["ms-azure", "ms-vscode.azure"],
    "aws": ["amazonwebservices"],
    "anthropic": ["anthropic", "claude"],
    "openai": ["openai"],
    "databricks": ["databricks"],
    "snowflake": ["snowflake"],
}


def detect_saas_from_env_vars() -> Dict[str, List[str]]:
    """
    Scan current process environment variables for SaaS credential key patterns.

    Returns dict of {saas_name: [evidence_strings]} for any matches found.
    Never returns values — only reports which key patterns were detected.
    """
    import os

    findings: Dict[str, List[str]] = {}
    env_keys = list(os.environ.keys())

    for saas, patterns in SAAS_ENV_PATTERNS.items():
        matched: List[str] = []
        for key in env_keys:
            key_upper = key.upper()
            for pattern in patterns:
                if key_upper.startswith(pattern) or key_upper == pattern.rstrip("_"):
                    matched.append("env_var_present")
                    break
        if matched:
            findings[saas] = list(set(matched))

    return findings


def detect_saas_from_imports(file_path: str) -> Dict[str, List[str]]:
    """
    Scan a Python source file for SaaS-related import statements.

    Returns dict of {saas_name: [evidence_strings]} for any matches found.
    Uses AST parsing when possible, falls back to line scanning.
    Never reads values — only detects import statements.
    """
    import ast

    findings: Dict[str, List[str]] = {}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except (OSError, PermissionError):
        return {}

    imported_modules = set()
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split(".")[0])
                    imported_modules.add(node.module)
    except SyntaxError:
        for line in source.splitlines():
            line = line.strip()
            if line.startswith("import ") or line.startswith("from "):
                parts = line.split()
                if len(parts) >= 2:
                    imported_modules.add(parts[1].split(".")[0])

    for saas, patterns in SAAS_IMPORT_PATTERNS.items():
        for pattern in patterns:
            module_root = pattern.split(".")[0]
            if pattern in imported_modules or module_root in imported_modules:
                if saas not in findings:
                    findings[saas] = []
                if "import_detected" not in findings[saas]:
                    findings[saas].append("import_detected")

    return findings


def detect_saas_from_env_files(search_dir: str) -> Dict[str, List[str]]:
    """
    Walk search_dir looking for .env files and similar credential files.

    For each found, scan key names (never values) for SaaS patterns.
    Returns dict of {saas_name: [evidence_strings]}.

    PRIVACY: reads only the KEY side of KEY=VALUE pairs. Value is never
    read, stored, or transmitted. Lines without = are skipped.
    """
    import os

    findings: Dict[str, List[str]] = {}
    credential_files_found: List[str] = []

    for root, dirs, files in os.walk(search_dir):
        dirs[:] = [
            d
            for d in dirs
            if d
            not in (
                "node_modules",
                "__pycache__",
                ".git",
                ".venv",
                "venv",
                "site-packages",
                ".tox",
                "dist",
                "build",
            )
        ]

        for filename in files:
            rel_path = os.path.join(os.path.relpath(root, search_dir), filename).lstrip(
                "./"
            )

            matched_pattern = None
            for pattern in ENV_FILE_NAMES:
                if rel_path == pattern or filename == os.path.basename(pattern):
                    matched_pattern = pattern
                    break

            if not matched_pattern:
                continue

            file_path = os.path.join(root, filename)
            credential_files_found.append(rel_path)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue

                        key = line.split("=", 1)[0].strip().upper()

                        for saas, patterns in SAAS_ENV_PATTERNS.items():
                            for pattern in patterns:
                                if key.startswith(pattern) or key == pattern.rstrip("_"):
                                    if saas not in findings:
                                        findings[saas] = []
                                    evidence = f"env_file_present:{os.path.basename(file_path)}"
                                    if evidence not in findings[saas]:
                                        findings[saas].append(evidence)
            except (OSError, PermissionError):
                continue

    if credential_files_found:
        findings["_credential_files"] = credential_files_found

    return findings


def _finding_matches_agent(
    finding: dict,
    agent_framework: str,
    agent_process_name: str,
) -> bool:
    """
    Returns True ONLY if this network finding can be attributed
    to this specific agent. Strict matching — when in doubt, exclude.
    """
    if not agent_framework.strip() and not agent_process_name.strip():
        return True  # no context = include all

    # connections array uses "process"; findings array uses "process_name"
    process = (
        (finding.get("process_name") or finding.get("process") or "")
    ).lower().strip()
    # provider from findings; service from connections — normalize via SERVICE_TO_SAAS
    provider_raw = (
        (finding.get("provider") or finding.get("service") or "")
    ).lower().strip()
    provider_slug = SERVICE_TO_SAAS.get(provider_raw, provider_raw)
    remote_host = (
        (finding.get("remote_host") or finding.get("destination") or "")
    ).lower().strip()

    fw = agent_framework.lower().strip()
    proc = agent_process_name.lower().strip()

    # Match on process name (strongest signal)
    if proc and process:
        if proc in process or process in proc:
            return True

    # Match on framework/provider or service (normalized slug)
    if fw and provider_slug:
        if fw in provider_slug or provider_slug in fw:
            return True

    # Match on remote_host domain (agent_framework may be slug or e.g. "google")
    if fw and remote_host:
        domains = SAAS_DOMAINS.get(fw, [])
        if not domains:
            for saas_key, dlist in SAAS_DOMAINS.items():
                if fw in saas_key or saas_key in fw:
                    domains = dlist
                    break
        for domain in domains or []:
            if domain and domain in remote_host:
                return True

    return False


def detect_saas_from_network_findings(
    network_findings: list,
    agent_framework: str | None = None,
    agent_process_name: str | None = None,
) -> Dict[str, List[str]]:
    """
    Scan Layer 2 network findings and connections for active SaaS.
    When agent context is set, ONLY includes findings that match
    _finding_matches_agent() (exclusive filter).
    Returns {saas: ["active_connection"]} or ["active_connection_unmatched"].
    """
    findings: Dict[str, List[str]] = {}
    try:
        agent_fw = (agent_framework or "").strip()
        agent_proc = (agent_process_name or "").strip()

        for nf in network_findings or []:
            if not isinstance(nf, dict):
                continue
            matched_saas: List[str] = []

            # 1. provider field (findings format)
            provider = (nf.get("provider") or "").lower()
            if provider:
                for saas in SAAS_DOMAINS:
                    if provider == saas or saas in provider or provider in saas:
                        matched_saas.append(saas)
                        break

            # 2. service field (connections format) -> map to slug
            if not matched_saas:
                service = (nf.get("service") or "").lower()
                if service and service in SERVICE_TO_SAAS:
                    matched_saas.append(SERVICE_TO_SAAS[service])
                if not matched_saas and service:
                    for slug in SAAS_DOMAINS:
                        if slug in service or service in slug:
                            matched_saas.append(slug)
                            break

            # 3. remote_host field
            if not matched_saas:
                remote_host = (nf.get("remote_host") or "").lower()
                for saas, domains in SAAS_DOMAINS.items():
                    for domain in domains:
                        if domain and domain in remote_host:
                            matched_saas.append(saas)
                            break
                    if matched_saas:
                        break

            # 4. destination field
            if not matched_saas:
                destination = (nf.get("destination") or "").lower()
                for saas, domains in SAAS_DOMAINS.items():
                    for domain in domains:
                        if domain and domain in destination:
                            matched_saas.append(saas)
                            break
                    if matched_saas:
                        break

            if not matched_saas:
                continue

            has_context = bool(agent_fw or agent_proc)

            if has_context:
                is_matched = _finding_matches_agent(nf, agent_fw, agent_proc)
                if not is_matched:
                    continue  # exclude entirely
                evidence_label = "active_connection"  # matched = confirmed
            else:
                evidence_label = "active_connection_unmatched"  # no context = unmatched

            for saas in matched_saas:
                if saas not in findings:
                    findings[saas] = []
                if evidence_label not in findings[saas]:
                    findings[saas].append(evidence_label)
    except Exception:
        pass
    return findings


def detect_saas_from_open_sockets(
    layer4_findings: list,
    agent_framework: str | None = None,
    agent_process_name: str | None = None,
) -> Dict[str, List[str]]:
    """
    Scan Layer 4 process_open_sockets findings for SaaS connections.
    When agent context is set, ONLY includes rows that match
    _finding_matches_agent() (exclusive filter).
    Returns {saas: ["open_socket"]} for matches.
    """
    findings: Dict[str, List[str]] = {}
    agent_fw = (agent_framework or "").strip()
    agent_proc = (agent_process_name or "").strip()

    for item in layer4_findings or []:
        if isinstance(item, dict) and "data" in item:
            rows = item["data"]
        elif isinstance(item, list):
            rows = item
        else:
            rows = [item]

        for row in rows:
            if not isinstance(row, dict):
                continue
            remote_address = (
                (row.get("remote_address") or row.get("destination") or row.get("remote_host") or "")
            ).lower()
            remote_port = row.get("remote_port") or row.get("port")

            matched_saas: List[str] = []
            if remote_port is not None:
                try:
                    port_int = int(remote_port)
                    if port_int in SAAS_PORTS:
                        matched_saas.append(SAAS_PORTS[port_int])
                except (ValueError, TypeError):
                    pass

            for saas, domains in SAAS_DOMAINS.items():
                for domain in domains:
                    if domain and domain in remote_address:
                        if saas not in matched_saas:
                            matched_saas.append(saas)
                        break

            if not matched_saas:
                continue

            # Exclusive attribution: build minimal finding and use same filter as network
            try:
                synthetic_finding = {
                    "process_name": row.get("process_name"),
                    "process": row.get("process"),
                    "remote_host": remote_address,
                    "destination": remote_address,
                }
                if not _finding_matches_agent(synthetic_finding, agent_fw, agent_proc):
                    continue
            except Exception:
                continue

            for saas in matched_saas:
                if saas not in findings:
                    findings[saas] = []
                if "open_socket" not in findings[saas]:
                    findings[saas].append("open_socket")

    return findings


def detect_saas_from_browser_history(
    layer4_findings: list,
) -> Dict[str, List[str]]:
    """
    Scan Layer 4 browser history findings for SaaS domain visits.
    Returns {saas: ["browser_history"]} for matches.
    Browser history = user is actively using this SaaS,
    even if no code integration exists yet.
    """
    findings: Dict[str, List[str]] = {}

    for item in layer4_findings:
        if not isinstance(item, dict):
            continue
        url = (
            (item.get("url") or item.get("visit_url") or item.get("title") or "")
        ).lower()

        if not url:
            continue

        for saas, domains in SAAS_DOMAINS.items():
            for domain in domains:
                if domain and domain in url:
                    if saas not in findings:
                        findings[saas] = []
                    if "browser_history" not in findings[saas]:
                        findings[saas].append("browser_history")

    return findings


def detect_saas_from_desktop_and_extensions(
    layer4_findings: list,
    agent_framework: str | None = None,
) -> Dict[str, List[str]]:
    """
    Scan Layer 4 desktop_apps and vscode_extensions findings.
    Generic apps (Slack, Notion, etc.) are attributed to all agents.
    Framework-specific (GitHub Copilot, Claude desktop, etc.) only when
    agent_framework matches the SaaS (e.g. github-framework agents get GitHub extension).
    """
    findings: Dict[str, List[str]] = {}
    agent_fw_lower = (agent_framework or "").lower()

    try:
        for item in layer4_findings or []:
            if not isinstance(item, dict):
                continue
            app_name = (
                item.get("name") or item.get("app_name") or item.get("bundle_name") or ""
            )
            for saas, apps in SAAS_DESKTOP_APPS.items():
                if saas in GENERIC_DESKTOP_SAAS:
                    pass
                elif agent_fw_lower and saas not in agent_fw_lower and agent_fw_lower not in saas:
                    continue
                for app in apps:
                    if app.lower() in app_name.lower():
                        if saas not in findings:
                            findings[saas] = []
                        if "desktop_app_installed" not in findings[saas]:
                            findings[saas].append("desktop_app_installed")
                        break

            try:
                bundle_id = (item.get("bundle_identifier") or "").lower()
                if bundle_id:
                    for saas, patterns in SAAS_BUNDLE_IDENTIFIERS.items():
                        if saas in GENERIC_DESKTOP_SAAS:
                            pass
                        elif agent_fw_lower and saas not in agent_fw_lower and agent_fw_lower not in saas:
                            continue
                        for pattern in patterns:
                            if pattern.lower() in bundle_id:
                                if saas not in findings:
                                    findings[saas] = []
                                if "desktop_app_installed" not in findings[saas]:
                                    findings[saas].append("desktop_app_installed")
                                break
            except Exception:
                pass

            ext_id = (
                (item.get("extension_id") or item.get("identifier") or item.get("name") or "")
            ).lower()
            for saas, ext_patterns in SAAS_VSCODE_EXTENSIONS.items():
                if saas in GENERIC_DESKTOP_SAAS:
                    pass
                elif agent_fw_lower and saas not in agent_fw_lower and agent_fw_lower not in saas:
                    continue
                for pattern in ext_patterns:
                    if pattern.lower() in ext_id:
                        if saas not in findings:
                            findings[saas] = []
                        if "vscode_extension_detected" not in findings[saas]:
                            findings[saas].append("vscode_extension_detected")
                        break
    except Exception:
        pass
    return findings


def _compute_confidence(evidence: List[str]) -> str:
    """
    Compute confidence tier based on evidence types.
    active_connection alone → "confirmed" (live observed connection).
    Machine-level signals have ceilings: browser_history only → "low";
    open_socket / active_connection_unmatched → max "medium".
    """
    RUNTIME_SIGNALS = {
        "active_connection",
        "active_connection_unmatched",
        "open_socket",
        "browser_history",
        "vscode_extension_detected",
        "desktop_app_installed",
    }
    STATIC_SIGNALS = (
        "import_detected",
        "env_var_present",
        "env_file_present",
    )

    has_active_matched = "active_connection" in evidence
    has_active_unmatched = "active_connection_unmatched" in evidence
    has_browser = "browser_history" in evidence
    has_open_socket = "open_socket" in evidence
    runtime_count = sum(1 for e in evidence if e in RUNTIME_SIGNALS)
    total = len(evidence)

    # All evidence is browser_history only → cannot attribute to agent
    if has_browser and not (
        has_active_matched or has_active_unmatched or has_open_socket
        or "vscode_extension_detected" in evidence
        or "desktop_app_installed" in evidence
    ):
        return "low"

    # active_connection alone = confirmed (live observed connection)
    if has_active_matched:
        return "confirmed"

    # active_connection without process match → max "medium"
    if has_active_unmatched and not has_active_matched:
        return "medium"

    # open_socket is machine-level → max "medium"
    if has_open_socket and not has_active_matched:
        return "medium"

    if total >= 3:
        return "confirmed"
    if total >= 2:
        return "high"
    if runtime_count >= 1:
        return "medium"
    return "low"


def _find_search_dir(file_path: str) -> str:
    """
    Walk up from file_path up to 4 directory levels looking for a
    directory that contains .env, pyproject.toml, setup.py, or .git;
    otherwise fall back to os.path.dirname(file_path).
    """
    file_path = os.path.abspath(file_path)
    search_dir = os.path.dirname(file_path)
    root_indicators = [".env", "pyproject.toml", "setup.py", ".git"]
    for _ in range(4):
        if not search_dir:
            break
        for name in root_indicators:
            if os.path.exists(os.path.join(search_dir, name)):
                return search_dir
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent
    return os.path.dirname(file_path)


def build_saas_connections(
    file_path: str,
    search_dir: str,
    network_findings: list | None = None,
    layer4_findings: list | None = None,
    agent_framework: str | None = None,
    agent_process_name: str | None = None,
) -> Dict:
    """
    Aggregate SaaS signals from all available detection layers.
    When agent_framework/agent_process_name are set, machine-level signals
    (Layer 2, desktop/extensions) are filtered to this agent only.

    Layer 1 (static):  env vars, imports, .env files — always per-agent.
    Layer 2 (network): active connections, filtered by agent when context given.
    Layer 4 (endpoint): open sockets, browser history (machine-level),
                        desktop apps, extensions (filtered by framework when given).
    """
    DATABASE_SAAS = {"postgres", "mysql", "redis", "mongodb", "mssql"}
    CLOUD_PROVIDERS = {"aws", "gcp", "azure"}
    LLM_PROVIDERS = {"openai", "anthropic", "google_ai"}

    network_findings = network_findings or []
    layer4_findings = layer4_findings or []

    run_static = bool(file_path and file_path.strip())
    if run_static:
        search_dir = _find_search_dir(file_path)
        env_findings = detect_saas_from_env_vars()
        import_findings = detect_saas_from_imports(file_path)
        file_findings = detect_saas_from_env_files(search_dir)
        credential_files = file_findings.pop("_credential_files", [])
    else:
        env_findings = {}
        import_findings = {}
        file_findings = {}
        credential_files = []

    merged: Dict[str, List[str]] = {}

    network_saas = detect_saas_from_network_findings(
        network_findings,
        agent_framework=agent_framework,
        agent_process_name=agent_process_name,
    )
    socket_saas = detect_saas_from_open_sockets(
        layer4_findings,
        agent_framework=agent_framework,
        agent_process_name=agent_process_name,
    )
    browser_saas = detect_saas_from_browser_history(layer4_findings)
    desktop_saas = detect_saas_from_desktop_and_extensions(
        layer4_findings,
        agent_framework=agent_framework,
    )

    for source in (
        env_findings,
        import_findings,
        file_findings,
        network_saas,
        socket_saas,
        browser_saas,
        desktop_saas,
    ):
        for saas, evidence in source.items():
            if saas not in merged:
                merged[saas] = []
            for e in evidence:
                if e not in merged[saas]:
                    merged[saas].append(e)

    detected = sorted(merged.keys())
    confidence = {
        saas: _compute_confidence(evidence)
        for saas, evidence in merged.items()
    }
    confirmed = [s for s, c in confidence.items() if c == "confirmed"]

    return {
        "detected": detected,
        "confirmed": confirmed,
        "evidence": merged,
        "confidence": confidence,
        "credential_files_found": credential_files,
        "has_database_access": any(s in detected for s in DATABASE_SAAS),
        "has_cloud_provider": any(s in detected for s in CLOUD_PROVIDERS),
        "has_llm_provider": any(s in detected for s in LLM_PROVIDERS),
        "has_external_api_calls": bool(
            set(detected) - DATABASE_SAAS - LLM_PROVIDERS
        ),
    }

