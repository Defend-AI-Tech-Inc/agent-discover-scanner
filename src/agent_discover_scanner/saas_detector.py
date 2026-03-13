"""
SaaS connection and credential presence detector.

CRITICAL PRIVACY RULE:
    Never capture, log, store, or transmit credential VALUES.
    Only detect and report the PRESENCE of credential keys/patterns.
"""

from __future__ import annotations

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


def build_saas_connections(file_path: str, search_dir: str) -> Dict:
    """
    Run all three detectors and merge results into a single
    saas_connections payload for the agent upload.

    Returns:
        {
            "detected": ["salesforce", "slack"],   # sorted list of detected SaaS
            "evidence": {
                "salesforce": ["env_var_present", "import_detected"],
                "slack": ["env_file_present:.env"]
            },
            "credential_files_found": [".env"],    # filenames only
            "has_database_access": True,
            "has_cloud_provider": True,
            "has_llm_provider": True,
            "has_external_api_calls": True,
        }
    """
    DATABASE_SAAS = {"postgres", "mysql", "redis", "mongodb"}
    CLOUD_PROVIDERS = {"aws", "gcp", "azure"}
    LLM_PROVIDERS = {"openai", "anthropic"}

    merged: Dict[str, List[str]] = {}

    env_findings = detect_saas_from_env_vars()
    import_findings = detect_saas_from_imports(file_path)
    file_findings = detect_saas_from_env_files(search_dir)

    credential_files = file_findings.pop("_credential_files", [])

    for source in (env_findings, import_findings, file_findings):
        for saas, evidence in source.items():
            if saas not in merged:
                merged[saas] = []
            for e in evidence:
                if e not in merged[saas]:
                    merged[saas].append(e)

    detected = sorted(merged.keys())

    return {
        "detected": detected,
        "evidence": merged,
        "credential_files_found": credential_files,
        "has_database_access": any(s in detected for s in DATABASE_SAAS),
        "has_cloud_provider": any(s in detected for s in CLOUD_PROVIDERS),
        "has_llm_provider": any(s in detected for s in LLM_PROVIDERS),
        "has_external_api_calls": bool(set(detected) - DATABASE_SAAS - LLM_PROVIDERS),
    }

