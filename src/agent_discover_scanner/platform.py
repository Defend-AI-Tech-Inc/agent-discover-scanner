import json
import logging
import os
import socket
from importlib import metadata as _metadata
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import certifi
import getpass
import platform as _platform

logger = logging.getLogger(__name__)

try:  # Optional dependency; warn once if missing
    import httpx  # type: ignore[import]
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]
    logger.warning(
        "httpx is not installed; DefendAI platform upload is disabled. "
        "Install httpx to enable automatic result upload."
    )

try:  # YAML is optional; fall back to JSON if unavailable
    import yaml  # type: ignore[import]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


_SANDBOX_TENANT_TOKEN = "sandbox-token-001"
_SANDBOX_API_KEY = "sandbox"
_DEFAULT_WAWSDB_URL = "https://wauzeway.defendai.ai"


def load_credentials() -> Optional[Dict[str, str]]:
    """
    Load DefendAI platform credentials from ~/.defendai/config.

    Tries YAML first (if PyYAML is installed), then JSON.
    Never raises; returns None if missing or invalid.
    """
    try:
        config_path = Path(os.path.expanduser("~/.defendai/config"))
        if not config_path.exists():
            return None

        raw = config_path.read_text(encoding="utf-8")
        data: Any = None

        # Try YAML first if available
        if yaml is not None:
            try:
                data = yaml.safe_load(raw)
            except Exception:
                data = None

        # Fallback to JSON
        if data is None:
            try:
                data = json.loads(raw)
            except Exception:
                return None

        if not isinstance(data, dict):
            return None

        api_key = data.get("api_key") or data.get("api-key")
        tenant_token = data.get("tenant_token") or data.get("tenant-token")
        wawsdb_url = data.get("wawsdb_url") or data.get("wawsdb-url")

        if not (api_key and tenant_token and wawsdb_url):
            return None

        return {
            "api_key": str(api_key),
            "tenant_token": str(tenant_token),
            "wawsdb_url": str(wawsdb_url),
        }
    except Exception:
        # Never propagate errors from credential loading
        return None


def format_agents_for_upload(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert scanner inventory report into /scanner/ingest agents[] format.

    Expected scan_results shape (from CorrelationEngine.generate_report):
        {
            "summary": {...},
            "risk_breakdown": {...},
            "inventory": {
                "confirmed": [AgentInventoryItem dicts...],
                "unknown": [...],
                "zombie": [...],
                "ghost": [...],
            },
        }
    """
    inventory = scan_results.get("inventory") or {}
    if not isinstance(inventory, dict):
        return []

    agents: List[Dict[str, Any]] = []

    for classification, items in inventory.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue

            # Derive a human-friendly name with sensible fallbacks
            name = (
                item.get("k8s_workload")
                or item.get("k8s_pod")
                or item.get("process_name")
                or item.get("code_file")
                or item.get("agent_id")
                or "unknown-agent"
            )

            framework = item.get("framework") or "Unknown"
            agent_type = str(classification).upper()

            # Map internal risk levels to a 0–1 confidence score
            risk_level = (item.get("risk_level") or "").lower()
            risk_to_confidence = {
                "critical": 0.99,
                "high": 0.9,
                "medium": 0.75,
                "low": 0.6,
            }
            confidence_score = risk_to_confidence.get(risk_level, 0.5)

            metadata = {
                **item,
                "classification": classification,
            }

            agents.append(
                {
                    "name": name,
                    "framework": framework,
                    "agent_type": agent_type,
                    "confidence_score": confidence_score,
                    "metadata": metadata,
                }
            )

    return agents


def upload_scan_results(
    scan_results: Dict[str, Any],
    hostname: str,
    api_key: Optional[str] = None,
    tenant_token: Optional[str] = None,
    wawsdb_url: str = _DEFAULT_WAWSDB_URL,
) -> bool:
    """
    Upload scan results to DefendAI platform.

    Credential resolution:
    - CLI arguments (api_key, tenant_token, wawsdb_url)
    - ~/.defendai/config
    - Built-in sandbox defaults

    Never raises; returns True on success, False otherwise.
    """
    # httpx is optional; if missing, just log and return with failure message
    if httpx is None:  # type: ignore[truthy-function]
        reason = "httpx not installed"
        logger.warning("httpx not available; skipping DefendAI platform upload.")
        print(f"⚠️ Platform upload failed: {reason} (scan still succeeded)")
        return False

    # Resolve credentials
    source = "sandbox"
    resolved_api_key = api_key
    resolved_tenant_token = tenant_token
    resolved_wawsdb_url = wawsdb_url or _DEFAULT_WAWSDB_URL

    if resolved_api_key and resolved_tenant_token:
        source = "cli"
    else:
        cfg = load_credentials()
        if cfg:
            # Only override from config when CLI values are missing
            if not resolved_api_key:
                resolved_api_key = cfg.get("api_key")
            if not resolved_tenant_token:
                resolved_tenant_token = cfg.get("tenant_token")
            resolved_wawsdb_url = cfg.get("wawsdb_url") or resolved_wawsdb_url
            if resolved_api_key and resolved_tenant_token:
                source = "config"

    if not resolved_api_key or not resolved_tenant_token:
        # Fall back to sandbox defaults
        resolved_api_key = _SANDBOX_API_KEY
        resolved_tenant_token = _SANDBOX_TENANT_TOKEN
        resolved_wawsdb_url = resolved_wawsdb_url or _DEFAULT_WAWSDB_URL
        source = "sandbox"

    # Announce which credential source is used
    if source == "cli":
        print("✓ Uploading to DefendAI platform...")
    elif source == "config":
        print("✓ Uploading to DefendAI platform (from ~/.defendai/config)...")
    else:
        print("💡 No credentials provided — uploading to DefendAI sandbox for preview")

    agents = format_agents_for_upload(scan_results)
    if not agents:
        # Nothing to upload; treat as success from the caller's perspective
        return True

    scan_id = str(uuid4())
    url = f"{resolved_wawsdb_url.rstrip('/')}/scanner/ingest"

    scanner_context = {
        "hostname": hostname,
        "username": getpass.getuser(),
        "os": f"{_platform.system()} {_platform.release()}",
        "os_version": _platform.version(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "scanner_version": _metadata.version("agent-discover-scanner"),
    }

    payload = {
        "hostname": hostname,
        "scan_id": scan_id,
        "agents": agents,
        "scanner_context": scanner_context,
    }

    headers = {
        "X-DefendAI-Tenant-Token": resolved_tenant_token,
        "Authorization": f"Bearer {resolved_api_key}",
    }

    try:
        with httpx.Client(timeout=30.0, verify=certifi.where()) as client:  # type: ignore[call-arg]
            response = client.post(url, json=payload, headers=headers)

        if 200 <= response.status_code < 300:
            print(f"✓ Results uploaded (scan_id: {scan_id})")
            return True

        reason = f"HTTP {response.status_code}"
        logger.warning(
            "DefendAI platform upload failed with status %s: %s",
            response.status_code,
            response.text,
        )
        print(f"⚠️ Platform upload failed: {reason} (scan still succeeded)")
        return False
    except Exception as exc:  # pragma: no cover - network failures are non-deterministic
        reason = str(exc) or exc.__class__.__name__
        logger.warning("DefendAI platform upload error: %s", exc, exc_info=True)
        print(f"⚠️ Platform upload failed: {reason} (scan still succeeded)")
        return False

