import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

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


def upload_scan_results(scan_results: Dict[str, Any], hostname: str) -> bool:
    """
    Upload scan results to DefendAI platform.

    Never raises; returns True on success, False otherwise.
    """
    # httpx is optional; if missing, just log and return
    if httpx is None:  # type: ignore[truthy-function]
        logger.warning("httpx not available; skipping DefendAI platform upload.")
        return False

    creds = load_credentials()
    if not creds:
        print(
            "💡 Connect to DefendAI platform: add api_key, tenant_token, "
            "wawsdb_url to ~/.defendai/config to enable automatic upload"
        )
        return False

    agents = format_agents_for_upload(scan_results)
    if not agents:
        # Nothing to upload; treat as success from the caller's perspective
        return True

    scan_id = str(uuid4())
    url = f"{creds['wawsdb_url'].rstrip('/')}/scanner/ingest"

    payload = {
        "hostname": hostname,
        "scan_id": scan_id,
        "agents": agents,
    }

    headers = {
        "X-DefendAI-Tenant-Token": creds["tenant_token"],
        "Authorization": f"Bearer {creds['api_key']}",
    }

    try:
        with httpx.Client(timeout=5.0) as client:  # type: ignore[call-arg]
            response = client.post(url, json=payload, headers=headers)

        if 200 <= response.status_code < 300:
            print(f"✓ Results uploaded to DefendAI platform (scan_id: {scan_id})")
            return True

        logger.warning(
            "DefendAI platform upload failed with status %s: %s",
            response.status_code,
            response.text,
        )
        return False
    except Exception as exc:
        logger.warning("DefendAI platform upload error: %s", exc, exc_info=True)
        return False

