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

from agent_discover_scanner.saas_detector import build_saas_connections

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

# Mapping from correlator.py classification keys → wawsdb agent_class vocabulary.
# The server drives final classification (ROGUE, lifecycle, etc.); this is a scanner hint.
# SHADOW is the catch-all for anything not yet confirmed at runtime.
_AGENT_CLASS_MAP: dict[str, str] = {
    "confirmed": "CONFIRMED",
    "ghost": "GHOST",
    "zombie": "ZOMBIE",
    "unknown": "SHADOW",        # found in code, not yet observed at runtime
    "shadow_ai_usage": "SHADOW",  # consumer/governance — shadow class
}


def build_cloud_audit_summary(findings: list[Any]) -> dict[str, Any]:
    """
    Aggregate raw Layer 5 Cloud Audit findings into a structured analytics block.

    Returns an empty dict when findings is empty so callers can skip the payload key.
    The ``findings`` list is embedded as-is to avoid a second read at the call site.
    """
    if not findings:
        return {}
    providers: list[str] = sorted({(f.get("provider") or "unknown") for f in findings})
    models_used: list[str] = sorted({
        f.get("model_id") for f in findings if f.get("model_id")
    })
    iam_users: list[str] = sorted({
        f.get("username") for f in findings if f.get("username")
    })
    event_types: dict[str, int] = {}
    for f in findings:
        et = f.get("event_name") or "Unknown"
        event_types[et] = event_types.get(et, 0) + 1
    return {
        "total_invocations": len(findings),
        "providers": providers,
        "models_used": models_used,
        "iam_users": iam_users,
        "event_types": event_types,
        "findings": findings,
    }


def build_network_summary(network_findings: list[Any]) -> dict[str, Any]:
    """
    Aggregate Layer 2 (psutil) network findings into a structured analytics block.

    Filters out Layer 5 cloud-audit and SSE-proxy findings that may have been merged
    into the network_findings list before this call.  Returns {} when no pure-L2
    data is present.
    """
    _l5_layers = {"layer5_cloud_audit", "layer5_sse_proxy"}
    l2_only = [
        f for f in (network_findings or [])
        if f.get("detection_layer") not in _l5_layers
    ]
    if not l2_only:
        return {}
    services_detected: list[str] = sorted({
        f.get("service") or f.get("provider") or "unknown"
        for f in l2_only
        if f.get("service") or f.get("provider")
    })
    processes: dict[str, int] = {}
    for f in l2_only:
        pn = f.get("process_name") or f.get("process") or ""
        if pn:
            processes[pn] = processes.get(pn, 0) + 1
    return {
        "total_connections": len(l2_only),
        "services_detected": services_detected,
        "processes": processes,
        "findings": l2_only,
    }


def _build_evidence_tags(item: dict[str, Any]) -> list[str]:
    """
    Return the ordered list of evidence-source tags for an agent record.

    If the correlator already populated ``evidence`` (v2.9.0+), return it
    directly.  Otherwise derive tags from ``detection_layers`` + available
    enrichment fields so older inventory records still get meaningful tags.

    Tags (stable wawsdb vocabulary):
      layer1_code_scan             — AST code scan (L1)
      layer2_network               — live psutil connection (L2)
      layer2_process_introspection — framework found via L2 entry-script introspection
      layer2_dns_host              — LLM hostname recovered via ForwardDNSCache
      layer3_k8s_runtime           — Kubernetes / Tetragon eBPF (L3)
      layer4_endpoint              — osquery endpoint discovery (L4)
      layer5_cloudtrail            — AWS CloudTrail Bedrock invocation (L5)
      layer5_sse_proxy             — SSE / CASB proxy LLM traffic (L5)
    """
    # Prefer pre-built tags emitted by the correlator
    prebuilt: list[str] = list(item.get("evidence") or [])
    if prebuilt:
        return prebuilt

    # Fallback derivation for older inventory records
    tags: list[str] = []
    detection_layers: list[str] = item.get("detection_layers") or []
    if "layer1" in detection_layers:
        tags.append("layer1_code_scan")
    if "layer2" in detection_layers:
        tags.append("layer2_network")
        if item.get("entry_script") or item.get("framework_confidence"):
            tags.append("layer2_process_introspection")
        if item.get("detected_hosts"):
            tags.append("layer2_dns_host")
    if "layer3" in detection_layers:
        tags.append("layer3_k8s_runtime")
    if "layer4" in detection_layers:
        tags.append("layer4_endpoint")
    if "layer5" in detection_layers:
        tags.append("layer5_cloudtrail")
    if "layer5_sse" in detection_layers:
        tags.append("layer5_sse_proxy")
    return tags


def _l5_events_for_agent(item: dict[str, Any], cloud_audit_findings: list[Any]) -> list[Any]:
    """
    Return the subset of cloud-audit findings attributable to this agent.

    Matching precedence:
    1. Exact IAM principal match on caller_identity / username
    2. Provider match (bedrock → all bedrock findings)

    Returns [] when no findings can be attributed.
    """
    if not cloud_audit_findings:
        return []
    # Exact IAM principal match — most precise attribution
    caller = (item.get("caller_identity") or "").strip()
    if caller:
        exact = [f for f in cloud_audit_findings if (f.get("username") or "").strip() == caller]
        if exact:
            return exact
    # Provider-level match (fallback)
    provider = (item.get("network_provider") or "").lower()
    if provider:
        return [f for f in cloud_audit_findings if (f.get("provider") or "").lower() == provider]
    return []


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


def format_agents_for_upload(
    scan_results: Dict[str, Any],
    network_findings: Optional[List[Any]] = None,
    layer4_findings: Optional[List[Any]] = None,
    mcp_result: Optional[Dict[str, Any]] = None,
    cloud_audit_findings: list[Any] | None = None,
) -> List[Dict[str, Any]]:
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
                "shadow_ai_usage": [...],
            },
        }
    """
    inventory = scan_results.get("inventory") or {}
    if not isinstance(inventory, dict):
        return []

    # Machine context once per run (platform uses for cross-machine correlation)
    _hostname = socket.gethostname()
    _username = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
    _os = _platform.system()

    agents: List[Dict[str, Any]] = []

    for classification, items in inventory.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue

            # Noise filter: skip tests, fixtures, scanner internals, and dependency dirs
            code_file_val = str(item.get("code_file") or "")
            agent_id_val = str(item.get("agent_id") or "")
            combined_path = f"{code_file_val} {agent_id_val}".lower()
            if any(
                pattern in combined_path
                for pattern in (
                    "tests/",
                    "fixtures/",
                    "test_",
                    "agent_discover_scanner/",
                    "node_modules/",
                    "site-packages/",
                    ".venv/",
                )
            ):
                continue

            saas_connections = (
                getattr(item, "saas_connections", None)
                or item.get("saas_connections")
                or {}
            )
            file_path_for_saas = code_file_val or (
                agent_id_val.rsplit(":", 1)[0] if ":" in agent_id_val else ""
            )
            if not saas_connections and file_path_for_saas:
                try:
                    file_path_for_saas = os.path.abspath(file_path_for_saas)
                    search_dir = os.path.dirname(file_path_for_saas) or os.getcwd()
                    agent_fw = item.get("framework") or item.get("network_provider") or ""
                    agent_proc = item.get("process_name") or ""
                    saas_connections = build_saas_connections(
                        file_path=file_path_for_saas,
                        search_dir=search_dir,
                        network_findings=network_findings,
                        layer4_findings=layer4_findings,
                        agent_framework=agent_fw or None,
                        agent_process_name=agent_proc or None,
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "saas_detector failed for %s: %s",
                        file_path_for_saas,
                        exc,
                    )
                    saas_connections = {}

            # Derive a human-friendly name with sensible fallbacks.
            # caller_identity is tried before the agent_id fallback so that L5-only GHOST
            # agents (where process_name=None) get an IAM ARN / email as their name rather
            # than the raw "ghost:bedrock:cloudtrail:…" agent_id string.
            name: str
            if item.get("k8s_workload"):
                name = str(item["k8s_workload"])
            elif item.get("k8s_pod"):
                name = str(item["k8s_pod"])
            elif item.get("process_name"):
                name = str(item["process_name"])
            elif item.get("caller_identity"):
                name = str(item["caller_identity"])
            else:
                # Fallback to code_file or agent_id with cleanup
                raw = code_file_val or agent_id_val
                if raw:
                    # Strip :NNN suffix if present
                    parts = raw.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        raw_path = parts[0]
                    else:
                        raw_path = raw
                    base = os.path.basename(raw_path)
                    name = os.path.splitext(base)[0] or base or "unknown-agent"
                else:
                    name = "unknown-agent"

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
                # agent_class uses the wawsdb contract vocabulary (CONFIRMED / GHOST /
                # ZOMBIE / SHADOW).  The server drives the final classification; this
                # is the scanner's hint based on what was observed during the scan.
                "agent_class": _AGENT_CLASS_MAP.get(classification, "SHADOW"),
                "hostname": _hostname,
                "username": _username,
                "os": _os,
            }
            if saas_connections:
                metadata["saas_connections"] = saas_connections

            try:
                if mcp_result and mcp_result.get("servers"):
                    metadata["mcp_connections"] = mcp_result
                    mcp_saas = mcp_result.get("saas_via_mcp", [])
                    if mcp_saas:
                        existing = list(saas_connections.get("detected", []))
                        for s in mcp_saas:
                            if s not in existing:
                                existing.append(s)
                        if isinstance(saas_connections, dict):
                            saas_connections = {**saas_connections, "detected": existing}
                            metadata["saas_connections"] = saas_connections
            except Exception:
                pass

            # Task 3 — per-agent Layer 5 enrichment.
            # Matches cloud-audit events to this agent (by IAM principal or provider)
            # and adds aggregate stats that power dashboard stat cards.
            # Task 4 — credential evidence: IAM users are added to credential_files_found
            # so the "Credential exposure" card shows real numbers instead of 0.
            try:
                l5_for_agent = _l5_events_for_agent(item, cloud_audit_findings or [])
                if l5_for_agent:
                    models_called = sorted({
                        f.get("model_id") for f in l5_for_agent if f.get("model_id")
                    })
                    l5_iam_users = sorted({
                        f.get("username") for f in l5_for_agent if f.get("username")
                    })
                    ts_list = [f.get("timestamp") for f in l5_for_agent if f.get("timestamp")]
                    last_invocation = max(ts_list) if ts_list else None
                    metadata["bedrock_invocations"] = len(l5_for_agent)
                    metadata["models_called"] = models_called
                    metadata["iam_users"] = l5_iam_users
                    if last_invocation:
                        metadata["last_invocation"] = last_invocation
                    # Credential evidence: prefix IAM usernames so they're distinguishable
                    if l5_iam_users:
                        _cur_saas = dict(metadata.get("saas_connections") or {})
                        _cred = list(_cur_saas.get("credential_files_found") or [])
                        for _u in l5_iam_users:
                            _iam_entry = f"IAM:{_u}"
                            if _iam_entry not in _cred:
                                _cred.append(_iam_entry)
                        _cur_saas["credential_files_found"] = _cred
                        metadata["saas_connections"] = _cur_saas
                        saas_connections = _cur_saas
            except Exception:
                pass

            agents.append(
                {
                    "name": name,
                    "framework": framework,
                    "agent_type": agent_type,
                    "confidence_score": confidence_score,
                    "hostname": _hostname,
                    "username": _username,
                    "os": _os,
                    "saas_connections": metadata.get("saas_connections") or {},
                    "mcp_connections": metadata.get("mcp_connections") or {},
                    # L5 enrichment promoted to top-level (server schema v2.8.0)
                    "model_id": item.get("model_id"),
                    "l5_framework": item.get("l5_framework"),
                    "caller_identity": item.get("caller_identity"),
                    "l5_event_count": item.get("l5_event_count") or 0,
                    # L2 enrichment: DNS-correlated hostnames, introspection evidence,
                    # and entry-script path for L1↔L2 agent-identity reconciliation (v2.9.0)
                    "detected_hosts": item.get("detected_hosts") or [],
                    "evidence": _build_evidence_tags(item),
                    "entry_script": item.get("entry_script"),
                    "framework_confidence": item.get("framework_confidence"),
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
    network_findings: Optional[List[Any]] = None,
    layer4_findings: Optional[List[Any]] = None,
    high_risk_agent: Optional[Dict[str, Any]] = None,
    mcp_result: Optional[Dict[str, Any]] = None,
    scan_dir: Optional[str] = None,
    # Signal-enhancement fields (v2.8.0)
    scan_meta: dict[str, Any] | None = None,
    network_interceptors: list[dict[str, Any]] | None = None,
    cloud_audit_findings: list[Any] | None = None,
    sse_proxy_findings: list[Any] | None = None,
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

    # Resolve credentials.
    #
    # tenant_token is OPTIONAL — the API key alone is sufficient to authenticate.
    # When a tenant_token is also provided it is forwarded as X-DefendAI-Tenant-Token
    # for backwards-compatibility with multi-tenant deployments, but it is never
    # required.  This means free-tier users can pass just --api-key and have the
    # upload work without a second credential.
    #
    # Resolution order:
    #   1. CLI arguments (api_key / tenant_token)
    #   2. ~/.defendai/config
    #   3. Built-in sandbox defaults (only when no api_key is found at all)
    source = "sandbox"
    resolved_api_key = api_key
    resolved_tenant_token = tenant_token
    resolved_wawsdb_url = wawsdb_url or _DEFAULT_WAWSDB_URL

    if resolved_api_key:
        # api_key alone is enough; tenant_token is supplemental
        source = "cli"
    else:
        cfg = load_credentials()
        if cfg:
            if not resolved_api_key:
                resolved_api_key = cfg.get("api_key")
            if not resolved_tenant_token:
                resolved_tenant_token = cfg.get("tenant_token")
            resolved_wawsdb_url = cfg.get("wawsdb_url") or resolved_wawsdb_url
            if resolved_api_key:
                source = "config"

    if not resolved_api_key:
        # No api_key found anywhere — fall back to sandbox for preview
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
        print("💡 No API key provided — uploading to DefendAI sandbox for preview")

    if mcp_result is None:
        try:
            from agent_discover_scanner.mcp_detector import detect_mcp_servers
            mcp_result = detect_mcp_servers(
                scan_dir=scan_dir,
                network_findings=network_findings,
                layer4_findings=layer4_findings,
            )
        except Exception:
            mcp_result = {}

    agents = format_agents_for_upload(
        scan_results,
        network_findings=network_findings,
        layer4_findings=layer4_findings,
        mcp_result=mcp_result,
        cloud_audit_findings=cloud_audit_findings,
    )
    # Do NOT early-return when agents=[].  The contract requires an ingest call on every
    # scan so the server receives scan_meta + raw L5 findings even when nothing was found.

    if high_risk_agent is None:
        try:
            from agent_discover_scanner.high_risk_agents import (
                detect_all_high_risk_agents,
            )
            high_risk_agent = detect_all_high_risk_agents(
                layer4_findings=layer4_findings,
                network_findings=network_findings,
            )
        except Exception:
            high_risk_agent = {}

    scan_id = str(uuid4())
    url = f"{resolved_wawsdb_url.rstrip('/')}/scanner/ingest"

    scanner_context = {
        "hostname": hostname,
        "username": getpass.getuser(),
        "os": f"{_platform.system()} {_platform.release()}",
        "os_version": _platform.version(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "scanner_version": _metadata.version("agentdiscover"),
    }

    # Build structured analytics summaries.
    # cloud_audit / network power dashboard stat cards (invocation count, models, etc.)
    _ca_summary = build_cloud_audit_summary(cloud_audit_findings or [])
    _net_summary = build_network_summary(network_findings or [])

    # wawsdb: ScannerAgent (proxy_router.py) should include high_risk_agent: dict = {}
    payload: dict[str, Any] = {
        "hostname": hostname,
        "scan_id": scan_id,
        # git_remote at top-level per contract (also present inside scan_meta)
        "git_remote": (scan_meta or {}).get("git_remote"),
        "agents": agents,
        "scanner_context": scanner_context,
        "high_risk_agent": high_risk_agent or {},
        "mcp_connections": mcp_result or {},
        # Signal-enhancement fields (v2.8.0)
        "scan_meta": scan_meta or {},
        "network_interceptors": network_interceptors or [],
        # Raw L5 event arrays (server-side processing / storage)
        "cloud_audit_findings": cloud_audit_findings or [],
        "sse_proxy_findings": sse_proxy_findings or [],
        # Structured summaries (dashboard stat cards)
        "cloud_audit": _ca_summary,
        "network": _net_summary,
    }

    MAX_UPLOAD_BYTES = 1_000_000  # 1MB
    truncation_applied = False
    browser_history_excluded = False
    try:
        payload_bytes = len(json.dumps(payload).encode("utf-8"))
        if payload_bytes > MAX_UPLOAD_BYTES:
            findings = payload.get("findings")
            if isinstance(findings, dict):
                if findings.pop("browser_history", None) is not None:
                    truncation_applied = True
                    browser_history_excluded = True

            if len(json.dumps(payload).encode("utf-8")) > MAX_UPLOAD_BYTES:
                findings = payload.get("findings")
                if isinstance(findings, dict):
                    for key, value in list(findings.items()):
                        if isinstance(value, list) and len(value) > 50:
                            findings[key] = value[:50]
                            truncation_applied = True
                            if isinstance(findings.get(key), list):
                                findings[f"{key}_truncated"] = True
    except Exception:
        # Keep original payload if size guard fails.
        pass

    if truncation_applied:
        if browser_history_excluded:
            print("⚠️  Large scan result truncated for upload (browser history excluded)")
        else:
            print("⚠️  Large scan result truncated for upload")

    # X-DefendAI-Tenant-Token is included only when a tenant token is available.
    # The Authorization: Bearer header carries the api_key and is always present.
    headers: dict[str, str] = {
        "Authorization": f"Bearer {resolved_api_key}",
    }
    if resolved_tenant_token:
        headers["X-DefendAI-Tenant-Token"] = resolved_tenant_token

    try:
        with httpx.Client(timeout=30.0, verify=certifi.where()) as client:  # type: ignore[call-arg]
            response = client.post(url, json=payload, headers=headers)

        if 200 <= response.status_code < 300:
            # Task 5 — enhanced CLI summary
            print("✓ Platform sync complete")
            print(f"  Agents uploaded:     {len(agents)}")
            if _ca_summary.get("total_invocations"):
                print(f"  Layer 5 events sent: {_ca_summary['total_invocations']}")
            if _ca_summary.get("iam_users"):
                print(f"  IAM users detected:  {len(_ca_summary['iam_users'])}")
            if _ca_summary.get("models_used"):
                print(f"  Models identified:   {len(_ca_summary['models_used'])}")
            if _net_summary.get("total_connections"):
                print(f"  Network connections: {_net_summary['total_connections']}")
            print("  Dashboard: https://discover.defendai.ai/dashboard/agent_inventory")
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

