"""
Correlation Engine: Match code findings with network activity.

Creates unified agent inventory and detects Ghost Agents.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Known LLM API hostnames for inferring provider from remote_address (Layer 4)
LLM_HOSTNAME_TO_PROVIDER: List[Tuple[str, str]] = [
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("api.groq.com", "groq"),
    ("api.deepseek.com", "deepseek"),
    ("api.perplexity.ai", "perplexity"),
    ("generativelanguage.googleapis.com", "google"),
    ("api.cohere.com", "cohere"),
    ("api.mistral.ai", "mistral"),
    ("api.together.xyz", "together"),
    ("api.huggingface.co", "huggingface"),
    ("ollama", "ollama"),
]


@dataclass
class AgentInventoryItem:
    """Unified agent inventory entry."""

    agent_id: str
    classification: str  # "confirmed", "zombie", "ghost", "unknown"
    risk_level: str  # "critical", "high", "medium", "low"

    # Code-based attributes
    code_file: Optional[str] = None
    framework: Optional[str] = None
    rule_id: Optional[str] = None
    has_code_execution: bool = False

    # Network-based attributes
    network_provider: Optional[str] = None
    last_seen: Optional[str] = None
    process_name: Optional[str] = None

    # Endpoint (Layer 4) attributes
    endpoint_process: Optional[str] = None
    endpoint_pid: Optional[int] = None
    endpoint_local_port: Optional[int] = None

    # Kubernetes (Layer 3) attributes
    k8s_pod: Optional[str] = None
    k8s_namespace: Optional[str] = None
    k8s_workload: Optional[str] = None

    # Which layers detected this agent (e.g. ["layer1", "layer2", "layer4"])
    detection_layers: Optional[List[str]] = None

    # Metadata
    discovered_at: Optional[str] = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now().isoformat()
        if self.detection_layers is None:
            self.detection_layers = []

    def to_dict(self) -> dict:
        return asdict(self)


class CorrelationEngine:
    """
    Correlates code findings with network findings to create unified inventory.

    Classification Logic:
    - CONFIRMED: Found in code AND active network traffic
    - ZOMBIE: Found in code but NO network traffic (deprecated/unused)
    - GHOST: Network traffic but NOT found in code (CRITICAL - unmanaged)
    - UNKNOWN: Found in code, not yet seen in network (not deployed yet)
    """

    @classmethod
    def load_code_findings(cls, sarif_path: Path) -> List[Dict]:
        """Load code scan findings from SARIF file."""
        if not sarif_path.exists():
            return []

        try:
            with open(sarif_path, "r") as f:
                sarif = json.load(f)

            findings = []
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    findings.append(
                        {
                            "rule_id": result.get("ruleId"),
                            "file_path": result["locations"][0]["physicalLocation"][
                                "artifactLocation"
                            ]["uri"],
                            "line": result["locations"][0]["physicalLocation"]["region"][
                                "startLine"
                            ],
                            "message": result["message"]["text"],
                            "level": result.get("level", "warning"),
                        }
                    )

            return findings
        except (json.JSONDecodeError, KeyError):
            return []

    @classmethod
    def load_network_findings(cls, network_path: Path) -> List[Dict]:
        """Load network monitoring findings from JSON file."""
        if not network_path.exists():
            return []

        try:
            with open(network_path, "r") as f:
                data = json.load(f)

            return data.get("findings", [])
        except (json.JSONDecodeError, KeyError):
            return []

    @classmethod
    def _infer_provider_from_address(cls, remote_address: str) -> Optional[str]:
        """Infer LLM provider from remote hostname/address."""
        if not remote_address:
            return None
        addr_lower = remote_address.lower()
        for hostname, provider in LLM_HOSTNAME_TO_PROVIDER:
            if hostname in addr_lower:
                return provider
        return None

    @classmethod
    def load_layer4_findings(cls, layer4_path: Path) -> List[Dict]:
        """
        Read osquery JSON output; return list of dicts with process_name, pid,
        remote_address, provider (inferred from remote_address against known LLM hostnames).
        """
        if not layer4_path.exists():
            return []

        try:
            with open(layer4_path, "r") as f:
                data = json.load(f)

            # Osquery can output {"data": [{"name": "...", "pid": ..., ...}]} or list of rows
            rows = data.get("data", data) if isinstance(data, dict) else data
            if not isinstance(rows, list):
                return []

            results = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                # Support common osquery column names
                process_name = (
                    row.get("process_name")
                    or row.get("name")
                    or row.get("process")
                    or ""
                )
                pid = row.get("pid")
                if pid is not None and not isinstance(pid, int):
                    try:
                        pid = int(pid)
                    except (TypeError, ValueError):
                        pid = None
                remote_address = (
                    row.get("remote_address")
                    or row.get("remote_addr")
                    or row.get("destination")
                    or row.get("dest_address")
                    or ""
                )
                if isinstance(remote_address, int):
                    remote_address = str(remote_address)
                provider = cls._infer_provider_from_address(remote_address)
                if provider is None:
                    continue
                local_port = row.get("local_port")
                if local_port is not None and not isinstance(local_port, int):
                    try:
                        local_port = int(local_port)
                    except (TypeError, ValueError):
                        local_port = None
                results.append(
                    {
                        "process_name": process_name,
                        "pid": pid,
                        "remote_address": remote_address,
                        "provider": provider,
                        "local_port": local_port,
                    }
                )
            return results
        except (json.JSONDecodeError, KeyError):
            return []

    @classmethod
    def load_layer3_findings(cls, layer3_path: Path) -> List[Dict]:
        """
        Read Tetragon/monitor-k8s JSONL output; return list of dicts with
        pod, namespace, workload, provider, timestamp.
        """
        if not layer3_path.exists():
            return []

        results = []
        try:
            with open(layer3_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Tetragon process/connect events: nested process, processK8s, etc.
                    process = obj.get("process", {}) or {}
                    process_k8s = process.get("pod", {}) or obj.get("processK8s", {}) or {}
                    pod = namespace = workload = ""
                    if isinstance(process_k8s, dict):
                        pod = process_k8s.get("pod") or process_k8s.get("name") or ""
                        namespace = process_k8s.get("namespace") or ""
                        workload = process_k8s.get("workload") or ""
                        if not workload and isinstance(process_k8s.get("container"), dict):
                            workload = process_k8s["container"].get("name") or ""

                    # Prefer top-level if present
                    pod = obj.get("pod") or pod
                    namespace = obj.get("namespace") or namespace
                    workload = obj.get("workload") or workload

                    # Infer provider from destination/URL in event if available
                    dest = obj.get("destination") or obj.get("remote_address") or obj.get("url") or ""
                    if isinstance(dest, dict):
                        dest = dest.get("address") or dest.get("host") or ""
                    provider = obj.get("provider") or cls._infer_provider_from_address(str(dest))

                    timestamp = obj.get("time") or obj.get("timestamp") or process.get("start_time")

                    results.append(
                        {
                            "pod": pod,
                            "namespace": namespace,
                            "workload": workload,
                            "provider": provider or "unknown",
                            "timestamp": timestamp,
                        }
                    )
        except OSError:
            return []

        return results

    @classmethod
    def extract_framework_from_rule(cls, rule_id: str) -> str:
        """Map rule ID to framework name."""
        mapping = {
            "DAI001": "AutoGen",
            "DAI002": "CrewAI",
            "DAI003": "LangChain/LangGraph",
            "DAI004": "Shadow AI",
            "DAI005": "Direct HTTP LLM Client",
            "DAI006": "LLM API Endpoint",
        }
        return mapping.get(rule_id, "Unknown")

    _PROVIDERS = frozenset(
        {
            "openai",
            "anthropic",
            "groq",
            "deepseek",
            "perplexity",
            "google",
            "huggingface",
            "ollama",
            "cohere",
            "mistral",
            "together",
        }
    )

    @classmethod
    def _code_finding_providers(cls, cf: Dict) -> List[str]:
        """Return list of provider names that may match this code finding."""
        message = (cf.get("message") or "").lower()
        framework = (cls.extract_framework_from_rule(cf.get("rule_id") or "")).lower()
        candidates = []
        for p in cls._PROVIDERS:
            if p in framework or p in message:
                candidates.append(p)
        if not candidates:
            if "openai" in message or "openai" in framework:
                candidates.append("openai")
            if "anthropic" in message or "anthropic" in framework:
                candidates.append("anthropic")
        if not candidates:
            return list(cls._PROVIDERS)
        return candidates

    @classmethod
    def _escalate_risk(cls, risk: str) -> str:
        """Escalate risk by one level (e.g. for Layer 3 runtime detection)."""
        order = ("low", "medium", "high", "critical")
        try:
            i = order.index(risk)
            return order[min(i + 1, len(order) - 1)]
        except ValueError:
            return risk

    @classmethod
    def correlate(
        cls,
        code_findings: List[Dict],
        network_findings: List[Dict],
        layer4_findings: Optional[List[Dict]] = None,
        layer3_findings: Optional[List[Dict]] = None,
    ) -> Dict[str, List[AgentInventoryItem]]:
        """
        Correlate code and network/layer3/layer4 findings.

        A finding is CONFIRMED if it appears in code (Layer 1) + any of Layer 2/3/4.
        Populates detection_layers, k8s fields from Layer 3, endpoint fields from Layer 4.
        Risk is escalated by one level if detected in Layer 3 (runtime eBPF).

        Returns:
            Dictionary with classifications: confirmed, zombie, ghost, unknown
        """
        inventory = {"confirmed": [], "zombie": [], "ghost": [], "unknown": []}
        layer4_findings = layer4_findings or []
        layer3_findings = layer3_findings or []

        # Layer 2: active providers from network_findings
        active_providers = {}
        for nf in network_findings:
            provider = (nf.get("provider") or "unknown").lower()
            if provider in cls._PROVIDERS or provider != "unknown":
                active_providers[provider] = {
                    "process": nf.get("process_name", "unknown"),
                    "timestamp": nf.get("timestamp"),
                }

        # Index Layer 3 by provider (first match per provider for filling k8s fields)
        layer3_by_provider: Dict[str, Dict] = {}
        for l3 in layer3_findings:
            p = (l3.get("provider") or "unknown").lower()
            if p not in layer3_by_provider and (p in cls._PROVIDERS or p != "unknown"):
                layer3_by_provider[p] = l3

        # Index Layer 4 by provider (first match per provider for filling endpoint fields)
        layer4_by_provider: Dict[str, Dict] = {}
        for l4 in layer4_findings:
            p = (l4.get("provider") or "unknown").lower()
            if p not in layer4_by_provider and (p in cls._PROVIDERS or p != "unknown"):
                layer4_by_provider[p] = l4

        # Process code findings (Layer 1)
        for cf in code_findings:
            agent_id = f"{cf['file_path']}:{cf['line']}"
            framework = cls.extract_framework_from_rule(cf["rule_id"])

            has_code_exec = "CODE EXECUTION" in (cf.get("message") or "") or "HIGH RISK" in (cf.get("message") or "")
            is_shadow_ai = cf["rule_id"] == "DAI004"

            if has_code_exec or is_shadow_ai:
                risk = "critical" if is_shadow_ai else "high"
            else:
                risk = "medium"

            detection_layers = ["layer1"]
            match_provider = None

            possible = cls._code_finding_providers(cf)

            if network_findings:
                for p in possible:
                    if p in active_providers:
                        match_provider = p
                        detection_layers.append("layer2")
                        break

            if layer3_findings and not any(l.startswith("layer3") for l in detection_layers):
                for p in possible:
                    if p in layer3_by_provider:
                        match_provider = match_provider or p
                        if "layer3" not in detection_layers:
                            detection_layers.append("layer3")
                        break

            if layer4_findings and "layer4" not in detection_layers:
                for p in possible:
                    if p in layer4_by_provider:
                        match_provider = match_provider or p
                        detection_layers.append("layer4")
                        break

            confirmed = len(detection_layers) > 1
            if confirmed:
                if "layer3" in detection_layers:
                    risk = cls._escalate_risk(risk)
            else:
                match_provider = None

            k8s_pod = k8s_namespace = k8s_workload = None
            endpoint_process = endpoint_pid = endpoint_local_port = None
            network_provider = None
            last_seen = None
            process_name = None

            if match_provider:
                if match_provider in active_providers:
                    info = active_providers[match_provider]
                    last_seen = info.get("timestamp")
                    process_name = info.get("process")
                network_provider = match_provider
                if match_provider in layer3_by_provider:
                    l3 = layer3_by_provider[match_provider]
                    k8s_pod = l3.get("pod")
                    k8s_namespace = l3.get("namespace")
                    k8s_workload = l3.get("workload")
                    if last_seen is None:
                        last_seen = l3.get("timestamp")
                if match_provider in layer4_by_provider:
                    l4 = layer4_by_provider[match_provider]
                    endpoint_process = l4.get("process_name")
                    endpoint_pid = l4.get("pid")
                    endpoint_local_port = l4.get("local_port")
                    if last_seen is None:
                        last_seen = l4.get("timestamp")  # if layer4 had timestamp
                    if process_name is None:
                        process_name = endpoint_process

            classification = "confirmed" if confirmed else "unknown"
            item = AgentInventoryItem(
                agent_id=agent_id,
                classification=classification,
                risk_level=risk,
                code_file=cf["file_path"],
                framework=framework,
                rule_id=cf["rule_id"],
                has_code_execution=has_code_exec,
                network_provider=network_provider,
                last_seen=last_seen,
                process_name=process_name,
                endpoint_process=endpoint_process,
                endpoint_pid=endpoint_pid,
                endpoint_local_port=endpoint_local_port,
                k8s_pod=k8s_pod,
                k8s_namespace=k8s_namespace,
                k8s_workload=k8s_workload,
                detection_layers=detection_layers,
            )
            inventory[classification].append(item)

        # GHOST AGENTS: Layer 2/3/4 activity with no code finding
        seen_providers = {item.network_provider for item in inventory["confirmed"] if item.network_provider}
        for provider, info in active_providers.items():
            if provider in seen_providers:
                continue
            seen_providers.add(provider)
            ghost_id = f"ghost:{provider}:{info.get('process', '')}"
            inventory["ghost"].append(
                AgentInventoryItem(
                    agent_id=ghost_id,
                    classification="ghost",
                    risk_level="critical",
                    network_provider=provider,
                    last_seen=info.get("timestamp"),
                    process_name=info.get("process"),
                    detection_layers=["layer2"],
                )
            )

        for provider, l3 in layer3_by_provider.items():
            if provider in seen_providers:
                continue
            seen_providers.add(provider)
            ghost_id = f"ghost:{provider}:{l3.get('pod', '')}"
            inventory["ghost"].append(
                AgentInventoryItem(
                    agent_id=ghost_id,
                    classification="ghost",
                    risk_level="critical",
                    network_provider=provider,
                    last_seen=l3.get("timestamp"),
                    k8s_pod=l3.get("pod"),
                    k8s_namespace=l3.get("namespace"),
                    k8s_workload=l3.get("workload"),
                    detection_layers=["layer3"],
                )
            )

        for provider, l4 in layer4_by_provider.items():
            if provider in seen_providers:
                continue
            seen_providers.add(provider)
            ghost_id = f"ghost:{provider}:{l4.get('process_name', '')}"
            inventory["ghost"].append(
                AgentInventoryItem(
                    agent_id=ghost_id,
                    classification="ghost",
                    risk_level="critical",
                    network_provider=provider,
                    process_name=l4.get("process_name"),
                    endpoint_process=l4.get("process_name"),
                    endpoint_pid=l4.get("pid"),
                    endpoint_local_port=l4.get("local_port"),
                    detection_layers=["layer4"],
                )
            )

        return inventory

    @classmethod
    def generate_report(
        cls, inventory: Dict[str, List[AgentInventoryItem]], output_path: Optional[Path] = None
    ) -> Dict:
        """
        Generate correlation report with statistics.

        Returns:
            Report dictionary with metrics and inventory
        """
        all_items = [item for items in inventory.values() for item in items]
        detection_coverage: Dict[str, int] = {}
        for item in all_items:
            layers = getattr(item, "detection_layers", None) or []
            key = ",".join(sorted(layers)) if layers else "none"
            detection_coverage[key] = detection_coverage.get(key, 0) + 1

        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_agents": sum(len(items) for items in inventory.values()),
                "confirmed": len(inventory["confirmed"]),
                "unknown": len(inventory["unknown"]),
                "zombie": len(inventory["zombie"]),
                "ghost": len(inventory["ghost"]),
                "detection_coverage": detection_coverage,
            },
            "risk_breakdown": {
                "critical": sum(1 for item in all_items if item.risk_level == "critical"),
                "high": sum(1 for item in all_items if item.risk_level == "high"),
                "medium": sum(1 for item in all_items if item.risk_level == "medium"),
                "low": sum(1 for item in all_items if item.risk_level == "low"),
            },
            "inventory": {
                classification: [item.to_dict() for item in items]
                for classification, items in inventory.items()
            },
        }

        # Save to file if requested
        if output_path:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)

        return report

    @classmethod
    def analyze_behaviors(cls, network_findings: List[Dict]) -> Dict:
        """
        Analyze network findings for behavioral patterns.

        Returns:
            Dictionary with detected behavioral patterns
        """
        from agent_discover_scanner.behavioral_patterns import BehavioralAnalyzer

        patterns = BehavioralAnalyzer.analyze_all_patterns(network_findings)

        # Count patterns
        summary = {
            "total_patterns": sum(len(p) for p in patterns.values()),
            "react_loops": len(patterns["react_loops"]),
            "rag_patterns": len(patterns["rag_patterns"]),
            "multi_turn": len(patterns["multi_turn"]),
            "token_bursts": len(patterns["token_bursts"]),
        }

        return {
            "summary": summary,
            "patterns": {
                pattern_type: [
                    {
                        "type": p.pattern_type,
                        "confidence": p.confidence,
                        "description": p.description,
                        "indicators": p.indicators,
                        "timestamp": p.timestamp,
                        "metadata": p.metadata,
                    }
                    for p in pattern_list
                ]
                for pattern_type, pattern_list in patterns.items()
            },
        }
