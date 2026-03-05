"""Kubernetes API-based agent discovery (Layer 3 without eBPF/Tetragon).

Uses the official kubernetes Python client and respects KUBECONFIG
for both out-of-cluster and in-cluster configurations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from rich.console import Console

console = Console()

try:
    # kubernetes client is optional; install via `pip install kubernetes`
    from kubernetes import client, config  # type: ignore[import]
except ImportError:  # pragma: no cover - handled gracefully at runtime
    client = None  # type: ignore[assignment]
    config = None  # type: ignore[assignment]


class K8sAPIMonitor:
    """Discover AI agent workloads via the Kubernetes API."""

    # Simple heuristics for provider inference from env / images / args
    _PROVIDER_KEYWORDS = {
        "openai": "openai",
        "anthropic": "anthropic",
        "gemini": "google",
        "generativelanguage": "google",
        "mistral": "mistral",
        "cohere": "cohere",
        "pinecone": "pinecone",
        "weaviate": "weaviate",
        "qdrant": "qdrant",
        "chromadb": "chroma",
        "chroma": "chroma",
    }

    _FRAMEWORK_KEYWORDS = (
        "langchain",
        "langgraph",
        "crewai",
        "autogen",
    )

    _ENV_PROVIDER_HINTS = {
        "OPENAI": "openai",
        "ANTHROPIC": "anthropic",
        "GEMINI": "google",
        "MISTRAL": "mistral",
        "COHERE": "cohere",
        "PINECONE": "pinecone",
        "WEAVIATE": "weaviate",
        "QDRANT": "qdrant",
        "CHROMA": "chroma",
    }

    def _load_kube_config(self) -> bool:
        """Load kubeconfig, respecting KUBECONFIG, with in-cluster fallback."""
        if config is None:
            return False
        # Try local kubeconfig first (respects KUBECONFIG)
        try:
            config.load_kube_config()
            return True
        except Exception:
            pass
        # Fallback to in-cluster config
        try:
            config.load_incluster_config()
            return True
        except Exception:
            return False

    def _infer_provider_from_text(self, text: str) -> Optional[str]:
        text_low = text.lower()
        for key, provider in self._PROVIDER_KEYWORDS.items():
            if key in text_low:
                return provider
        return None

    def _infer_provider_from_env(self, env_list) -> Optional[str]:
        if not env_list:
            return None
        for env_var in env_list:
            name = getattr(env_var, "name", None)
            if not name:
                continue
            for key, provider in self._ENV_PROVIDER_HINTS.items():
                if key in name.upper():
                    return provider
        return None

    def _analyze_workload(self, workload) -> List[Dict]:
        """Return normalized Layer 3 findings for a single workload object."""
        results: List[Dict] = []

        meta = getattr(workload, "metadata", None)
        spec = getattr(workload, "spec", None)
        if not meta or not spec:
            return results

        workload_name = getattr(meta, "name", None) or ""
        namespace = getattr(meta, "namespace", None) or "default"
        tpl = getattr(spec, "template", None)
        pod_spec = getattr(tpl, "spec", None) if tpl else None
        containers = getattr(pod_spec, "containers", None) if pod_spec else None
        if not workload_name or not containers:
            return results

        for container in containers:
            image = getattr(container, "image", "") or ""
            command = getattr(container, "command", None) or []
            args = getattr(container, "args", None) or []
            env_list = getattr(container, "env", None) or []

            text_blobs = [
                image,
                " ".join(command),
                " ".join(args),
            ]
            combined_text = " ".join(text_blobs)

            provider = self._infer_provider_from_env(env_list) or self._infer_provider_from_text(
                combined_text
            )

            has_framework = any(
                fw in combined_text.lower() or any(fw in (getattr(e, "name", "") or "").lower() for e in env_list)
                for fw in self._FRAMEWORK_KEYWORDS
            )

            # Only record workloads that look AI-related (provider or framework hints)
            if not provider and not has_framework:
                continue

            # Normalize into the shape expected by CorrelationEngine.load_layer3_findings
            timestamp = datetime.now().isoformat()
            results.append(
                {
                    "pod": workload_name,  # best-effort; real pods will be derived by correlator
                    "namespace": namespace,
                    "workload": workload_name,
                    "provider": provider or "unknown",
                    "timestamp": timestamp,
                }
            )

        return results

    def discover_agents(self) -> List[Dict]:
        """Discover AI agent workloads using the Kubernetes API."""
        if client is None or config is None:
            console.print(
                "[yellow]kubernetes Python client not installed; "
                "skipping Kubernetes API discovery (Layer 3 base path).[/yellow]"
            )
            return []

        if not self._load_kube_config():
            console.print(
                "[yellow]Could not load Kubernetes config (KUBECONFIG / in-cluster); "
                "skipping Kubernetes API discovery.[/yellow]"
            )
            return []

        api = client.AppsV1Api()
        findings: List[Dict] = []

        try:
            deployments = api.list_deployment_for_all_namespaces().items
        except Exception:
            deployments = []
        try:
            statefulsets = api.list_stateful_set_for_all_namespaces().items
        except Exception:
            statefulsets = []
        try:
            daemonsets = api.list_daemon_set_for_all_namespaces().items
        except Exception:
            daemonsets = []

        for workload in deployments + statefulsets + daemonsets:
            findings.extend(self._analyze_workload(workload))

        return findings

