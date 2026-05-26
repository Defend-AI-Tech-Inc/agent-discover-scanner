"""
Abstract base class and shared fallback strategies for SSE network proxy detection.

All SSE vendor plugins inherit fallback_strategies and the shared detection
implementations from this base. Each vendor only defines its own vendor name,
process_names, and env_var_patterns.
"""

from __future__ import annotations

import os
import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class InterceptorResult:
    """Result from detecting a network interceptor (SSE proxy)."""

    vendor: str
    confidence: str  # "high" | "medium" | "low"
    evidence: list[str]
    fallback_strategy: str  # best available strategy for Bedrock detection through this proxy


class NetworkInterceptor(ABC):
    """
    Abstract base for SSE network proxy detectors.

    Concrete plugins implement vendor, process_names, and env_var_patterns only.
    Detection precedence: process_list > env_var > system_proxy.
    Fallback strategies are implemented once here and inherited by all plugins.
    """

    @property
    @abstractmethod
    def vendor(self) -> str:
        ...

    @property
    @abstractmethod
    def process_names(self) -> list[str]:
        ...

    @property
    @abstractmethod
    def env_var_patterns(self) -> list[str]:
        ...

    def detect(self) -> InterceptorResult | None:
        """Run all checks in precedence order; return result or None."""
        evidence: list[str] = []

        matched_process = self._check_process_list()
        if matched_process:
            evidence.append(f"process:{matched_process}")
            return InterceptorResult(
                vendor=self.vendor,
                confidence="high",
                evidence=evidence,
                fallback_strategy=self._best_fallback_strategy(),
            )

        matched_env = self._check_env_vars()
        if matched_env:
            evidence.append(f"env_var:{matched_env}")
            return InterceptorResult(
                vendor=self.vendor,
                confidence="medium",
                evidence=evidence,
                fallback_strategy=self._best_fallback_strategy(),
            )

        matched_proxy = self._check_system_proxy()
        if matched_proxy:
            evidence.append(f"system_proxy:{matched_proxy}")
            return InterceptorResult(
                vendor=self.vendor,
                confidence="low",
                evidence=evidence,
                fallback_strategy=self._best_fallback_strategy(),
            )

        return None

    # --- Primary detection helpers ---

    def _check_process_list(self) -> str | None:
        try:
            import psutil

            for proc in psutil.process_iter(["name"]):
                try:
                    name = (proc.info.get("name") or "").strip()
                    for target in self.process_names:
                        tl = target.lower()
                        if name.lower() == tl or name.lower().startswith(tl + "."):
                            return target
                except Exception:
                    continue
        except ImportError:
            pass
        except Exception:
            pass
        return None

    def _check_env_vars(self) -> str | None:
        """Scan running process environments for vendor-specific variables."""
        try:
            import psutil

            for proc in psutil.process_iter(["name"]):
                try:
                    env = proc.environ()
                    for pattern in self.env_var_patterns:
                        if any(k.upper().startswith(pattern.upper()) for k in env):
                            return pattern
                except Exception:
                    continue
        except ImportError:
            pass
        except Exception:
            pass
        return None

    def _check_system_proxy(self) -> str | None:
        """Check HTTPS_PROXY / HTTP_PROXY env vars for vendor fingerprints."""
        try:
            proxy = (
                os.environ.get("HTTPS_PROXY")
                or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY")
                or os.environ.get("http_proxy")
                or ""
            )
            if proxy:
                vendor_slug = self.vendor.lower().split()[0]
                if vendor_slug in proxy.lower():
                    return proxy[:80]
        except Exception:
            pass
        return None

    def _best_fallback_strategy(self) -> str:
        for strategy in self.fallback_strategies:
            if strategy in ("bedrock_resource_api", "cloudtrail_api") and self._boto3_available():
                return strategy
            if strategy == "dns_cache":
                return strategy
            if strategy == "process_env_scan":
                return strategy
        return self.fallback_strategies[0] if self.fallback_strategies else "none"

    @staticmethod
    def _boto3_available() -> bool:
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    # --- Shared fallback strategies (implemented once, inherited by all SSE plugins) ---

    @property
    def fallback_strategies(self) -> list[str]:
        """Ordered list; first viable one is selected as the recommendation."""
        return [
            "bedrock_resource_api",
            "cloudtrail_api",
            "dns_cache",
            "process_env_scan",
        ]

    @staticmethod
    def run_process_env_scan() -> list[dict]:
        """
        Scan running process environments for AWS credential/region indicators.
        Works regardless of which proxy is active.
        """
        aws_keys = frozenset(
            {"AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_REGION"}
        )
        results: list[dict] = []
        try:
            import psutil

            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    env = proc.environ()
                    found = {k: v for k, v in env.items() if k in aws_keys}
                    if found:
                        results.append({
                            "pid": proc.pid,
                            "process": (proc.info.get("name") or ""),
                            "aws_env_vars": sorted(found.keys()),
                            "region": found.get("AWS_DEFAULT_REGION") or found.get("AWS_REGION"),
                        })
                except Exception:
                    continue
        except ImportError:
            pass
        except Exception:
            pass
        return results

    @staticmethod
    def run_dns_cache_scan() -> list[str]:
        """
        Dump the OS DNS cache and return lines that mention Bedrock hostnames.
        ipconfig /displaydns on Windows; dscacheutil on macOS; no-op on Linux.
        """
        system = platform.system()
        lines: list[str] = []
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["ipconfig", "/displaydns"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.splitlines()
            elif system == "Darwin":
                result = subprocess.run(
                    ["dscacheutil", "-cachedump", "-entries", "Host"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.splitlines()
        except Exception:
            pass

        return [
            line for line in lines
            if "bedrock-runtime" in line.lower() or "bedrock-agent" in line.lower()
        ]

    @staticmethod
    def run_bedrock_resource_api() -> dict:
        """
        Query Bedrock management API to enumerate agents and knowledge bases.
        Cloud-side call — not routed through the TLS proxy, so proxy-immune.
        Requires boto3 and valid AWS credentials.
        """
        result: dict = {"agents": [], "knowledge_bases": [], "available": False}
        try:
            import boto3
            import botocore.exceptions  # type: ignore[import]

            region = (
                os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
            )
            client = boto3.client("bedrock-agent", region_name=region)

            try:
                resp = client.list_agents(maxResults=10)
                result["agents"] = [
                    a.get("agentName") or a.get("agentId")
                    for a in resp.get("agentSummaries", [])
                ]
                result["available"] = True
            except botocore.exceptions.ClientError:
                pass

            try:
                resp = client.list_knowledge_bases(maxResults=10)
                result["knowledge_bases"] = [
                    kb.get("name") or kb.get("knowledgeBaseId")
                    for kb in resp.get("knowledgeBaseSummaries", [])
                ]
                result["available"] = True
            except botocore.exceptions.ClientError:
                pass
        except ImportError:
            pass
        except Exception:
            pass
        return result

    @staticmethod
    def run_cloudtrail_api() -> list[dict]:
        """
        Query AWS CloudTrail for recent bedrock.amazonaws.com events.
        Cloud-side — fully proxy-immune.
        Requires boto3 and CloudTrail read permissions.
        """
        events: list[dict] = []
        try:
            from datetime import datetime, timedelta, timezone

            import boto3

            region = (
                os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
            )
            client = boto3.client("cloudtrail", region_name=region)
            start_time = datetime.now(timezone.utc) - timedelta(hours=24)

            resp = client.lookup_events(
                LookupAttributes=[{
                    "AttributeKey": "EventSource",
                    "AttributeValue": "bedrock.amazonaws.com",
                }],
                StartTime=start_time,
                MaxResults=20,
            )
            for event in resp.get("Events", []):
                ts = event.get("EventTime")
                events.append({
                    "event_name": event.get("EventName"),
                    "username": event.get("Username"),
                    "event_time": ts.isoformat() if ts else None,
                })
        except ImportError:
            pass
        except Exception:
            pass
        return events
