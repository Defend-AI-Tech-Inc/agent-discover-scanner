"""
Abstract base class and shared finding type for Layer 5 — SSE Proxy detectors.

All SSE proxy detectors (Zscaler ZIA, Prisma Access, Netskope) inherit from
SSEProxyDetector and produce SSEProxyFinding instances. Pattern mirrors
detectors/cloud_audit/base.py exactly.

Supported providers (v2.8.0):
  zscaler  — Zscaler Internet Access (ZIA) web transaction logs   (GA)
  prisma   — Palo Alto Prisma Access / Cortex Data Lake           (GA)
  netskope — Netskope Security Cloud                              (Preview / stub)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SSEProxyFinding:
    """
    Normalised finding from an SSE proxy / CASB web log.

    Carries the minimal set of fields needed for Layer 5 → correlator
    integration. Shape mirrors CloudAuditFinding.to_dict() so that the
    correlator can consume SSEProxyFinding objects alongside CloudAuditFinding
    and plain network dicts without changes.
    """

    provider: str
    """LLM provider inferred from destination hostname: "openai", "anthropic", etc."""

    source: str
    """Sub-source: "zscaler_zia" | "prisma_access" | "netskope"."""

    event_time: datetime
    """UTC timestamp of the web transaction."""

    username: str
    """Identity of the user / source (user@corp.com or source IP principal)."""

    source_ip: str
    """Client IP address originating the connection."""

    destination_host: str
    """Destination hostname recorded by the proxy (e.g. "api.openai.com")."""

    action: str = "ALLOWED"
    """Proxy disposition: ALLOWED | BLOCKED | etc."""

    model_id: str | None = None
    """Always None for SSE proxy findings — the proxy terminates TLS, not the payload."""

    framework_hint: str | None = None
    """Always None — SSE proxies see the TCP/TLS layer, not the HTTP User-Agent in body."""

    detection_layer: str = "layer5_sse_proxy"
    """Always 'layer5_sse_proxy' — identifies the finding source in the inventory."""

    def to_dict(self) -> dict:
        """
        Serialise to the dict shape expected by CorrelationEngine.correlate().

        Shape is identical to CloudAuditFinding.to_dict() and _normalise_event()
        in aws_cloudtrail.py so that the correlator's existing provider-matching
        and GHOST-detection logic works without modification.
        """
        return {
            "provider": self.provider,
            "process_name": None,           # SSE proxies have no OS process info
            "timestamp": self.event_time.isoformat(),
            "source": self.source,
            "event_name": self.action,
            "username": self.username,
            "source_ip": self.source_ip,
            "model_id": None,
            "framework": None,
            "destination_host": self.destination_host,
            "detection_layer": self.detection_layer,
        }


class SSEProxyDetector(ABC):
    """
    Abstract base for Layer 5 SSE proxy / CASB detectors.

    Concrete detectors implement:
      provider       — class-level string: "zscaler" | "prisma" | "netskope"
      detect()       — query the proxy log and return findings
      is_available() — return True when required credentials / SDKs are present

    is_available() MUST NOT raise. detect() is allowed to raise; callers wrap
    in try/except. Mirrors CloudAuditDetector ABC contract exactly.
    """

    provider: str  # "zscaler" | "prisma" | "netskope"

    @abstractmethod
    def detect(self, hours_back: int) -> list[SSEProxyFinding]:
        """
        Query the proxy's web transaction log for LLM API calls.

        Args:
            hours_back: How many hours of log history to query.

        Returns:
            List of SSEProxyFinding instances (may be empty).

        Raises:
            NotImplementedError: When the detector is a stub.
            Any HTTP / credential exception: Callers handle gracefully.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if the required credentials are present.

        Never raises.
        """
