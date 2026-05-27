"""
Abstract base class and shared finding type for Layer 5 — Cloud Audit detectors.

All cloud provider audit-log detectors inherit from CloudAuditDetector and
produce CloudAuditFinding instances. The ABC mirrors the interceptors/base.py
pattern: each concrete detector declares its provider identity and implements
detect() and is_available(). The __init__.py auto-discovers all registered
detectors.

Supported providers (v2.7.0):
  aws    — CloudTrail LookupEvents / CloudTrail Lake   (GA)
  azure  — Azure Monitor activity logs                  (Preview / stub)
  gcp    — GCP Cloud Audit Logs                         (Preview / stub)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CloudAuditFinding:
    """
    Normalised finding from any cloud provider audit log.

    Carries the minimal set of fields needed for Layer 5 → correlator
    integration. Mirrors the dict shape returned by run_cloudtrail_detection()
    so that existing correlator logic can consume CloudAuditFinding objects
    alongside plain dicts without changes.
    """

    provider: str
    """Cloud provider: "aws", "azure", "gcp"."""

    service: str
    """AI service invoked: "bedrock", "azure_openai", "vertex_ai", etc."""

    event_name: str
    """API action name, e.g. "InvokeModel", "completions", "predict"."""

    event_time: datetime
    """UTC timestamp of the event."""

    principal: str
    """Identity that made the call: IAM ARN, Azure principal ID, GCP service account."""

    source_ip: str
    """Originating IP address recorded by the cloud provider."""

    model_id: str | None = None
    """Model or agent identifier when present in the request parameters."""

    framework_hint: str | None = None
    """SDK / framework inferred from the HTTP User-Agent at call time."""

    detection_layer: str = "layer5_cloud_audit"
    """Always 'layer5_cloud_audit' — identifies the finding source in the inventory."""

    source: str = "cloudtrail_historical"
    """Sub-source within the provider, e.g. 'cloudtrail_historical', 'cloudtrail_lake'."""

    def to_dict(self) -> dict:
        """
        Serialise to the dict shape expected by CorrelationEngine.correlate().

        The correlator treats Layer 2 / Layer 5 findings as a flat list of
        provider-tagged dicts.  This shape is identical to what
        _normalise_event() in aws_cloudtrail.py returns.
        """
        return {
            "provider": self.service,          # correlator uses "provider" = service name
            "process_name": None,
            "timestamp": self.event_time.isoformat(),
            "source": self.source,
            "event_name": self.event_name,
            "username": self.principal,
            "source_ip": self.source_ip,
            "model_id": self.model_id,
            "framework": self.framework_hint,
            "detection_layer": self.detection_layer,
        }


class CloudAuditDetector(ABC):
    """
    Abstract base for Layer 5 cloud provider audit-log detectors.

    Concrete detectors implement:
      provider     — class-level string attribute ("aws", "azure", "gcp")
      detect()     — query the provider's audit log and return findings
      is_available() — return True when required credentials / SDKs are present

    is_available() MUST NOT raise — it should only return False when the
    provider is unavailable so the auto-discovery loop can skip gracefully.

    detect() is allowed to raise; callers are expected to wrap in try/except.
    """

    provider: str  # "aws" | "azure" | "gcp"

    @abstractmethod
    def detect(self, hours_back: int) -> list[CloudAuditFinding]:
        """
        Query the cloud provider's audit log for AI API invocations.

        Args:
            hours_back: How many hours into the past to scan.

        Returns:
            List of CloudAuditFinding instances (may be empty).

        Raises:
            NotImplementedError: When the provider is a stub pending implementation.
            Any SDK / credential exception: Callers handle gracefully.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if the required SDK and credentials are present.

        This is called before detect() to allow the auto-discovery loop to
        skip unavailable providers without producing noisy error output.
        Never raises.
        """
