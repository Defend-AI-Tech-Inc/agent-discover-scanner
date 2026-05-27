"""
Layer 5 — Cloud Audit detector package.

Auto-discovers all CloudAuditDetector subclasses registered in this package
(aws_cloudtrail, azure_monitor, gcp_audit) and exposes a single entry point:

    run_cloud_audit_detection(...)

The entry point calls each available detector in order (AWS → Azure → GCP),
merges results, and returns a flat list of normalised findings.

Public API
----------
run_cloud_audit_detection   — top-level entry point used by scan_runner
CloudAuditDetector          — ABC for custom provider plugins
CloudAuditFinding           — normalised finding dataclass

Supported providers (v2.7.0):
  aws    — CloudTrail LookupEvents / CloudTrail Lake   (GA)
  azure  — Azure Monitor activity logs                  (Preview / stub)
  gcp    — GCP Cloud Audit Logs                         (Preview / stub)
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Callable
from typing import TYPE_CHECKING

from agent_discover_scanner.detectors.cloud_audit.base import (
    CloudAuditDetector,
    CloudAuditFinding,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

__all__ = [
    "CloudAuditDetector",
    "CloudAuditFinding",
    "run_cloud_audit_detection",
    "get_available_detectors",
]

# ---------------------------------------------------------------------------
# Auto-discovery — mirrors interceptors/__init__.py pattern
# ---------------------------------------------------------------------------

_SUBMODULES = ("aws_cloudtrail", "azure_monitor", "gcp_audit")


def _discover_detector_classes() -> list[type[CloudAuditDetector]]:
    """
    Walk each sub-module in this package and collect all CloudAuditDetector
    subclasses.  Returns them in the canonical order: AWS → Azure → GCP.
    """
    found: list[type[CloudAuditDetector]] = []
    pkg_path = __path__  # type: ignore[name-defined]
    pkg_name = __name__

    for mod_info in pkgutil.iter_modules(pkg_path):
        if mod_info.name.startswith("_"):
            continue
        full_name = f"{pkg_name}.{mod_info.name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as exc:
            logger.debug("cloud_audit: skipping %s (import error: %s)", full_name, exc)
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, CloudAuditDetector)
                and obj is not CloudAuditDetector
                and obj not in found
            ):
                found.append(obj)

    # Sort by provider name to get stable AWS → Azure → GCP order
    _order = {"aws": 0, "azure": 1, "gcp": 2}
    found.sort(key=lambda cls: _order.get(getattr(cls, "provider", "z"), 99))
    return found


def get_available_detectors(
    region: str | None = None,
    lake_arn: str | None = None,
) -> list[CloudAuditDetector]:
    """
    Return instantiated CloudAuditDetector objects for providers whose
    is_available() returns True.

    Args:
        region:   Cloud region hint forwarded to detectors that support it
                  (currently only AWSCloudTrailDetector).
        lake_arn: CloudTrail Lake event-data-store ARN; forwarded to
                  AWSCloudTrailDetector when provided.

    Returns:
        List of ready-to-use detector instances, in provider order.
    """
    detector_classes = _discover_detector_classes()
    available: list[CloudAuditDetector] = []

    for cls in detector_classes:
        # AWSCloudTrailDetector accepts region / lake_arn at construction time;
        # Azure and GCP stubs use the no-arg constructor.
        try:
            if getattr(cls, "provider", None) == "aws":
                instance: CloudAuditDetector = cls(region=region, lake_arn=lake_arn)
            else:
                instance = cls()
        except Exception as exc:
            logger.debug("cloud_audit: failed to instantiate %s: %s", cls.__name__, exc)
            continue

        try:
            if instance.is_available():
                available.append(instance)
        except Exception as exc:
            logger.debug(
                "cloud_audit: %s.is_available() raised: %s", cls.__name__, exc
            )

    return available


# ---------------------------------------------------------------------------
# Top-level entry point used by scan_runner
# ---------------------------------------------------------------------------


def run_cloud_audit_detection(
    hours_back: int = 1,
    region: str | None = None,
    lake_arn: str | None = None,
    azure_monitor_enabled: bool = False,
    gcp_audit_enabled: bool = False,
    _warn_fn: Callable[[str], None] | None = None,
) -> list[dict]:
    """
    Run all available Layer 5 Cloud Audit detectors and return merged findings.

    Execution order: AWS (CloudTrail) → Azure Monitor → GCP Cloud Audit.

    Providers whose is_available() returns False are silently skipped.
    Azure and GCP stub detectors always return False until implemented.

    Args:
        hours_back:           How many hours of audit log history to query.
        region:               Cloud region to query (used by AWS detector).
        lake_arn:             CloudTrail Lake event-data-store ARN (AWS only).
        azure_monitor_enabled: Currently ignored; reserved for when the Azure
                               detector is implemented.
        gcp_audit_enabled:    Currently ignored; reserved for when the GCP
                               detector is implemented.
        _warn_fn:             Optional callable receiving human-readable warning
                              messages (e.g. "no credentials") that scan_runner
                              surfaces to the console. Never raises.

    Returns:
        Flat list of normalised finding dicts (same shape as _normalise_event()
        in aws_cloudtrail.py, consumable by CorrelationEngine.correlate()).

    Never raises — all detector errors are caught and logged.
    """
    from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
        run_cloudtrail_detection,
    )

    all_findings: list[dict] = []

    # -- AWS (CloudTrail) -------------------------------------------------
    # We call run_cloudtrail_detection() directly rather than going through
    # AWSCloudTrailDetector.detect() so that the _warn_fn callback is honoured
    # (detect() has no _warn_fn parameter by ABC contract).
    try:
        aws_findings = run_cloudtrail_detection(
            lookback_hours=hours_back,
            lake_arn=lake_arn,
            region=region,
            _warn_fn=_warn_fn,
        )
        all_findings.extend(aws_findings)
        if aws_findings:
            logger.info(
                "Layer 5 (AWS CloudTrail): %d finding(s)", len(aws_findings)
            )
    except Exception as exc:
        logger.warning("Layer 5 — AWS CloudTrail detection error: %s", exc)
        if _warn_fn:
            _warn_fn(f"Cloud audit (AWS) error: {exc}")

    # -- Azure (stub) -----------------------------------------------------
    # azure_monitor_enabled is wired up for future implementation; today the
    # detector's is_available() always returns False.
    if azure_monitor_enabled:
        try:
            from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (
                AzureMonitorDetector,
            )
            az = AzureMonitorDetector()
            if az.is_available():
                for finding in az.detect(hours_back=hours_back):
                    all_findings.append(finding.to_dict())
        except NotImplementedError:
            pass  # stub — expected
        except Exception as exc:
            logger.debug("Layer 5 — Azure Monitor detection error: %s", exc)

    # -- GCP (stub) -------------------------------------------------------
    if gcp_audit_enabled:
        try:
            from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (
                GCPAuditLogDetector,
            )
            gcp = GCPAuditLogDetector()
            if gcp.is_available():
                for finding in gcp.detect(hours_back=hours_back):
                    all_findings.append(finding.to_dict())
        except NotImplementedError:
            pass  # stub — expected
        except Exception as exc:
            logger.debug("Layer 5 — GCP audit detection error: %s", exc)

    return all_findings
