"""
Layer 5 — SSE Proxy detector package.

Auto-discovers all SSEProxyDetector subclasses registered in this package
(zscaler_zia, prisma_access, netskope) and exposes a single entry point:

    run_sse_proxy_detection(...)

The entry point instantiates each available detector in order
(Zscaler → Prisma → Netskope), merges results into a flat list of normalised
finding dicts (same shape as CloudAuditFinding.to_dict()), and returns them
for the correlator to consume.

Output is written to layer5_sse_proxy.json by scan_runner and merged into
the network_findings list passed to CorrelationEngine.correlate() with
detection_layer="layer5_sse_proxy" so that the correlator can distinguish
SSE proxy findings from live Layer 2 psutil observations.

Public API
----------
run_sse_proxy_detection   — top-level entry point used by scan_runner
SSEProxyDetector          — ABC for custom SSE proxy plugins
SSEProxyFinding           — normalised finding dataclass

Supported providers (v2.8.0):
  zscaler  — Zscaler ZIA web transaction logs   (GA)
  prisma   — Prisma Access / Cortex Data Lake   (GA)
  netskope — Netskope Security Cloud            (Preview / stub)
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Callable

from agent_discover_scanner.detectors.sse_proxy.base import (
    SSEProxyDetector,
    SSEProxyFinding,
)

logger = logging.getLogger(__name__)

__all__ = [
    "SSEProxyDetector",
    "SSEProxyFinding",
    "run_sse_proxy_detection",
    "get_available_sse_detectors",
]

# Canonical provider order for auto-discovery
_PROVIDER_ORDER: dict[str, int] = {"zscaler": 0, "prisma": 1, "netskope": 2}


def _discover_sse_detector_classes() -> list[type[SSEProxyDetector]]:
    """
    Walk each sub-module in this package and collect all SSEProxyDetector subclasses.
    Returns them in canonical provider order: Zscaler → Prisma → Netskope.
    Mirrors cloud_audit/_discover_detector_classes() exactly.
    """
    found: list[type[SSEProxyDetector]] = []
    pkg_path = __path__  # type: ignore[name-defined]
    pkg_name = __name__

    for mod_info in pkgutil.iter_modules(pkg_path):
        if mod_info.name.startswith("_"):
            continue
        full_name = f"{pkg_name}.{mod_info.name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as exc:
            logger.debug("sse_proxy: skipping %s (import error: %s)", full_name, exc)
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, SSEProxyDetector)
                and obj is not SSEProxyDetector
                and obj not in found
            ):
                found.append(obj)

    found.sort(key=lambda cls: _PROVIDER_ORDER.get(getattr(cls, "provider", "z"), 99))
    return found


def get_available_sse_detectors(
    zscaler_tenant: str | None = None,
    zscaler_api_key: str | None = None,
    prisma_tenant_id: str | None = None,
    prisma_client_id: str | None = None,
    prisma_region: str | None = None,
) -> list[SSEProxyDetector]:
    """
    Return instantiated SSEProxyDetector objects for providers whose
    is_available() returns True.

    Constructor kwargs override environment variables; see each detector
    class for the full precedence rules.
    """
    detector_classes = _discover_sse_detector_classes()
    available: list[SSEProxyDetector] = []

    for cls in detector_classes:
        try:
            p = getattr(cls, "provider", None)
            if p == "zscaler":
                instance: SSEProxyDetector = cls(
                    tenant=zscaler_tenant,
                    api_key=zscaler_api_key,
                )
            elif p == "prisma":
                instance = cls(
                    tenant_id=prisma_tenant_id,
                    client_id=prisma_client_id,
                    region=prisma_region,
                )
            else:
                instance = cls()
        except Exception as exc:
            logger.debug("sse_proxy: failed to instantiate %s: %s", cls.__name__, exc)
            continue

        try:
            if instance.is_available():
                available.append(instance)
        except Exception as exc:
            logger.debug("sse_proxy: %s.is_available() raised: %s", cls.__name__, exc)

    return available


def run_sse_proxy_detection(
    hours_back: int = 1,
    zscaler_enabled: bool = False,
    zscaler_tenant: str | None = None,
    zscaler_api_key: str | None = None,
    prisma_access_enabled: bool = False,
    prisma_tenant_id: str | None = None,
    prisma_client_id: str | None = None,
    prisma_region: str | None = None,
    _warn_fn: Callable[[str], None] | None = None,
) -> list[dict]:
    """
    Run all enabled and available SSE proxy detectors and return merged findings.

    A detector runs only when both of the following are true:
      1. Its corresponding enable flag is True (--zscaler or --prisma-access).
      2. Its is_available() returns True (credentials present).

    Execution order: Zscaler ZIA → Prisma Access → Netskope (stub, always skipped).

    Args:
        hours_back:           Lookback window in hours.
        zscaler_enabled:      Enable Zscaler ZIA detection.
        zscaler_tenant:       Zscaler tenant prefix (overrides ZSCALER_TENANT).
        zscaler_api_key:      Zscaler API key (overrides ZSCALER_API_KEY).
        prisma_access_enabled: Enable Prisma Access detection.
        prisma_tenant_id:     Prisma tenant/TSG ID (overrides PRISMA_TENANT_ID).
        prisma_client_id:     Prisma OAuth2 client ID (overrides PRISMA_CLIENT_ID).
        prisma_region:        CDL region: us/eu/uk/sg/ca/jp/au (overrides PRISMA_REGION).
        _warn_fn:             Optional callable for human-readable warning messages.

    Returns:
        Flat list of normalised finding dicts (detection_layer="layer5_sse_proxy"),
        consumable by CorrelationEngine.correlate().

    Never raises — all detector errors are caught and logged.
    """
    all_findings: list[dict] = []

    if not (zscaler_enabled or prisma_access_enabled):
        return all_findings

    # -- Zscaler ZIA ----------------------------------------------------------
    if zscaler_enabled:
        try:
            from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import (
                ZscalerZIADetector,
            )
            zscaler = ZscalerZIADetector(
                tenant=zscaler_tenant,
                api_key=zscaler_api_key,
            )
            if zscaler.is_available():
                findings = zscaler.detect(hours_back=hours_back)
                for f in findings:
                    all_findings.append(f.to_dict())
                if findings:
                    logger.info("Layer 5 (Zscaler ZIA): %d finding(s)", len(findings))
            else:
                _msg = (
                    "Zscaler ZIA scan skipped: ZSCALER_API_KEY, ZSCALER_USERNAME, "
                    "ZSCALER_PASSWORD, and ZSCALER_TENANT must all be set"
                )
                logger.warning(_msg)
                if _warn_fn:
                    _warn_fn(_msg)
        except Exception as exc:
            _emsg = f"SSE proxy (Zscaler ZIA) error: {exc}"
            logger.warning(_emsg)
            if _warn_fn:
                _warn_fn(_emsg)

    # -- Prisma Access --------------------------------------------------------
    if prisma_access_enabled:
        try:
            from agent_discover_scanner.detectors.sse_proxy.prisma_access import (
                PrismaAccessDetector,
            )
            prisma = PrismaAccessDetector(
                tenant_id=prisma_tenant_id,
                client_id=prisma_client_id,
                region=prisma_region,
            )
            if prisma.is_available():
                findings = prisma.detect(hours_back=hours_back)
                for f in findings:
                    all_findings.append(f.to_dict())
                if findings:
                    logger.info("Layer 5 (Prisma Access): %d finding(s)", len(findings))
            else:
                _msg = (
                    "Prisma Access scan skipped: PRISMA_CLIENT_ID, "
                    "PRISMA_CLIENT_SECRET, and PRISMA_TENANT_ID must all be set"
                )
                logger.warning(_msg)
                if _warn_fn:
                    _warn_fn(_msg)
        except Exception as exc:
            _emsg = f"SSE proxy (Prisma Access) error: {exc}"
            logger.warning(_emsg)
            if _warn_fn:
                _warn_fn(_emsg)

    # -- Netskope (stub — always skipped) ------------------------------------
    # NetskopeDetector.is_available() always returns False; nothing to do here.

    return all_findings
