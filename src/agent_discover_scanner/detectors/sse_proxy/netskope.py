"""
Netskope Security Cloud detector stub — Layer 5 SSE Proxy.

Netskope integration is planned for a future release. This stub satisfies the
auto-discovery contract so that the __init__.py loader does not error when it
encounters this module.

is_available() always returns False, so detect() is never called by the
auto-discovery loop. Manually instantiating and calling detect() raises
NotImplementedError with migration guidance.
"""

from __future__ import annotations

from agent_discover_scanner.detectors.sse_proxy.base import SSEProxyDetector, SSEProxyFinding


class NetskopeDetector(SSEProxyDetector):
    """
    [Preview — stub] Layer 5 SSE Proxy detector for Netskope Security Cloud.

    Not yet implemented. is_available() always returns False.
    Required env vars (future): NETSKOPE_API_TOKEN, NETSKOPE_TENANT.
    """

    provider = "netskope"

    def is_available(self) -> bool:
        """Always False — Netskope detector is not yet implemented."""
        return False

    def detect(self, hours_back: int) -> list[SSEProxyFinding]:
        """Raises NotImplementedError — this detector is a stub."""
        raise NotImplementedError(
            "NetskopeDetector is not yet implemented. "
            "Netskope support is planned for a future agentdiscover release. "
            "See https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/issues "
            "to track progress or contribute an implementation."
        )
