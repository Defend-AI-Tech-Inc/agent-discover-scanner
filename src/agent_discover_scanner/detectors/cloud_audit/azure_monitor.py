"""
Azure Monitor activity log detector — Layer 5 Cloud Audit (Azure).

Status: Preview / stub — not yet implemented.
Track progress: github.com/Defend-AI-Tech-Inc/agent-discover-scanner

When implemented, this detector will query Azure Monitor activity logs for
Azure OpenAI Service invocations, providing the same forensic attribution
(caller identity, model, timestamp) that AWS CloudTrail provides for Bedrock.

Required Azure SDK (when implemented):
  pip install azure-mgmt-monitor azure-identity

Required permissions (when implemented):
  Microsoft.Insights/diagnosticSettings/read
  Microsoft.Insights/eventtypes/values/read
"""

from __future__ import annotations

from agent_discover_scanner.detectors.cloud_audit.base import (
    CloudAuditDetector,
    CloudAuditFinding,
)

_NOT_IMPLEMENTED_MSG = (
    "Azure Monitor detection coming soon. "
    "Track progress: github.com/Defend-AI-Tech-Inc/agent-discover-scanner"
)


class AzureMonitorDetector(CloudAuditDetector):
    """
    Layer 5 Cloud Audit detector for Azure via Azure Monitor activity logs.

    Currently a stub — detect() raises NotImplementedError.
    is_available() always returns False so auto-discovery skips it gracefully.
    """

    provider = "azure"

    def is_available(self) -> bool:
        """Always False until the Azure SDK integration is implemented."""
        return False

    def detect(self, hours_back: int) -> list[CloudAuditFinding]:
        """
        Not yet implemented.

        Raises:
            NotImplementedError: Always, until the Azure Monitor integration
                is implemented in a future release.
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
