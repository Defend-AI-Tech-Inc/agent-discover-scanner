"""
GCP Cloud Audit Log detector — Layer 5 Cloud Audit (GCP).

Status: Preview / stub — not yet implemented.
Track progress: github.com/Defend-AI-Tech-Inc/agent-discover-scanner

When implemented, this detector will query GCP Cloud Audit Logs for
Vertex AI and Gemini API invocations, providing the same forensic attribution
(caller identity, model, timestamp) that AWS CloudTrail provides for Bedrock.

Required GCP SDK (when implemented):
  pip install google-cloud-logging

Required IAM permissions (when implemented):
  roles/logging.viewer  (or logging.logEntries.list on the project)
"""

from __future__ import annotations

from agent_discover_scanner.detectors.cloud_audit.base import (
    CloudAuditDetector,
    CloudAuditFinding,
)

_NOT_IMPLEMENTED_MSG = (
    "GCP Cloud Audit Log detection coming soon. "
    "Track progress: github.com/Defend-AI-Tech-Inc/agent-discover-scanner"
)


class GCPAuditLogDetector(CloudAuditDetector):
    """
    Layer 5 Cloud Audit detector for GCP via Cloud Audit Logs.

    Currently a stub — detect() raises NotImplementedError.
    is_available() always returns False so auto-discovery skips it gracefully.
    """

    provider = "gcp"

    def is_available(self) -> bool:
        """Always False until the GCP SDK integration is implemented."""
        return False

    def detect(self, hours_back: int) -> list[CloudAuditFinding]:
        """
        Not yet implemented.

        Raises:
            NotImplementedError: Always, until the GCP Cloud Audit Log
                integration is implemented in a future release.
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
