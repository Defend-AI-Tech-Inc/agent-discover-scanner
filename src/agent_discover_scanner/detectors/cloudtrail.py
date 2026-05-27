"""
Backward-compatibility shim — re-exports from detectors.cloud_audit.aws_cloudtrail.

The canonical home for all AWS CloudTrail detection logic is now:
  agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail

This module exists so that existing code and tests that import from
  agent_discover_scanner.detectors.cloudtrail
continue to work without modification.  All names are re-exported verbatim.

Do not add logic here — extend aws_cloudtrail.py instead.
"""

from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (  # noqa: F401
    BEDROCK_INVOKE_EVENTS,
    AWSCloudTrailDetector,
    _build_label,
    _extract_model_id,
    _normalise_event,
    _parse_framework_from_user_agent,
    fetch_cloudtrail_events,
    fetch_cloudtrail_lake_events,
    run_cloudtrail_detection,
)
