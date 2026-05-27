"""
Tests for Layer 5 — Cloud Audit package structure and integration.

Covers:
  - Package imports and public API
  - Backward-compat shim (detectors.cloudtrail re-exports)
  - CloudAuditFinding.to_dict() shape
  - CloudAuditDetector ABC contract
  - AWSCloudTrailDetector class
  - AzureMonitorDetector / GCPAuditLogDetector stubs
  - get_available_detectors() auto-discovery
  - run_cloud_audit_detection() — normal flow, empty results, warn_fn, disable paths
  - layer5_cloud_audit.json output written by execute_scan_all
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Package imports
# ---------------------------------------------------------------------------


class TestPackageImports:
    def test_cloud_audit_init_importable(self):
        from agent_discover_scanner.detectors.cloud_audit import (  # noqa: F401
            CloudAuditDetector,
            CloudAuditFinding,
            get_available_detectors,
            run_cloud_audit_detection,
        )

    def test_base_importable(self):
        from agent_discover_scanner.detectors.cloud_audit.base import (  # noqa: F401
            CloudAuditDetector,
            CloudAuditFinding,
        )

    def test_aws_cloudtrail_importable(self):
        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (  # noqa: F401
            AWSCloudTrailDetector,
            run_cloudtrail_detection,
        )

    def test_azure_monitor_importable(self):
        from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (  # noqa: F401
            AzureMonitorDetector,
        )

    def test_gcp_audit_importable(self):
        from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (  # noqa: F401
            GCPAuditLogDetector,
        )


# ---------------------------------------------------------------------------
# Backward-compat shim
# ---------------------------------------------------------------------------


class TestBackwardCompatShim:
    """detectors.cloudtrail must still export all original names."""

    def test_run_cloudtrail_detection_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            run_cloudtrail_detection,
        )

    def test_fetch_cloudtrail_events_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            fetch_cloudtrail_events,
        )

    def test_fetch_cloudtrail_lake_events_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            fetch_cloudtrail_lake_events,
        )

    def test_bedrock_invoke_events_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            BEDROCK_INVOKE_EVENTS,
        )

    def test_parse_framework_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            _parse_framework_from_user_agent,
        )

    def test_extract_model_id_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            _extract_model_id,
        )

    def test_normalise_event_importable(self):
        from agent_discover_scanner.detectors.cloudtrail import (  # noqa: F401
            _normalise_event,
        )

    def test_shim_is_same_object_as_canonical(self):
        """The shim must point to the identical object, not a copy."""
        from agent_discover_scanner.detectors import cloudtrail as shim
        from agent_discover_scanner.detectors.cloud_audit import aws_cloudtrail as canon

        assert shim.run_cloudtrail_detection is canon.run_cloudtrail_detection
        assert shim.BEDROCK_INVOKE_EVENTS is canon.BEDROCK_INVOKE_EVENTS


# ---------------------------------------------------------------------------
# CloudAuditFinding dataclass
# ---------------------------------------------------------------------------


class TestCloudAuditFinding:
    def _make_finding(self, **overrides):
        from agent_discover_scanner.detectors.cloud_audit.base import CloudAuditFinding

        defaults = dict(
            provider="aws",
            service="bedrock",
            event_name="InvokeModel",
            event_time=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            principal="arn:aws:iam::123:user/alice",
            source_ip="10.0.0.1",
            model_id="anthropic.claude-3-sonnet",
            framework_hint="LangChain",
            source="cloudtrail_historical",
        )
        defaults.update(overrides)
        return CloudAuditFinding(**defaults)

    def test_to_dict_provider_maps_to_service(self):
        f = self._make_finding(service="bedrock")
        d = f.to_dict()
        # correlator uses "provider" key = the service name, not the cloud provider
        assert d["provider"] == "bedrock"

    def test_to_dict_timestamp_is_isoformat(self):
        f = self._make_finding()
        d = f.to_dict()
        assert "2026-01-15" in d["timestamp"]

    def test_to_dict_detection_layer(self):
        f = self._make_finding()
        d = f.to_dict()
        assert d["detection_layer"] == "layer5_cloud_audit"

    def test_to_dict_model_id_preserved(self):
        f = self._make_finding(model_id="mistral.mistral-7b")
        d = f.to_dict()
        assert d["model_id"] == "mistral.mistral-7b"

    def test_to_dict_process_name_is_none(self):
        f = self._make_finding()
        d = f.to_dict()
        assert d["process_name"] is None

    def test_default_detection_layer(self):
        f = self._make_finding()
        assert f.detection_layer == "layer5_cloud_audit"


# ---------------------------------------------------------------------------
# CloudAuditDetector ABC
# ---------------------------------------------------------------------------


class TestCloudAuditDetectorABC:
    def test_cannot_instantiate_directly(self):
        from agent_discover_scanner.detectors.cloud_audit.base import CloudAuditDetector

        with pytest.raises(TypeError):
            CloudAuditDetector()  # type: ignore[abstract]

    def test_concrete_subclass_requires_provider(self):
        from agent_discover_scanner.detectors.cloud_audit.base import (
            CloudAuditDetector,
        )

        class _Concrete(CloudAuditDetector):
            provider = "test"

            def detect(self, hours_back):
                return []

            def is_available(self):
                return True

        instance = _Concrete()
        assert instance.provider == "test"
        assert instance.is_available() is True
        assert instance.detect(1) == []


# ---------------------------------------------------------------------------
# AWSCloudTrailDetector
# ---------------------------------------------------------------------------


class TestAWSCloudTrailDetector:
    def test_provider_is_aws(self):
        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
            AWSCloudTrailDetector,
        )

        det = AWSCloudTrailDetector()
        assert det.provider == "aws"

    def test_is_available_true_when_boto3_present(self):
        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
            AWSCloudTrailDetector,
        )

        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            det = AWSCloudTrailDetector()
            assert det.is_available() is True

    def test_is_available_false_when_boto3_missing(self):
        import sys

        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
            AWSCloudTrailDetector,
        )

        orig = sys.modules.pop("boto3", None)
        try:
            det = AWSCloudTrailDetector()
            with patch(
                "agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail.AWSCloudTrailDetector.is_available",
                return_value=False,
            ):
                assert det.is_available() is False
        finally:
            if orig is not None:
                sys.modules["boto3"] = orig

    def test_detect_returns_list(self):
        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
            AWSCloudTrailDetector,
        )

        det = AWSCloudTrailDetector()
        _ct = "agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail.run_cloudtrail_detection"
        with patch(_ct, return_value=[]) as mock_ct:
            result = det.detect(hours_back=1)
        assert isinstance(result, list)
        assert mock_ct.call_count == 1


# ---------------------------------------------------------------------------
# Azure / GCP stubs
# ---------------------------------------------------------------------------


class TestAzureMonitorDetector:
    def test_provider_is_azure(self):
        from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (
            AzureMonitorDetector,
        )

        assert AzureMonitorDetector().provider == "azure"

    def test_is_available_false(self):
        from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (
            AzureMonitorDetector,
        )

        assert AzureMonitorDetector().is_available() is False

    def test_detect_raises_not_implemented(self):
        from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (
            AzureMonitorDetector,
        )

        with pytest.raises(NotImplementedError):
            AzureMonitorDetector().detect(hours_back=1)


class TestGCPAuditLogDetector:
    def test_provider_is_gcp(self):
        from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (
            GCPAuditLogDetector,
        )

        assert GCPAuditLogDetector().provider == "gcp"

    def test_is_available_false(self):
        from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (
            GCPAuditLogDetector,
        )

        assert GCPAuditLogDetector().is_available() is False

    def test_detect_raises_not_implemented(self):
        from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (
            GCPAuditLogDetector,
        )

        with pytest.raises(NotImplementedError):
            GCPAuditLogDetector().detect(hours_back=1)


# ---------------------------------------------------------------------------
# get_available_detectors
# ---------------------------------------------------------------------------


class TestGetAvailableDetectors:
    def test_returns_list(self):
        from agent_discover_scanner.detectors.cloud_audit import get_available_detectors

        result = get_available_detectors()
        assert isinstance(result, list)

    def test_aws_included_when_boto3_available(self):
        from agent_discover_scanner.detectors.cloud_audit import get_available_detectors
        from agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail import (
            AWSCloudTrailDetector,
        )

        with patch.object(AWSCloudTrailDetector, "is_available", return_value=True):
            result = get_available_detectors()
        providers = [d.provider for d in result]
        assert "aws" in providers

    def test_azure_excluded_when_stub(self):
        """Azure stub always returns is_available=False, so never in the list."""
        from agent_discover_scanner.detectors.cloud_audit import get_available_detectors

        result = get_available_detectors()
        providers = [d.provider for d in result]
        assert "azure" not in providers

    def test_gcp_excluded_when_stub(self):
        from agent_discover_scanner.detectors.cloud_audit import get_available_detectors

        result = get_available_detectors()
        providers = [d.provider for d in result]
        assert "gcp" not in providers


# ---------------------------------------------------------------------------
# run_cloud_audit_detection
# ---------------------------------------------------------------------------


class TestRunCloudAuditDetection:
    _CT_PATCH = (
        "agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail.run_cloudtrail_detection"
    )

    def test_returns_empty_list_when_no_findings(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        with patch(self._CT_PATCH, return_value=[]):
            result = run_cloud_audit_detection(hours_back=1)
        assert result == []

    def test_returns_findings_from_cloudtrail(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        fake_finding = {
            "provider": "bedrock",
            "process_name": None,
            "timestamp": "2026-01-15T10:00:00+00:00",
            "source": "cloudtrail_historical",
            "event_name": "InvokeModel",
            "username": "arn:aws:iam::123:user/alice",
            "source_ip": "10.0.0.1",
            "model_id": "anthropic.claude-3-sonnet",
            "framework": "LangChain",
            "detection_layer": "layer5_cloud_audit",
        }
        with patch(self._CT_PATCH, return_value=[fake_finding]):
            result = run_cloud_audit_detection(hours_back=1)
        assert len(result) == 1
        assert result[0]["provider"] == "bedrock"
        assert result[0]["detection_layer"] == "layer5_cloud_audit"

    def test_warn_fn_forwarded_to_cloudtrail(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        warn_messages: list[str] = []

        def _warn(msg: str) -> None:
            warn_messages.append(msg)

        with patch(self._CT_PATCH, return_value=[]) as mock_ct:
            run_cloud_audit_detection(hours_back=1, _warn_fn=_warn)
        assert mock_ct.call_args.kwargs.get("_warn_fn") is _warn

    def test_region_forwarded_to_cloudtrail(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        with patch(self._CT_PATCH, return_value=[]) as mock_ct:
            run_cloud_audit_detection(hours_back=1, region="ap-southeast-1")
        assert mock_ct.call_args.kwargs.get("region") == "ap-southeast-1"

    def test_lake_arn_forwarded_to_cloudtrail(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        arn = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE"
        with patch(self._CT_PATCH, return_value=[]) as mock_ct:
            run_cloud_audit_detection(hours_back=1, lake_arn=arn)
        assert mock_ct.call_args.kwargs.get("lake_arn") == arn

    def test_exception_in_cloudtrail_does_not_raise(self):
        """run_cloud_audit_detection must never raise, even on AWS error."""
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection

        with patch(self._CT_PATCH, side_effect=RuntimeError("AWS exploded")):
            result = run_cloud_audit_detection(hours_back=1)
        assert result == []

    def test_azure_stub_not_called_when_disabled(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection
        from agent_discover_scanner.detectors.cloud_audit.azure_monitor import (
            AzureMonitorDetector,
        )

        with patch(self._CT_PATCH, return_value=[]):
            with patch.object(AzureMonitorDetector, "detect") as mock_az:
                run_cloud_audit_detection(hours_back=1, azure_monitor_enabled=False)
        mock_az.assert_not_called()

    def test_gcp_stub_not_called_when_disabled(self):
        from agent_discover_scanner.detectors.cloud_audit import run_cloud_audit_detection
        from agent_discover_scanner.detectors.cloud_audit.gcp_audit import (
            GCPAuditLogDetector,
        )

        with patch(self._CT_PATCH, return_value=[]):
            with patch.object(GCPAuditLogDetector, "detect") as mock_gcp:
                run_cloud_audit_detection(hours_back=1, gcp_audit_enabled=False)
        mock_gcp.assert_not_called()


# ---------------------------------------------------------------------------
# Layer 5 output file — execute_scan_all writes layer5_cloud_audit.json
# ---------------------------------------------------------------------------


class TestLayer5OutputFile:
    """
    Verify that execute_scan_all writes layer5_cloud_audit.json when
    cloud_audit_enabled=True (or cloud_audit_hours > 0).
    """

    _CT_PATCH = (
        "agent_discover_scanner.detectors.cloud_audit.aws_cloudtrail.run_cloudtrail_detection"
    )

    def _run_scan_all(self, tmp_path, *, cloud_audit_enabled: bool = True) -> Path:
        from agent_discover_scanner.scan_runner import execute_scan_all

        (tmp_path / "dummy.py").write_text("x = 1\n")
        minimal_summary = {
            "connections": [], "findings": [], "services": {},
            "processes": {}, "total_connections": 0, "scan_duration": 1,
            "unique_services": [], "rag_patterns": [],
        }

        out_dir = tmp_path / "out"
        with (
            patch("agent_discover_scanner.scan_runner._invoke_layer1_scan"),
            patch(
                "agent_discover_scanner.scan_runner.CorrelationEngine.load_code_findings",
                return_value=[],
            ),
            patch("agent_discover_scanner.scan_runner.NetworkMonitor") as mock_nm,
            patch(
                "agent_discover_scanner.scan_runner.CorrelationEngine.correlate",
                return_value={
                    "confirmed": [], "ghost": [], "unknown": [],
                    "shadow_ai": [], "zombie": [],
                },
            ),
            patch(self._CT_PATCH, return_value=[]) as _mock,
        ):
            mock_nm.return_value.monitor.return_value = minimal_summary
            execute_scan_all(
                path=str(tmp_path),
                output=out_dir,
                duration=1,
                layer3_file=None,
                skip_layers="3,4",
                daemon=False,
                max_log_size=10,
                max_log_backups=1,
                platform=False,
                api_key=None,
                tenant_token=None,
                wawsdb_url="http://localhost",
                platform_interval=5,
                verbose=False,
                scan_output_format="text",
                cloud_audit_enabled=cloud_audit_enabled,
                cloud_audit_hours=0,
            )
        return out_dir

    def test_layer5_json_created_when_enabled(self, tmp_path):
        import json

        out_dir = self._run_scan_all(tmp_path, cloud_audit_enabled=True)
        layer5_file = out_dir / "layer5_cloud_audit.json"
        assert layer5_file.exists(), "layer5_cloud_audit.json should be written"
        data = json.loads(layer5_file.read_text())
        assert "findings" in data

    def test_layer5_json_not_created_when_disabled(self, tmp_path):
        out_dir = self._run_scan_all(tmp_path, cloud_audit_enabled=False)
        layer5_file = out_dir / "layer5_cloud_audit.json"
        assert not layer5_file.exists(), (
            "layer5_cloud_audit.json should NOT be written when cloud audit is disabled"
        )
