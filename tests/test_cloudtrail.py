"""
Tests for detectors/cloudtrail.py — standard CloudTrail and CloudTrail Lake detectors.

All tests are fully mocked; no real AWS credentials, network calls, or boto3 installation
is needed. boto3/botocore are injected into sys.modules for the duration of each test.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch  # noqa: F401

import pytest

from agent_discover_scanner.detectors.cloudtrail import (
    BEDROCK_INVOKE_EVENTS,
    _extract_model_id,
    _normalise_event,
    _parse_framework_from_user_agent,
    fetch_cloudtrail_events,
    fetch_cloudtrail_lake_events,
    run_cloudtrail_detection,
)

# ---------------------------------------------------------------------------
# Boto3 / botocore injection helpers
# ---------------------------------------------------------------------------


class _NoCredentialsError(Exception):
    pass


class _ClientError(Exception):
    def __init__(self, error_response: dict, operation_name: str = "op"):
        self.response = error_response
        super().__init__(str(error_response))


@contextmanager
def _inject_boto3(client_mock):
    """
    Inject minimal boto3 + botocore stubs into sys.modules.

    The exception classes are real Python classes so `except` clauses work.
    boto3.client() is wired to return client_mock.
    """
    mock_botocore_exceptions = MagicMock()
    mock_botocore_exceptions.NoCredentialsError = _NoCredentialsError
    mock_botocore_exceptions.ClientError = _ClientError

    mock_botocore = MagicMock()
    mock_botocore.exceptions = mock_botocore_exceptions

    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = client_mock

    modules = {
        "boto3": mock_boto3,
        "botocore": mock_botocore,
        "botocore.exceptions": mock_botocore_exceptions,
    }
    # Remove cached imports so the module's `import boto3` picks up the mock.
    old = {k: sys.modules.pop(k) for k in modules if k in sys.modules}
    sys.modules.update(modules)
    try:
        yield mock_boto3
    finally:
        for k in modules:
            sys.modules.pop(k, None)
        sys.modules.update(old)


# ---------------------------------------------------------------------------
# Test data factories
# ---------------------------------------------------------------------------


def _make_ct_event(
    event_name: str = "InvokeModel",
    event_time: datetime | None = None,
    username: str = "arn:aws:iam::123456789012:user/alice",
    source_ip: str = "10.0.1.42",
    user_agent: str = "boto3/1.34.0 Python/3.12.0",
    model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
) -> dict:
    """Build a minimal CloudTrail Events API response item."""
    import json

    if event_time is None:
        event_time = datetime.now(timezone.utc)

    raw = {
        "eventSource": "bedrock.amazonaws.com",
        "eventName": event_name,
        "eventTime": event_time.isoformat(),
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "userIdentity": {"arn": username},
        "requestParameters": {"modelId": model_id},
    }
    return {
        "EventName": event_name,
        "EventTime": event_time,
        "Username": username,
        "CloudTrailEvent": json.dumps(raw),
    }


def _make_lake_row(
    event_name: str = "InvokeModel",
    event_time: str = "2026-05-26T10:00:00Z",
    arn: str = "arn:aws:iam::123456789012:user/alice",
    source_ip: str = "10.0.1.42",
    user_agent: str = "boto3/1.34.0 Python/3.12.0",
    model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
) -> list[dict]:
    """Build a CloudTrail Lake QueryResultRows row (list of single-key dicts)."""
    import json

    return [
        {"eventName": event_name},
        {"eventTime": event_time},
        {"userIdentity.arn": arn},
        {"sourceIPAddress": source_ip},
        {"userAgent": user_agent},
        {"requestParameters": json.dumps({"modelId": model_id})},
    ]


# ---------------------------------------------------------------------------
# Unit — _parse_framework_from_user_agent
# ---------------------------------------------------------------------------


class TestParseFrameworkFromUserAgent:
    def test_langchain_aws_prefix(self):
        ua = "langchain-aws/0.1.0 Python/3.12.0 botocore/1.34.0"
        assert _parse_framework_from_user_agent(ua) == "LangChain/LangGraph"

    def test_langchain_underscore(self):
        ua = "langchain_aws/0.1.0 botocore/1.34.0"
        assert _parse_framework_from_user_agent(ua) == "LangChain/LangGraph"

    def test_boto3_only(self):
        ua = "Boto3/1.34.0 Python/3.12.0 botocore/1.34.0"
        assert _parse_framework_from_user_agent(ua) == "AWS SDK (boto3)"

    def test_bedrock_agent(self):
        ua = "amazon-bedrock-agent/1.0"
        assert _parse_framework_from_user_agent(ua) == "Managed Bedrock Agent"

    def test_unknown_ua(self):
        ua = "custom-internal-client/2.0"
        assert _parse_framework_from_user_agent(ua) == "Unknown"

    def test_empty_ua(self):
        assert _parse_framework_from_user_agent("") == "Unknown"

    def test_none_ua(self):
        assert _parse_framework_from_user_agent(None) == "Unknown"


# ---------------------------------------------------------------------------
# Unit — _extract_model_id
# ---------------------------------------------------------------------------


class TestExtractModelId:
    def test_model_id_from_request_params(self):
        import json

        raw = json.dumps(
            {"requestParameters": {"modelId": "anthropic.claude-3-sonnet-20240229-v1:0"}}
        )
        assert _extract_model_id(raw) == "anthropic.claude-3-sonnet-20240229-v1:0"

    def test_agent_id_fallback(self):
        import json

        raw = json.dumps({"requestParameters": {"agentId": "ABCDEF1234"}})
        assert _extract_model_id(raw) == "ABCDEF1234"

    def test_missing_params_returns_none(self):
        import json

        assert _extract_model_id(json.dumps({})) is None

    def test_malformed_json_returns_none(self):
        assert _extract_model_id("{not valid json}") is None


# ---------------------------------------------------------------------------
# Unit — _normalise_event
# ---------------------------------------------------------------------------


class TestNormaliseEvent:
    def test_output_shape_cloudtrail_historical(self):
        event_time = datetime(2026, 5, 26, 10, 0, 0, tzinfo=timezone.utc)
        finding = _normalise_event(
            event_name="InvokeModel",
            event_time=event_time,
            username="arn:aws:iam::123456789012:user/alice",
            source_ip="10.0.1.42",
            user_agent="boto3/1.34.0",
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            source="cloudtrail_historical",
        )
        assert finding["provider"] == "bedrock"
        assert finding["process_name"] is None
        assert finding["source"] == "cloudtrail_historical"
        assert finding["event_name"] == "InvokeModel"
        assert finding["username"] == "arn:aws:iam::123456789012:user/alice"
        assert finding["model_id"] == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert finding["framework"] == "AWS SDK (boto3)"
        assert "CloudTrail historical" in finding["label"]

    def test_langchain_label_appears_in_label(self):
        event_time = datetime(2026, 5, 26, 10, 0, 0, tzinfo=timezone.utc)
        finding = _normalise_event(
            event_name="InvokeModel",
            event_time=event_time,
            username=None,
            source_ip=None,
            user_agent="langchain-aws/0.1.0 Python/3.12.0",
            model_id=None,
            source="cloudtrail_historical",
        )
        assert "LangChain/LangGraph" in finding["label"]
        assert "via" in finding["label"]

    def test_lake_source_label(self):
        event_time = datetime(2026, 5, 26, 10, 0, 0, tzinfo=timezone.utc)
        finding = _normalise_event(
            event_name="Converse",
            event_time=event_time,
            username=None,
            source_ip=None,
            user_agent=None,
            model_id=None,
            source="cloudtrail_lake",
        )
        assert "CloudTrail Lake" in finding["label"]


# ---------------------------------------------------------------------------
# fetch_cloudtrail_events — mocked boto3
# ---------------------------------------------------------------------------


class TestFetchCloudtrailEvents:
    def _make_paginator(self, pages: list[list[dict]]):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": p} for p in pages]
        return paginator

    def test_invoke_model_event_is_returned(self):
        ct_event = _make_ct_event(event_name="InvokeModel")
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_events(lookback_hours=1)

        assert len(findings) == 1
        assert findings[0]["event_name"] == "InvokeModel"
        assert findings[0]["provider"] == "bedrock"
        assert findings[0]["source"] == "cloudtrail_historical"

    def test_invoke_agent_event_is_returned(self):
        ct_event = _make_ct_event(event_name="InvokeAgent")
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_events(lookback_hours=1)

        assert len(findings) == 1
        assert findings[0]["event_name"] == "InvokeAgent"

    def test_non_invoke_events_are_filtered_out(self):
        ct_event = _make_ct_event(event_name="ListFoundationModels")
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_events(lookback_hours=1)

        assert findings == []

    def test_framework_detected_from_langchain_user_agent(self):
        ct_event = _make_ct_event(
            event_name="InvokeModel",
            user_agent="langchain-aws/0.1.0 Python/3.12.0 botocore/1.34.0",
        )
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_events()

        assert findings[0]["framework"] == "LangChain/LangGraph"

    def test_boto3_user_agent_framework(self):
        ct_event = _make_ct_event(
            event_name="InvokeModel",
            user_agent="Boto3/1.34.0 Python/3.12.0 botocore/1.34.0",
        )
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_events()

        assert findings[0]["framework"] == "AWS SDK (boto3)"

    def test_no_credentials_raises(self):
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = _NoCredentialsError()

        with _inject_boto3(mock_client):
            with pytest.raises(_NoCredentialsError):
                fetch_cloudtrail_events()

    def test_all_bedrock_invoke_event_names_pass_filter(self):
        for event_name in BEDROCK_INVOKE_EVENTS:
            ct_event = _make_ct_event(event_name=event_name)
            mock_client = MagicMock()
            mock_client.get_paginator.return_value = self._make_paginator([[ct_event]])
            with _inject_boto3(mock_client):
                findings = fetch_cloudtrail_events()
            assert len(findings) == 1, f"{event_name} should produce a finding"


# ---------------------------------------------------------------------------
# fetch_cloudtrail_lake_events — mocked boto3
# ---------------------------------------------------------------------------


class TestFetchCloudtrailLakeEvents:
    _ARN = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE-ARN"

    def _mock_client(self, rows: list):
        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-12345"}
        client.get_query_results.return_value = {
            "QueryStatus": "FINISHED",
            "QueryResultRows": rows,
        }
        return client

    def test_invoke_model_lake_event(self):
        mock_client = self._mock_client([_make_lake_row(event_name="InvokeModel")])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_lake_events(self._ARN)

        assert len(findings) == 1
        assert findings[0]["event_name"] == "InvokeModel"
        assert findings[0]["source"] == "cloudtrail_lake"
        assert findings[0]["provider"] == "bedrock"

    def test_non_invoke_events_filtered(self):
        mock_client = self._mock_client([_make_lake_row(event_name="ListFoundationModels")])

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_lake_events(self._ARN)

        assert findings == []

    def test_framework_from_lake_user_agent(self):
        mock_client = self._mock_client(
            [_make_lake_row(user_agent="langchain-aws/0.1.0 Python/3.12.0")]
        )

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_lake_events(self._ARN)

        assert findings[0]["framework"] == "LangChain/LangGraph"

    def test_model_id_extracted_from_request_parameters(self):
        mock_client = self._mock_client(
            [_make_lake_row(model_id="mistral.mistral-large-2402-v1:0")]
        )

        with _inject_boto3(mock_client):
            findings = fetch_cloudtrail_lake_events(self._ARN)

        assert findings[0]["model_id"] == "mistral.mistral-large-2402-v1:0"

    def test_query_timeout_raises_timeout_error(self):
        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-timeout"}
        client.get_query_results.return_value = {"QueryStatus": "RUNNING"}
        client.cancel_query.return_value = {}

        with _inject_boto3(client):
            with pytest.raises(TimeoutError):
                fetch_cloudtrail_lake_events(self._ARN, timeout_seconds=0)

    def test_query_failed_status_raises_runtime_error(self):
        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-fail"}
        client.get_query_results.return_value = {
            "QueryStatus": "FAILED",
            "QueryError": "Internal server error",
        }

        with _inject_boto3(client):
            with pytest.raises(RuntimeError, match="FAILED"):
                fetch_cloudtrail_lake_events(self._ARN)


# ---------------------------------------------------------------------------
# run_cloudtrail_detection — integration + graceful degradation
# ---------------------------------------------------------------------------


class TestRunCloudtrailDetection:
    def test_returns_empty_list_when_boto3_missing(self):
        no_modules = {"boto3": None, "botocore": None, "botocore.exceptions": None}
        with patch.dict("sys.modules", no_modules):
            findings = run_cloudtrail_detection(lookback_hours=1)
        assert findings == []

    def test_no_aws_credentials_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = _NoCredentialsError()

        with _inject_boto3(mock_client):
            findings = run_cloudtrail_detection(lookback_hours=1)

        assert findings == []

    def test_access_denied_returns_empty_list(self):
        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = _ClientError(error_response, "LookupEvents")

        with _inject_boto3(mock_client):
            findings = run_cloudtrail_detection(lookback_hours=1)

        assert findings == []

    def test_standard_cloudtrail_findings_returned(self):
        ct_event = _make_ct_event(event_name="InvokeModel")
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": [ct_event]}]
        mock_client = MagicMock()
        mock_client.get_paginator.return_value = paginator

        with _inject_boto3(mock_client):
            findings = run_cloudtrail_detection(lookback_hours=1)

        assert len(findings) == 1
        assert findings[0]["source"] == "cloudtrail_historical"

    def test_lake_findings_returned_when_arn_provided(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": []}]

        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-lake"}
        client.get_query_results.return_value = {
            "QueryStatus": "FINISHED",
            "QueryResultRows": [_make_lake_row(event_name="Converse")],
        }
        client.get_paginator.return_value = paginator

        with _inject_boto3(client):
            findings = run_cloudtrail_detection(
                lookback_hours=1,
                lake_arn="arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE",
            )

        lake_findings = [f for f in findings if f["source"] == "cloudtrail_lake"]
        assert len(lake_findings) >= 1

    def test_lake_timeout_falls_back_to_standard(self):
        """CloudTrail Lake timeout must not prevent standard CloudTrail from running."""
        ct_event = _make_ct_event(event_name="InvokeModel")
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": [ct_event]}]

        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-lake-timeout"}
        client.get_query_results.return_value = {"QueryStatus": "RUNNING"}
        client.cancel_query.return_value = {}
        client.get_paginator.return_value = paginator

        with _inject_boto3(client):
            findings = run_cloudtrail_detection(
                lookback_hours=1,
                lake_arn="arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE",
                lake_timeout_seconds=0,
            )

        assert any(f["source"] == "cloudtrail_historical" for f in findings)

    def test_zero_lookback_skips_cloudtrail(self):
        """lookback_hours=0 with no lake_arn should not call boto3 at all."""
        called = []

        def fake_boto3_client(*args, **kwargs):
            called.append(args)
            return MagicMock()

        mock_boto3 = MagicMock()
        mock_boto3.client.side_effect = fake_boto3_client
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.NoCredentialsError = _NoCredentialsError
        mock_botocore_exc.ClientError = _ClientError

        old = {k: sys.modules.pop(k) for k in ("boto3", "botocore", "botocore.exceptions")
               if k in sys.modules}
        sys.modules.update({
            "boto3": mock_boto3,
            "botocore": MagicMock(),
            "botocore.exceptions": mock_botocore_exc,
        })
        try:
            findings = run_cloudtrail_detection(lookback_hours=0)
        finally:
            for k in ("boto3", "botocore", "botocore.exceptions"):
                sys.modules.pop(k, None)
            sys.modules.update(old)

        assert findings == []
        assert called == []

    def test_deduplication_keeps_lake_entry_over_standard(self):
        """Same event in both Lake and standard CloudTrail → keep Lake, drop duplicate."""
        import json

        event_time = datetime(2026, 5, 26, 10, 0, 0, tzinfo=timezone.utc)
        username = "arn:aws:iam::123456789012:user/alice"

        lake_row = [
            {"eventName": "InvokeModel"},
            {"eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"userIdentity.arn": username},
            {"sourceIPAddress": "10.0.1.42"},
            {"userAgent": "boto3/1.34.0"},
            {"requestParameters": json.dumps({"modelId": "anthropic.claude-3-sonnet"})},
        ]

        raw = {
            "eventSource": "bedrock.amazonaws.com",
            "eventName": "InvokeModel",
            "eventTime": event_time.isoformat(),
            "sourceIPAddress": "10.0.1.42",
            "userAgent": "boto3/1.34.0",
            "userIdentity": {"arn": username},
            "requestParameters": {"modelId": "anthropic.claude-3-sonnet"},
        }
        ct_event = {
            "EventName": "InvokeModel",
            "EventTime": event_time,
            "Username": username,
            "CloudTrailEvent": json.dumps(raw),
        }

        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": [ct_event]}]

        client = MagicMock()
        client.start_query.return_value = {"QueryId": "q-dedup"}
        client.get_query_results.return_value = {
            "QueryStatus": "FINISHED",
            "QueryResultRows": [lake_row],
        }
        client.get_paginator.return_value = paginator

        with _inject_boto3(client):
            findings = run_cloudtrail_detection(
                lookback_hours=1,
                lake_arn="arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/EXAMPLE",
            )

        lake_count = sum(1 for f in findings if f["source"] == "cloudtrail_lake")
        standard_count = sum(1 for f in findings if f["source"] == "cloudtrail_historical")
        assert lake_count == 1
        assert standard_count == 0


# ---------------------------------------------------------------------------
# Integration — CloudTrail findings feed into correlate_bedrock_findings
# ---------------------------------------------------------------------------


class TestCloudtrailBedrockCorrelation:
    def test_cloudtrail_plus_layer1_bedrock_is_confirmed(self):
        from agent_discover_scanner.correlator import CorrelationEngine

        l1 = {
            "file_path": "app.py",
            "line": 10,
            "rule_id": "DAI007",
            "message": "AWS Bedrock boto3 client instantiation detected",
        }
        l2 = {
            "provider": "bedrock",
            "process_name": None,
            "source": "cloudtrail_historical",
            "event_name": "InvokeModel",
            "timestamp": "2026-05-26T10:00:00+00:00",
            "framework": "AWS SDK (boto3)",
        }
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1], layer2_findings=[l2]
        )
        assert len(items) == 1
        assert items[0].classification == "confirmed"

    def test_cloudtrail_only_no_layer1_is_ghost(self):
        from agent_discover_scanner.correlator import CorrelationEngine

        l2 = {
            "provider": "bedrock",
            "process_name": None,
            "source": "cloudtrail_lake",
            "event_name": "InvokeAgent",
            "timestamp": "2026-05-26T10:00:00+00:00",
            "framework": "Managed Bedrock Agent",
        }
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[], layer2_findings=[l2]
        )
        assert len(items) == 1
        assert items[0].classification == "ghost"
        assert items[0].risk_level == "critical"

    def test_langchain_framework_preserved_through_cloudtrail(self):
        from agent_discover_scanner.correlator import CorrelationEngine

        l1 = {
            "file_path": "agent.py",
            "line": 5,
            "rule_id": "DAI003",
            "message": "LangChain agent initialization detected",
        }
        l2 = {
            "provider": "bedrock",
            "process_name": None,
            "source": "cloudtrail_historical",
            "event_name": "InvokeModel",
            "timestamp": "2026-05-26T10:00:00+00:00",
            "framework": "LangChain/LangGraph",
        }
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1], layer2_findings=[l2]
        )
        assert items[0].framework in ("LangChain", "LangChain/LangGraph")
