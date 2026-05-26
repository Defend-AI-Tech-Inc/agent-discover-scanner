"""
CloudTrail and CloudTrail Lake detectors for AWS Bedrock Layer 2 discovery.

AWS Bedrock endpoints resolve to generic EC2 IPs after TLS; passive network
monitoring (psutil) is blind to Bedrock traffic. CloudTrail is the correct
alternative data source on any platform, and the only source with honest
framework attribution (via the UserAgent field captured at call time).

Two detectors are provided:
  fetch_cloudtrail_events()       — standard CloudTrail (5-15 min delay)
  fetch_cloudtrail_lake_events()  — CloudTrail Lake (~60 sec delay)

Both feed into Layer 2 via run_cloudtrail_detection(). Findings carry:
  source: "cloudtrail_historical"  (standard CloudTrail)
  source: "cloudtrail_lake"        (CloudTrail Lake)

Minimum IAM permissions:
  cloudtrail:LookupEvents
  cloudtrail:StartQuery          (Lake only)
  cloudtrail:GetQueryResults     (Lake only)
  cloudtrail:DescribeEventDataStores  (Lake only)
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Bedrock event names that indicate model or agent invocation
BEDROCK_INVOKE_EVENTS = frozenset({
    "InvokeModel",
    "InvokeAgent",
    "Converse",
    "ConverseStream",
    "InvokeModelWithResponseStream",
})

# UserAgent substrings → framework label
# Order matters: check most specific first.
# LangGraph routes through langchain-aws, so its UA is indistinguishable from
# plain LangChain at this layer. Layer 1 (DAI003) is the authoritative source
# for LangGraph-vs-LangChain distinction.
_UA_FRAMEWORK_MAP: list[tuple[str, str]] = [
    ("langchain-aws", "LangChain/LangGraph"),
    ("langchain_aws", "LangChain/LangGraph"),
    ("langchain", "LangChain"),
    ("amazon-bedrock-agent", "Managed Bedrock Agent"),
    ("bedrock-agent", "Managed Bedrock Agent"),
    ("boto3", "AWS SDK (boto3)"),
    ("aws-sdk", "AWS SDK"),
]


def _parse_framework_from_user_agent(user_agent: str) -> str:
    """
    Extract framework hint from a CloudTrail userAgent string.

    This is the only layer where framework-to-API-call attribution is honest:
    the HTTP User-Agent is captured by CloudTrail at the moment of the call.
    boto3 direct calls set "Boto3/x.y.z ..."; langchain-aws prefixes with its
    own package name. LangGraph calls go through langchain-aws, so they carry
    the same UA prefix as plain LangChain.
    """
    ua_lower = (user_agent or "").lower()
    for marker, label in _UA_FRAMEWORK_MAP:
        if marker in ua_lower:
            return label
    return "Unknown"


def _age_label(event_time: datetime) -> str:
    """Return a human-readable age string, e.g. '~8 min ago' or '~2h ago'."""
    now = datetime.now(timezone.utc)
    delta = now - event_time.astimezone(timezone.utc)
    total_seconds = max(0, int(delta.total_seconds()))
    if total_seconds < 90:
        return f"~{total_seconds}s ago"
    if total_seconds < 3600:
        return f"~{total_seconds // 60} min ago"
    return f"~{total_seconds // 3600}h ago"


def _build_label(
    event_name: str,
    framework: str,
    source: str,
    event_time: datetime,
) -> str:
    """
    Build the human-readable label for a CloudTrail Bedrock finding.

    Examples:
      "AWS Bedrock — InvokeModel via LangChain/LangGraph (CloudTrail historical, ~8 min ago)"
      "AWS Bedrock — InvokeAgent (CloudTrail Lake, ~45 sec ago)"
    """
    source_label = (
        "CloudTrail Lake" if source == "cloudtrail_lake" else "CloudTrail historical"
    )
    age = _age_label(event_time)
    if framework and framework not in ("Unknown", "AWS SDK (boto3)", "AWS SDK"):
        return f"AWS Bedrock — {event_name} via {framework} ({source_label}, {age})"
    return f"AWS Bedrock — {event_name} ({source_label}, {age})"


def _extract_model_id(ct_event_json: str) -> str | None:
    """
    Parse the raw CloudTrailEvent JSON blob and return the Bedrock model ID
    from requestParameters, if present.
    """
    try:
        raw = json.loads(ct_event_json)
        params = raw.get("requestParameters") or {}
        return (
            params.get("modelId")
            or params.get("model")
            or params.get("agentId")
            or None
        )
    except (json.JSONDecodeError, TypeError):
        return None


def _normalise_event(
    *,
    event_name: str,
    event_time: datetime,
    username: str | None,
    source_ip: str | None,
    user_agent: str | None,
    model_id: str | None,
    source: str,
) -> dict:
    """Return a Layer 2-compatible finding dict for a single CloudTrail event."""
    framework = _parse_framework_from_user_agent(user_agent or "")
    label = _build_label(event_name, framework, source, event_time)
    return {
        # Fields expected by CorrelationEngine.correlate()
        "provider": "bedrock",
        "process_name": None,  # CloudTrail has no process name
        "timestamp": event_time.isoformat(),
        # CloudTrail-specific metadata
        "source": source,
        "event_name": event_name,
        "username": username,
        "source_ip": source_ip,
        "model_id": model_id,
        "framework": framework,
        "user_agent": user_agent,
        "label": label,
    }


# ---------------------------------------------------------------------------
# Detector 1 — Standard CloudTrail
# ---------------------------------------------------------------------------


def fetch_cloudtrail_events(
    lookback_hours: int = 1,
    region: str | None = None,
) -> list[dict]:
    """
    Query CloudTrail LookupEvents for Bedrock invocation activity.

    Filters on EventSource=bedrock.amazonaws.com then post-filters to the
    subset of event names that indicate actual model/agent invocations.
    Returns a list of normalised Layer 2 findings.

    Raises CallerError (subclass of Exception) when boto3 is missing or
    credentials are absent/insufficient — callers must handle gracefully.
    """
    import boto3
    import botocore.exceptions  # type: ignore[import]

    _region = region or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    client = boto3.client("cloudtrail", region_name=_region)
    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    findings: list[dict] = []

    try:
        paginator = client.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=[{
                "AttributeKey": "EventSource",
                "AttributeValue": "bedrock.amazonaws.com",
            }],
            StartTime=start_time,
            PaginationConfig={"MaxItems": 200},
        )
        for page in pages:
            for ct_event in page.get("Events", []):
                event_name = ct_event.get("EventName") or ""
                if event_name not in BEDROCK_INVOKE_EVENTS:
                    continue

                event_time = ct_event.get("EventTime")
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time)
                if not isinstance(event_time, datetime):
                    continue

                raw_json = ct_event.get("CloudTrailEvent") or "{}"
                model_id = _extract_model_id(raw_json)

                # Extra fields from the raw CloudTrail JSON blob
                try:
                    raw = json.loads(raw_json)
                except (json.JSONDecodeError, TypeError):
                    raw = {}

                username = ct_event.get("Username") or raw.get("userIdentity", {}).get("arn")
                source_ip = raw.get("sourceIPAddress")
                user_agent = raw.get("userAgent")

                findings.append(_normalise_event(
                    event_name=event_name,
                    event_time=event_time,
                    username=username,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    model_id=model_id,
                    source="cloudtrail_historical",
                ))

    except botocore.exceptions.NoCredentialsError:
        raise
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "AuthFailure", "UnauthorizedOperation"):
            raise
        raise

    return findings


# ---------------------------------------------------------------------------
# Detector 2 — CloudTrail Lake
# ---------------------------------------------------------------------------


def fetch_cloudtrail_lake_events(
    event_data_store_arn: str,
    lookback_minutes: int = 60,
    region: str | None = None,
    timeout_seconds: int = 30,
) -> list[dict]:
    """
    Query CloudTrail Lake for near-real-time Bedrock invocation events.

    Starts a SQL query against the given event data store ARN and polls until
    FINISHED (or FAILED). Poll interval is 2 s; hard timeout is timeout_seconds.
    On timeout, cancels the query and raises TimeoutError.

    Returns a list of normalised Layer 2 findings with source="cloudtrail_lake".
    """
    import boto3
    import botocore.exceptions  # type: ignore[import]

    _region = region or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    client = boto3.client("cloudtrail", region_name=_region)

    now = datetime.now(timezone.utc)
    since_str = (now - timedelta(minutes=lookback_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    sql = (
        f"SELECT eventName, eventTime, userIdentity.arn, "
        f"sourceIPAddress, userAgent, requestParameters "
        f"FROM {event_data_store_arn} "
        f"WHERE eventSource = 'bedrock.amazonaws.com' "
        f"AND eventTime > '{since_str}' "
        f"ORDER BY eventTime DESC LIMIT 100"
    )

    try:
        start_resp = client.start_query(QueryStatement=sql)
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "AuthFailure"):
            raise
        raise

    query_id = start_resp["QueryId"]
    deadline = time.monotonic() + timeout_seconds
    final_rows: list[list] = []

    while time.monotonic() < deadline:
        try:
            result = client.get_query_results(
                EventDataStore=event_data_store_arn,
                QueryId=query_id,
            )
        except botocore.exceptions.ClientError:
            raise

        status = result.get("QueryStatus", "")
        if status == "FINISHED":
            final_rows = result.get("QueryResultRows", [])
            break
        if status in ("FAILED", "CANCELLED", "TIMED_OUT"):
            err = result.get("QueryError") or status
            raise RuntimeError(f"CloudTrail Lake query {status}: {err}")

        time.sleep(2)
    else:
        # Hard timeout — cancel and surface the failure gracefully
        try:
            client.cancel_query(
                EventDataStore=event_data_store_arn, QueryId=query_id
            )
        except Exception:
            pass
        raise TimeoutError(
            f"CloudTrail Lake query did not finish within {timeout_seconds}s"
        )

    findings: list[dict] = []
    for row in final_rows:
        # Each row is a list of single-key dicts: [{"eventName": "InvokeModel"}, ...]
        try:
            row_dict: dict[str, str] = {}
            for cell in row:
                if isinstance(cell, dict):
                    row_dict.update(cell)
        except Exception:
            continue

        event_name = row_dict.get("eventName") or ""
        if event_name not in BEDROCK_INVOKE_EVENTS:
            continue

        raw_time = row_dict.get("eventTime") or ""
        try:
            event_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        # requestParameters is a JSON-encoded string in Lake results
        model_id: str | None = None
        raw_params = row_dict.get("requestParameters") or "{}"
        try:
            params = json.loads(raw_params) if isinstance(raw_params, str) else raw_params
            model_id = params.get("modelId") or params.get("model") or params.get("agentId")
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        findings.append(_normalise_event(
            event_name=event_name,
            event_time=event_time,
            username=row_dict.get("userIdentity.arn"),
            source_ip=row_dict.get("sourceIPAddress"),
            user_agent=row_dict.get("userAgent"),
            model_id=model_id,
            source="cloudtrail_lake",
        ))

    return findings


# ---------------------------------------------------------------------------
# Top-level entry point used by scan_runner
# ---------------------------------------------------------------------------


def run_cloudtrail_detection(
    lookback_hours: int = 1,
    lake_arn: str | None = None,
    region: str | None = None,
    lake_timeout_seconds: int = 30,
) -> list[dict]:
    """
    Run CloudTrail (and optionally Lake) detection and return normalised findings.

    Precedence:
      1. If lake_arn provided → try Lake first (near-real-time).
      2. Always run standard CloudTrail as well (historical / fallback).
      3. Deduplicate: if the same (event_name, username, timestamp) appears in
         both, keep the Lake entry (more timely).

    Graceful degradation:
      - Missing boto3 → warning logged, empty list returned.
      - No AWS credentials → warning logged, empty list returned.
      - AccessDenied → warning logged, empty list returned.
      - Lake timeout or query failure → warning logged, fall back to standard.

    Never raises.
    """
    results: list[dict] = []
    lake_succeeded = False

    # --- Lake (near-real-time) ---
    if lake_arn:
        try:
            lake_findings = fetch_cloudtrail_lake_events(
                event_data_store_arn=lake_arn,
                lookback_minutes=lookback_hours * 60,
                region=region,
                timeout_seconds=lake_timeout_seconds,
            )
            results.extend(lake_findings)
            lake_succeeded = True
            logger.info(
                "CloudTrail Lake: %d Bedrock event(s) in last %dh",
                len(lake_findings),
                lookback_hours,
            )
        except ImportError:
            logger.warning(
                "boto3 not installed — CloudTrail Lake detection skipped"
            )
        except TimeoutError as exc:
            logger.warning(
                "CloudTrail Lake timed out (%s) — falling back to standard CloudTrail", exc
            )
        except Exception as exc:
            _code = getattr(getattr(exc, "response", {}), "get", lambda *a: None)(
                "Error", {}
            ).get("Code", "")
            if _code in ("AccessDeniedException", "AuthFailure"):
                logger.warning(
                    "CloudTrail Lake: insufficient permissions (%s) — skipping", _code
                )
            else:
                logger.warning("CloudTrail Lake detection failed: %s", exc)

    # --- Standard CloudTrail (historical) ---
    if not lake_succeeded or not lake_arn:
        # Always run standard if Lake failed or wasn't requested
        pass

    # Run standard CloudTrail unconditionally when lookback_hours > 0
    # (provides historical forensic data even when Lake is available)
    if lookback_hours > 0:
        try:
            ct_findings = fetch_cloudtrail_events(
                lookback_hours=lookback_hours,
                region=region,
            )
            logger.info(
                "CloudTrail: %d Bedrock event(s) in last %dh",
                len(ct_findings),
                lookback_hours,
            )
            # Deduplicate: skip standard findings that duplicate a Lake entry
            if lake_succeeded and results:
                lake_keys = {
                    (f.get("event_name"), f.get("username"), f.get("timestamp"))
                    for f in results
                }
                ct_findings = [
                    f for f in ct_findings
                    if (f.get("event_name"), f.get("username"), f.get("timestamp"))
                    not in lake_keys
                ]
            results.extend(ct_findings)
        except ImportError:
            logger.warning(
                "boto3 not installed — CloudTrail detection skipped"
            )
        except Exception as exc:
            _resp = getattr(exc, "response", None)
            if _resp:
                code = (_resp.get("Error") or {}).get("Code", "")
                if code in ("AccessDeniedException", "AuthFailure", "UnauthorizedOperation"):
                    logger.warning(
                        "CloudTrail: insufficient permissions (%s) — "
                        "grant cloudtrail:LookupEvents to enable Bedrock Layer 2 detection",
                        code,
                    )
                    return results
            if "NoCredentialsError" in type(exc).__name__ or "credentials" in str(exc).lower():
                logger.warning(
                    "CloudTrail: no AWS credentials found — "
                    "configure AWS_ACCESS_KEY_ID / AWS_PROFILE to enable Bedrock detection"
                )
                return results
            logger.warning("CloudTrail detection failed: %s", exc)

    return results
