"""
Palo Alto Networks Prisma Access / Cortex Data Lake detector — Layer 5 SSE Proxy.

Queries Prisma Access firewall traffic logs via the Cortex Data Lake (CDL)
Query API for connections to known LLM API endpoints.

Authentication flow:
  1. POST OAuth2 client credentials grant to PAN auth endpoint → access_token.
  2. POST /query/v1/jobs to start a CDL SQL query against firewall.traffic.
  3. Poll GET /query/v1/jobs/{job_id} until DONE / FAILED.
  4. Iterate paginated GET /query/v1/jobs/{job_id}/results.

Required environment variables (or constructor kwargs):
  PRISMA_CLIENT_ID      — OAuth2 client ID from Prisma Access hub
  PRISMA_CLIENT_SECRET  — OAuth2 client secret
  PRISMA_TENANT_ID      — Tenant Service Group (TSG) ID
  PRISMA_REGION         — CDL region: "us", "eu", "uk", "sg", "ca", "jp", "au"

Cortex Data Lake regions and their API base URLs:
  us  → api.us.cdl.paloaltonetworks.com
  eu  → api.eu.cdl.paloaltonetworks.com
  uk  → api.uk.cdl.paloaltonetworks.com
  sg  → api.sg.cdl.paloaltonetworks.com
  ca  → api.ca.cdl.paloaltonetworks.com
  jp  → api.jp.cdl.paloaltonetworks.com
  au  → api.au.cdl.paloaltonetworks.com
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

from agent_discover_scanner.detectors.sse_proxy.base import SSEProxyDetector, SSEProxyFinding

logger = logging.getLogger(__name__)

_AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
_CDL_BASE_TEMPLATE = "https://api.{region}.cdl.paloaltonetworks.com"

_CDL_REGIONS: frozenset[str] = frozenset({"us", "eu", "uk", "sg", "ca", "jp", "au"})

_POLL_INTERVAL_SEC = 3
_POLL_MAX_ATTEMPTS = 20  # 60 seconds max


def _build_llm_hostnames() -> list[tuple[str, str]]:
    """Return canonical (hostname_fragment, provider) list from the correlator."""
    try:
        from agent_discover_scanner.correlator import LLM_HOSTNAME_TO_PROVIDER
        return list(LLM_HOSTNAME_TO_PROVIDER)
    except Exception:
        return [
            ("api.openai.com", "openai"),
            ("api.anthropic.com", "anthropic"),
            ("generativelanguage.googleapis.com", "google"),
            ("api.mistral.ai", "mistral"),
            ("api.cohere.com", "cohere"),
            ("bedrock-runtime.", "bedrock"),
            ("api.groq.com", "groq"),
        ]


def _provider_for_hostname(host: str) -> str | None:
    """Return the LLM provider for a destination hostname, or None."""
    host_lower = (host or "").lower()
    for fragment, provider in _build_llm_hostnames():
        if fragment in host_lower:
            return provider
    return None


def _build_sql(start_iso: str, end_iso: str, llm_hostnames: list[tuple[str, str]]) -> str:
    """
    Build the CDL SQL query filtering traffic logs by LLM destination hostnames.

    Uses the firewall.traffic dataset with LIKE conditions for each known LLM
    hostname fragment. Returns up to 1 000 rows ordered by most recent first.
    """
    conditions = " OR ".join(
        f"dst_hostname LIKE '%{fragment}%'"
        for fragment, _ in llm_hostnames
        if fragment and "%" not in fragment  # safety: skip any fragment with wildcards
    )
    if not conditions:
        conditions = "FALSE"
    return (
        f"SELECT time_generated, src_user, src_ip, dst_hostname, app, action "
        f"FROM `firewall.traffic` "
        f"WHERE time_generated >= '{start_iso}' "
        f"AND time_generated <= '{end_iso}' "
        f"AND ({conditions}) "
        f"ORDER BY time_generated DESC "
        f"LIMIT 1000"
    )


class PrismaAccessDetector(SSEProxyDetector):
    """
    Layer 5 SSE Proxy detector for Palo Alto Networks Prisma Access.

    Queries Cortex Data Lake (CDL) firewall traffic logs for connections to
    known LLM API endpoints and returns normalised SSEProxyFinding instances.

    Credentials precedence (each kwarg overrides the corresponding env var):
      client_id     → PRISMA_CLIENT_ID
      client_secret → PRISMA_CLIENT_SECRET
      tenant_id     → PRISMA_TENANT_ID
      region        → PRISMA_REGION  (default: "us")
    """

    provider = "prisma"

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        tenant_id: str | None = None,
        region: str | None = None,
    ) -> None:
        self._client_id = client_id or os.environ.get("PRISMA_CLIENT_ID") or ""
        self._client_secret = client_secret or os.environ.get("PRISMA_CLIENT_SECRET") or ""
        self._tenant_id = tenant_id or os.environ.get("PRISMA_TENANT_ID") or ""
        _region_raw = region or os.environ.get("PRISMA_REGION") or "us"
        self._region = _region_raw.lower().strip()

    def is_available(self) -> bool:
        """Return True when client_id, client_secret, and tenant_id are all present."""
        return bool(self._client_id and self._client_secret and self._tenant_id)

    def _cdl_base(self) -> str:
        """Return the CDL API base URL for the configured region."""
        region = self._region if self._region in _CDL_REGIONS else "us"
        return _CDL_BASE_TEMPLATE.format(region=region)

    def _get_access_token(self, client) -> str:
        """
        Obtain an OAuth2 access token via client credentials grant.

        Raises RuntimeError if the token exchange fails.
        """
        scope = f"tsg_id:{self._tenant_id}"
        resp = client.post(
            _AUTH_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"PrismaAccess: OAuth2 token exchange failed "
                f"(HTTP {resp.status_code}): {resp.text[:200]}"
            )
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("PrismaAccess: OAuth2 response missing access_token")
        return token

    def _start_query(self, client, token: str, sql: str) -> str:
        """Submit a CDL SQL query and return the job ID."""
        base = self._cdl_base()
        resp = client.post(
            f"{base}/query/v1/jobs",
            json={"query": sql, "dialect": "csql"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=20,
        )
        if resp.status_code not in (200, 201, 202):
            raise RuntimeError(
                f"PrismaAccess: CDL query start failed "
                f"(HTTP {resp.status_code}): {resp.text[:200]}"
            )
        data = resp.json()
        job_id = data.get("jobId") or data.get("id") or data.get("queryId")
        if not job_id:
            raise RuntimeError("PrismaAccess: CDL query response missing job ID")
        return str(job_id)

    def _poll_job(self, client, token: str, job_id: str) -> None:
        """
        Poll until the CDL query job is DONE.

        Raises RuntimeError on FAILED status or TimeoutError when
        _POLL_MAX_ATTEMPTS is exhausted.
        """
        base = self._cdl_base()
        for attempt in range(_POLL_MAX_ATTEMPTS):
            resp = client.get(
                f"{base}/query/v1/jobs/{job_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"PrismaAccess: CDL job poll failed (HTTP {resp.status_code})"
                )
            status = resp.json().get("status") or resp.json().get("state") or ""
            status_upper = status.upper()
            if status_upper in ("DONE", "SUCCEEDED", "FINISHED", "COMPLETE"):
                return
            if status_upper in ("FAILED", "ERROR", "CANCELLED"):
                raise RuntimeError(f"PrismaAccess: CDL query {status}: {resp.text[:200]}")
            time.sleep(_POLL_INTERVAL_SEC)
        raise TimeoutError(
            f"PrismaAccess: CDL query {job_id} did not complete within "
            f"{_POLL_MAX_ATTEMPTS * _POLL_INTERVAL_SEC}s"
        )

    def _fetch_results(self, client, token: str, job_id: str) -> list[dict]:
        """Fetch all paginated result rows from a completed CDL query job."""
        base = self._cdl_base()
        all_rows: list[dict] = []
        page_token: str | None = None

        while True:
            params: dict = {"maxResults": 1000}
            if page_token:
                params["pageToken"] = page_token
            resp = client.get(
                f"{base}/query/v1/jobs/{job_id}/results",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                timeout=30,
            )
            if resp.status_code != 200:
                logger.warning(
                    "PrismaAccess: results fetch failed (HTTP %d)", resp.status_code
                )
                break
            data = resp.json()
            rows = data.get("results") or data.get("rows") or []
            all_rows.extend(rows)
            page_token = data.get("nextPageToken") or data.get("pageToken")
            if not page_token or not rows:
                break

        return all_rows

    def _parse_row(self, row: dict) -> SSEProxyFinding | None:
        """Convert a CDL firewall.traffic row to an SSEProxyFinding."""
        try:
            dst_host = (
                row.get("dst_hostname")
                or row.get("destinationHostname")
                or row.get("dst_ip")
                or ""
            )
            provider = _provider_for_hostname(dst_host)
            if provider is None:
                return None  # Not an LLM destination

            ts_raw = row.get("time_generated") or row.get("timestamp") or ""
            if isinstance(ts_raw, str) and ts_raw:
                try:
                    event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except ValueError:
                    event_time = datetime.now(timezone.utc)
            elif isinstance(ts_raw, (int, float)) and ts_raw > 0:
                event_time = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            else:
                event_time = datetime.now(timezone.utc)

            username = (
                row.get("src_user")
                or row.get("srcUser")
                or row.get("source_user")
                or "unknown"
            )
            src_ip = (
                row.get("src_ip")
                or row.get("srcIp")
                or row.get("sourceAddress")
                or "0.0.0.0"
            )
            action = (row.get("action") or "ALLOW").upper()

            return SSEProxyFinding(
                provider=provider,
                source="prisma_access",
                event_time=event_time,
                username=str(username),
                source_ip=str(src_ip),
                destination_host=str(dst_host),
                action=action,
            )
        except Exception as exc:
            logger.debug("PrismaAccess: failed to parse row: %s — %r", exc, row)
            return None

    def detect(self, hours_back: int) -> list[SSEProxyFinding]:
        """
        Query Cortex Data Lake firewall traffic for LLM API calls.

        Executes a single CDL SQL query that covers all known LLM hostname
        fragments, polls until complete, parses and deduplicates results.
        """
        import httpx

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours_back)
        start_iso = start_time.strftime("%Y-%m-%d %H:%M:%S")
        end_iso = now.strftime("%Y-%m-%d %H:%M:%S")

        llm_hosts = _build_llm_hostnames()
        sql = _build_sql(start_iso, end_iso, llm_hosts)

        findings: list[SSEProxyFinding] = []
        seen_keys: set[tuple] = set()

        with httpx.Client(verify=True) as client:
            token = self._get_access_token(client)
            job_id = self._start_query(client, token, sql)
            logger.info("PrismaAccess: started CDL query job %s", job_id)
            self._poll_job(client, token, job_id)
            rows = self._fetch_results(client, token, job_id)

        for row in rows:
            finding = self._parse_row(row)
            if finding is None:
                continue
            dedup_key = (
                finding.username,
                finding.destination_host,
                finding.event_time.replace(second=0, microsecond=0),
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            findings.append(finding)

        logger.info("PrismaAccess: %d LLM-related finding(s)", len(findings))
        return findings
