"""
Zscaler Internet Access (ZIA) detector — Layer 5 SSE Proxy.

Queries Zscaler ZIA web transaction logs for connections to known LLM API
endpoints. Uses Zscaler's HMAC-based API key obfuscation algorithm, session
authentication, and the /api/v1/webTransactions/search endpoint.

Authentication flow:
  1. Obfuscate API key with current Unix timestamp (Zscaler algorithm).
  2. POST /api/v1/authenticatedSession → JSESSIONID session cookie.
  3. POST /api/v1/webTransactions/search with hostname filters and time range.
  4. DELETE /api/v1/authenticatedSession to log out.

Required environment variables (or constructor kwargs):
  ZSCALER_API_KEY   — raw API key from ZIA admin portal
  ZSCALER_USERNAME  — admin or service account username
  ZSCALER_PASSWORD  — password for the above account
  ZSCALER_TENANT    — tenant hostname prefix, e.g. "zsapi" → zsapi.zscaler.net

IAM / Role requirements:
  Read access to ZIA web transaction logs (auditor or read-only admin role).

The canonical LLM hostname list is imported from
agent_discover_scanner.correlator.LLM_HOSTNAME_TO_PROVIDER so that Zscaler
and the network monitor always share a single source of truth.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

from agent_discover_scanner.detectors.sse_proxy.base import SSEProxyDetector, SSEProxyFinding

logger = logging.getLogger(__name__)

# Provider identifiers to skip: browser frontends generate a lot of traffic
# from non-API paths; we include them anyway for completeness — governance
# teams want to know about browser-based AI usage too.
_SKIP_PROVIDERS: frozenset[str] = frozenset()   # nothing skipped by default


def _obfuscate_api_key(api_key: str, timestamp_ms: int) -> str:
    """
    Apply Zscaler's timestamp-based API key obfuscation.

    This is the canonical algorithm from the Zscaler ZIA API documentation
    and the official Zscaler Python SDK (zscaler-sdk-python). It is required
    for all /api/v1/authenticatedSession calls.

    Args:
        api_key:      Raw API key string from the ZIA admin portal.
        timestamp_ms: Current Unix timestamp in milliseconds.

    Returns:
        Obfuscated key string to pass as "apiKey" in the auth payload.
    """
    ts = str(timestamp_ms)
    # Use last 6 digits of the millisecond timestamp
    high = ts[-6:]
    # Right-shift the high block by 1 to derive the low block
    low = str(int(high) >> 1)

    obfuscated = ""
    for ch in high:
        obfuscated += api_key[int(ch)]
    for ch in low:
        obfuscated += api_key[int(ch) + 2]
    return obfuscated


def _build_llm_hostnames() -> list[tuple[str, str]]:
    """
    Return the canonical (hostname_fragment, provider) list from the correlator.

    Importing lazily at call time avoids circular imports at module load.
    """
    try:
        from agent_discover_scanner.correlator import LLM_HOSTNAME_TO_PROVIDER
        return list(LLM_HOSTNAME_TO_PROVIDER)
    except Exception:
        # Fallback minimal list if correlator cannot be imported
        return [
            ("api.openai.com", "openai"),
            ("api.anthropic.com", "anthropic"),
            ("generativelanguage.googleapis.com", "google"),
            ("api.mistral.ai", "mistral"),
            ("api.cohere.com", "cohere"),
            ("bedrock-runtime.", "bedrock"),
            ("api.groq.com", "groq"),
            ("api.deepseek.com", "deepseek"),
        ]


def _provider_for_hostname(host: str) -> str | None:
    """Return the LLM provider for a destination hostname, or None if not an LLM host."""
    host_lower = (host or "").lower()
    for fragment, provider in _build_llm_hostnames():
        if fragment in host_lower:
            return provider
    return None


class ZscalerZIADetector(SSEProxyDetector):
    """
    Layer 5 SSE Proxy detector for Zscaler Internet Access (ZIA).

    Queries ZIA web transaction logs for connections to known LLM API endpoints
    and returns normalised SSEProxyFinding instances.

    Credentials precedence (each kwarg overrides the corresponding env var):
      api_key  → ZSCALER_API_KEY
      username → ZSCALER_USERNAME
      password → ZSCALER_PASSWORD
      tenant   → ZSCALER_TENANT   (e.g. "acme" → https://acme.zsapi.net)
    """

    provider = "zscaler"

    _DEFAULT_BASE_URL_TEMPLATE = "https://{tenant}.zsapi.net/api/v1"

    def __init__(
        self,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        tenant: str | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("ZSCALER_API_KEY") or ""
        self._username = username or os.environ.get("ZSCALER_USERNAME") or ""
        self._password = password or os.environ.get("ZSCALER_PASSWORD") or ""
        self._tenant = tenant or os.environ.get("ZSCALER_TENANT") or ""

    def is_available(self) -> bool:
        """Return True when all four required credentials are present."""
        return bool(self._api_key and self._username and self._password and self._tenant)

    def _base_url(self) -> str:
        return self._DEFAULT_BASE_URL_TEMPLATE.format(tenant=self._tenant)

    def _authenticate(self, client) -> str | None:
        """
        Authenticate with ZIA and return the JSESSIONID cookie value.

        Returns None if authentication fails so that callers can fall back
        gracefully instead of raising.
        """
        timestamp_ms = int(time.time() * 1000)
        obfuscated = _obfuscate_api_key(self._api_key, timestamp_ms)
        payload = {
            "apiKey": obfuscated,
            "username": self._username,
            "password": self._password,
            "timestamp": str(timestamp_ms),
        }
        try:
            resp = client.post(
                f"{self._base_url()}/authenticatedSession",
                json=payload,
                timeout=15,
            )
            if resp.status_code == 200:
                jsessionid = resp.cookies.get("JSESSIONID")
                return jsessionid
            logger.warning(
                "ZscalerZIA: authentication failed (HTTP %d): %s",
                resp.status_code,
                resp.text[:200],
            )
            return None
        except Exception as exc:
            logger.warning("ZscalerZIA: authentication error: %s", exc)
            return None

    def _logout(self, client) -> None:
        try:
            client.delete(f"{self._base_url()}/authenticatedSession", timeout=10)
        except Exception:
            pass

    def _search_transactions(
        self,
        client,
        start_time: datetime,
        end_time: datetime,
        hostname_fragment: str,
    ) -> list[dict]:
        """
        Search ZIA web transaction logs for a single hostname fragment.

        Returns a list of raw transaction dicts (empty list on any error).
        """
        payload = {
            "startTime": int(start_time.timestamp() * 1000),
            "endTime": int(end_time.timestamp() * 1000),
            "page": 1,
            "limit": 500,
            "filters": [
                {
                    "field": "hostname",
                    "operator": "CONTAINS",
                    "value": hostname_fragment,
                }
            ],
        }
        try:
            resp = client.post(
                f"{self._base_url()}/webTransactions/search",
                json=payload,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("webTransactions") or data.get("items") or []
            logger.debug(
                "ZscalerZIA: transaction search returned HTTP %d for %s",
                resp.status_code,
                hostname_fragment,
            )
            return []
        except Exception as exc:
            logger.debug("ZscalerZIA: transaction search error (%s): %s", hostname_fragment, exc)
            return []

    def _parse_transaction(self, txn: dict, provider: str) -> SSEProxyFinding | None:
        """Convert a raw ZIA transaction dict to an SSEProxyFinding."""
        try:
            # ZIA uses millisecond timestamps
            ts_raw = txn.get("time") or txn.get("timestamp") or 0
            if isinstance(ts_raw, (int, float)) and ts_raw > 1e10:
                # milliseconds → datetime
                event_time = datetime.fromtimestamp(ts_raw / 1000, tz=timezone.utc)
            elif isinstance(ts_raw, str):
                event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            else:
                event_time = datetime.now(timezone.utc)

            hostname = (
                txn.get("hostname")
                or txn.get("serverHostname")
                or txn.get("host")
                or ""
            )
            username = (
                txn.get("login")
                or txn.get("user")
                or txn.get("userName")
                or txn.get("clientSrcUser")
                or "unknown"
            )
            src_ip = (
                txn.get("clientSrcIp")
                or txn.get("srcIp")
                or txn.get("srcIP")
                or "0.0.0.0"
            )
            action = (txn.get("action") or txn.get("policy") or "ALLOWED").upper()

            return SSEProxyFinding(
                provider=provider,
                source="zscaler_zia",
                event_time=event_time,
                username=str(username),
                source_ip=str(src_ip),
                destination_host=str(hostname),
                action=action,
            )
        except Exception as exc:
            logger.debug("ZscalerZIA: failed to parse transaction: %s — %r", exc, txn)
            return None

    def detect(self, hours_back: int) -> list[SSEProxyFinding]:
        """
        Query ZIA web transaction logs for LLM API calls.

        Iterates through all known LLM hostname fragments, makes one search
        request per fragment, parses results, deduplicates, and returns
        normalised SSEProxyFinding instances.
        """
        import httpx

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours_back)
        findings: list[SSEProxyFinding] = []
        seen_keys: set[tuple] = set()

        with httpx.Client(verify=True) as client:
            jsessionid = self._authenticate(client)
            if not jsessionid:
                raise PermissionError(
                    "ZscalerZIA: could not authenticate — check ZSCALER_API_KEY, "
                    "ZSCALER_USERNAME, ZSCALER_PASSWORD, and ZSCALER_TENANT"
                )

            client.cookies.set("JSESSIONID", jsessionid, domain=f"{self._tenant}.zsapi.net")

            try:
                llm_hosts = _build_llm_hostnames()
                # Only query API-endpoint hostname fragments (skip browser
                # frontends that are pure web apps — too noisy in proxy logs).
                # Actually include everything: governance teams want full visibility.
                for fragment, provider in llm_hosts:
                    if provider in _SKIP_PROVIDERS:
                        continue
                    txns = self._search_transactions(client, start_time, now, fragment)
                    for txn in txns:
                        finding = self._parse_transaction(txn, provider)
                        if finding is None:
                            continue
                        # Deduplicate on (username, destination_host, timestamp minute)
                        dedup_key = (
                            finding.username,
                            finding.destination_host,
                            finding.event_time.replace(second=0, microsecond=0),
                        )
                        if dedup_key in seen_keys:
                            continue
                        seen_keys.add(dedup_key)
                        findings.append(finding)
            finally:
                self._logout(client)

        logger.info("ZscalerZIA: %d LLM-related transaction(s) found", len(findings))
        return findings
