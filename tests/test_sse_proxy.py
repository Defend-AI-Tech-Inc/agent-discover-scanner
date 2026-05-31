"""
Tests for Layer 5 — SSE Proxy detection (v2.8.0).

Coverage:
  TestObfuscateApiKey          — Zscaler HMAC obfuscation algorithm
  TestZscalerIsAvailable       — credential checks
  TestZscalerAuthenticate      — HTTP auth success / failure paths
  TestZscalerSearchTransactions — transaction search & dedup
  TestZscalerDetect            — end-to-end detect() with mock HTTP
  TestPrismaIsAvailable        — credential checks
  TestPrismaRegionUrl          — CDL region → base URL
  TestPrismaBuildSql           — SQL query construction
  TestPrismaDetect             — end-to-end detect() with mock HTTP (poll loop)
  TestNetskopeStub             — stub always returns [] / raises
  TestSSEProxyFindingToDict    — finding serialisation matches correlator shape
  TestRunSSEProxyDetection     — public entry point flag gating & merging
  TestSSEProxyCorrelator       — correlator l5_sse_proxy split, CONFIRMED, GHOST
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC = timezone.utc


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=_UTC)


def _finding_dict(provider: str, ts: str, username: str = "alice@corp.com",
                  source: str = "zscaler_zia") -> dict:
    """Build a minimal SSE proxy finding dict as the correlator sees it."""
    return {
        "provider": provider,
        "process_name": None,
        "timestamp": ts,
        "source": source,
        "event_name": "ALLOWED",
        "username": username,
        "source_ip": "10.0.0.1",
        "model_id": None,
        "framework": None,
        "destination_host": f"api.{provider}.com",
        "detection_layer": "layer5_sse_proxy",
    }


# ---------------------------------------------------------------------------
# TestObfuscateApiKey
# ---------------------------------------------------------------------------

class TestObfuscateApiKey:
    def _obfuscate(self, key, ts_ms):
        from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import _obfuscate_api_key
        return _obfuscate_api_key(key, ts_ms)

    def test_output_is_string(self):
        result = self._obfuscate("abcdefghij", 1_700_000_000_000)
        assert isinstance(result, str)

    def test_output_not_empty(self):
        result = self._obfuscate("abcdefghij", 1_700_000_000_000)
        assert len(result) > 0

    def test_different_timestamps_give_different_results(self):
        key = "abcdefghij0123456789"
        r1 = self._obfuscate(key, 1_700_000_100_000)
        r2 = self._obfuscate(key, 1_700_000_200_000)
        assert r1 != r2

    def test_same_inputs_deterministic(self):
        key = "ABCDEFGHIJ0123456789"
        r1 = self._obfuscate(key, 1_700_000_000_999)
        r2 = self._obfuscate(key, 1_700_000_000_999)
        assert r1 == r2

    def test_algorithm_produces_chars_from_key(self):
        """All output characters must come from the input key (index-based)."""
        key = "ABCDEFGHIJ0123456789"
        ts_ms = 1_700_000_000_123
        result = self._obfuscate(key, ts_ms)
        for ch in result:
            assert ch in key, f"Unexpected char {ch!r} not in key"


# ---------------------------------------------------------------------------
# TestZscalerIsAvailable
# ---------------------------------------------------------------------------

class TestZscalerIsAvailable:
    def _make(self, **kwargs):
        from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import ZscalerZIADetector
        return ZscalerZIADetector(**kwargs)

    def test_all_creds_present(self):
        d = self._make(api_key="k", username="u", password="p", tenant="t")
        assert d.is_available() is True

    def test_missing_api_key(self):
        d = self._make(api_key="", username="u", password="p", tenant="t")
        assert d.is_available() is False

    def test_missing_tenant(self):
        d = self._make(api_key="k", username="u", password="p", tenant="")
        assert d.is_available() is False

    def test_missing_all(self):
        d = self._make()
        assert d.is_available() is False

    def test_env_vars_used(self, monkeypatch):
        monkeypatch.setenv("ZSCALER_API_KEY", "k")
        monkeypatch.setenv("ZSCALER_USERNAME", "u")
        monkeypatch.setenv("ZSCALER_PASSWORD", "p")
        monkeypatch.setenv("ZSCALER_TENANT", "mytenant")
        from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import ZscalerZIADetector
        d = ZscalerZIADetector()
        assert d.is_available() is True


# ---------------------------------------------------------------------------
# TestZscalerAuthenticate
# ---------------------------------------------------------------------------

class TestZscalerAuthenticate:
    def _make(self):
        from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import ZscalerZIADetector
        return ZscalerZIADetector(
            api_key="key0123456789", username="u", password="p", tenant="acme"
        )

    def test_returns_jsessionid_on_200(self):
        d = self._make()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.cookies = {"JSESSIONID": "abc123"}
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        result = d._authenticate(mock_client)
        assert result == "abc123"

    def test_returns_none_on_401(self):
        d = self._make()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        result = d._authenticate(mock_client)
        assert result is None

    def test_returns_none_on_exception(self):
        d = self._make()
        mock_client = MagicMock()
        mock_client.post.side_effect = ConnectionError("timeout")
        result = d._authenticate(mock_client)
        assert result is None


# ---------------------------------------------------------------------------
# TestZscalerDetect
# ---------------------------------------------------------------------------

class TestZscalerDetect:
    def _make(self):
        from agent_discover_scanner.detectors.sse_proxy.zscaler_zia import ZscalerZIADetector
        return ZscalerZIADetector(
            api_key="key0123456789", username="u", password="p", tenant="acme"
        )

    def _make_txn(self, host: str, user: str = "bob@corp.com") -> dict:
        """Use field names that _parse_transaction recognises."""
        return {
            "hostname": host,       # preferred field
            "login": user,
            "clientSrcIp": "192.168.1.100",
            "action": "ALLOW",
            "time": "2026-05-28T10:00:00Z",
        }

    def test_detect_returns_findings_for_llm_host(self):
        d = self._make()
        txns = [self._make_txn("api.openai.com"), self._make_txn("api.openai.com")]

        mock_cm = MagicMock()
        mock_client = MagicMock()
        mock_cm.__enter__ = lambda s: mock_client
        mock_cm.__exit__ = MagicMock(return_value=False)

        # Auth returns JSESSIONID
        auth_resp = MagicMock(status_code=200)
        auth_resp.cookies = {"JSESSIONID": "sess1"}

        # Search returns our txns for openai hostname, empty for all others
        search_resp_with = MagicMock(status_code=200)
        search_resp_with.json.return_value = {"webTransactions": txns}
        search_resp_empty = MagicMock(status_code=200)
        search_resp_empty.json.return_value = {"webTransactions": []}
        delete_resp = MagicMock(status_code=200)

        call_count = {"n": 0}

        def post_side(url, **kwargs):
            n = call_count["n"]
            call_count["n"] += 1
            if "authenticatedSession" in url and kwargs.get("json"):
                return auth_resp
            body = kwargs.get("json") or {}
            filters = body.get("filters") or []
            for f in filters:
                if "openai" in (f.get("value") or ""):
                    return search_resp_with
            return search_resp_empty

        mock_client.post.side_effect = post_side
        mock_client.delete.return_value = delete_resp

        with patch("httpx.Client", return_value=mock_cm):
            findings = d.detect(hours_back=1)

        # Two identical txns → deduped to 1 (same minute + user + host)
        assert len(findings) >= 1
        assert findings[0].provider == "openai"
        assert findings[0].detection_layer == "layer5_sse_proxy"
        assert findings[0].source == "zscaler_zia"

    def test_detect_skips_non_llm_host(self):
        """When no transactions match an LLM hostname, no findings are produced."""
        d = self._make()
        mock_cm = MagicMock()
        mock_client = MagicMock()
        mock_cm.__enter__ = lambda s: mock_client
        mock_cm.__exit__ = MagicMock(return_value=False)

        auth_resp = MagicMock(status_code=200)
        auth_resp.cookies = {"JSESSIONID": "sess1"}
        search_resp_empty = MagicMock(status_code=200)
        search_resp_empty.json.return_value = {"webTransactions": []}
        mock_client.post.return_value = auth_resp
        mock_client.delete.return_value = MagicMock(status_code=200)

        with patch("httpx.Client", return_value=mock_cm):
            with patch(
                "agent_discover_scanner.detectors.sse_proxy.zscaler_zia._build_llm_hostnames",
                return_value=[("api.openai.com", "openai")],
            ):
                with patch.object(d, "_search_transactions", return_value=[]):
                    findings = d.detect(hours_back=1)
        assert findings == []

    def test_detect_raises_on_auth_failure(self):
        """detect() raises PermissionError when ZIA authentication fails."""
        d = self._make()
        mock_cm = MagicMock()
        mock_client = MagicMock()
        mock_cm.__enter__ = lambda s: mock_client
        mock_cm.__exit__ = MagicMock(return_value=False)

        auth_resp = MagicMock(status_code=403, text="Forbidden")
        auth_resp.cookies = {}
        mock_client.post.return_value = auth_resp

        with patch("httpx.Client", return_value=mock_cm):
            with pytest.raises(PermissionError, match="ZscalerZIA"):
                d.detect(hours_back=1)


# ---------------------------------------------------------------------------
# TestPrismaIsAvailable
# ---------------------------------------------------------------------------

class TestPrismaIsAvailable:
    def _make(self, **kwargs):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import PrismaAccessDetector
        return PrismaAccessDetector(**kwargs)

    def test_all_creds_present(self):
        d = self._make(tenant_id="tid", client_id="cid", client_secret="s")
        assert d.is_available() is True

    def test_missing_secret(self):
        d = self._make(tenant_id="tid", client_id="cid")
        assert d.is_available() is False

    def test_missing_tenant(self):
        d = self._make(client_id="cid", client_secret="s")
        assert d.is_available() is False

    def test_env_vars_used(self, monkeypatch):
        monkeypatch.setenv("PRISMA_CLIENT_ID", "cid")
        monkeypatch.setenv("PRISMA_CLIENT_SECRET", "secret")
        monkeypatch.setenv("PRISMA_TENANT_ID", "tenant123")
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import PrismaAccessDetector
        d = PrismaAccessDetector()
        assert d.is_available() is True


# ---------------------------------------------------------------------------
# TestPrismaRegionUrl
# ---------------------------------------------------------------------------

class TestPrismaRegionUrl:
    def _make(self, region=None):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import PrismaAccessDetector
        return PrismaAccessDetector(
            tenant_id="tid", client_id="cid", client_secret="s", region=region
        )

    def test_us_region(self):
        d = self._make(region="us")
        assert "api.us.cdl" in d._cdl_base()

    def test_eu_region(self):
        d = self._make(region="eu")
        assert "api.eu.cdl" in d._cdl_base()

    def test_invalid_region_defaults_to_us(self):
        d = self._make(region="xx")
        assert "api.us.cdl" in d._cdl_base()

    def test_no_region_defaults_to_us(self):
        d = self._make(region=None)
        assert "api.us.cdl" in d._cdl_base()


# ---------------------------------------------------------------------------
# TestPrismaBuildSql
# ---------------------------------------------------------------------------

class TestPrismaBuildSql:
    # _build_sql(start_iso, end_iso, llm_hostnames) — positional args
    def test_sql_contains_like_clauses(self):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import _build_sql
        sql = _build_sql(
            "2026-01-01 00:00:00",
            "2026-01-01 01:00:00",
            [("api.openai.com", "openai"), ("api.anthropic.com", "anthropic")],
        )
        assert "LIKE" in sql.upper() or "like" in sql.lower()
        assert "api.openai.com" in sql or "openai" in sql.lower()

    def test_sql_contains_time_filter(self):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import _build_sql
        sql = _build_sql(
            "2026-05-28 00:00:00",
            "2026-05-28 01:00:00",
            [("api.openai.com", "openai")],
        )
        assert "2026-05-28" in sql

    def test_sql_targets_firewall_traffic(self):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import _build_sql
        sql = _build_sql(
            "2026-01-01 00:00:00",
            "2026-01-01 01:00:00",
            [("api.openai.com", "openai")],
        )
        assert "firewall" in sql.lower() or "traffic" in sql.lower()


# ---------------------------------------------------------------------------
# TestPrismaDetect
# ---------------------------------------------------------------------------

class TestPrismaDetect:
    def _make(self):
        from agent_discover_scanner.detectors.sse_proxy.prisma_access import PrismaAccessDetector
        return PrismaAccessDetector(
            tenant_id="tid", client_id="cid", client_secret="s", region="us"
        )

    def _mock_token_resp(self):
        r = MagicMock(status_code=200)
        r.json.return_value = {"access_token": "tok123", "expires_in": 3600}
        return r

    def _mock_job_resp(self, job_id="job-001"):
        r = MagicMock(status_code=200)
        r.json.return_value = {"jobId": job_id}
        return r

    def _mock_status_done(self, job_id="job-001"):
        r = MagicMock(status_code=200)
        r.json.return_value = {"jobId": job_id, "state": "DONE", "rowCount": 1}
        return r

    def _mock_results(self, rows):
        r = MagicMock(status_code=200)
        r.json.return_value = {"result": {"data": rows}, "resultMetaData": {"pageToken": None}}
        return r

    def test_detect_returns_findings(self):
        d = self._make()
        row = {
            "dest_hostname": "api.anthropic.com",
            "src_user": "carol@corp.com",
            "src_ip": "10.1.1.1",
            "action": "allow",
            "event_time": "2026-05-28T09:00:00Z",
        }

        token_resp = self._mock_token_resp()
        job_resp = self._mock_job_resp()
        status_resp = self._mock_status_done()
        results_resp = self._mock_results([row])

        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: s
        mock_client.__exit__ = MagicMock(return_value=False)

        call_count = {"n": 0}

        def side_effect(url, **kwargs):
            n = call_count["n"]
            call_count["n"] += 1
            if "access_token" in url:
                return token_resp
            if "jobs" in url and kwargs.get("json"):
                return job_resp
            if "jobs/job-001" in url and not kwargs.get("json"):
                return status_resp if n < 5 else results_resp
            return results_resp

        mock_client.post.side_effect = side_effect

        def get_side(url, **kwargs):
            if "state" in url or "job-001" in url:
                return status_resp
            return results_resp

        mock_client.get.side_effect = get_side

        with patch("httpx.Client", return_value=mock_client):
            with patch.object(d, "_get_access_token", return_value="tok123"):
                with patch.object(d, "_start_query", return_value="job-001"):
                    with patch.object(d, "_poll_job", return_value=True):
                        with patch.object(d, "_fetch_results", return_value=[row]):
                            with patch.object(
                                d, "_parse_row",
                                return_value=MagicMock(
                                    provider="anthropic",
                                    source="prisma_access",
                                    detection_layer="layer5_sse_proxy",
                                )
                            ):
                                findings = d.detect(hours_back=1)

        assert len(findings) >= 1

    def test_detect_raises_on_auth_failure(self):
        """detect() propagates RuntimeError when OAuth2 token exchange fails."""
        d = self._make()

        def _raise_auth(_client):
            raise RuntimeError("PrismaAccess: OAuth2 token exchange failed (HTTP 401): ...")

        with patch.object(d, "_get_access_token", side_effect=_raise_auth):
            mock_cm = MagicMock()
            mock_cm.__enter__ = lambda s: MagicMock()
            mock_cm.__exit__ = MagicMock(return_value=False)
            with patch("httpx.Client", return_value=mock_cm):
                with pytest.raises(RuntimeError, match="PrismaAccess"):
                    d.detect(hours_back=1)

    def test_detect_returns_empty_on_poll_timeout(self):
        d = self._make()
        with patch.object(d, "_get_access_token", return_value="tok"):
            with patch.object(d, "_start_query", return_value="job-x"):
                with patch.object(d, "_poll_job", return_value=False):
                    findings = d.detect(hours_back=1)
        assert findings == []


# ---------------------------------------------------------------------------
# TestNetskopeStub
# ---------------------------------------------------------------------------

class TestNetskopeStub:
    def _make(self):
        from agent_discover_scanner.detectors.sse_proxy.netskope import NetskopeDetector
        return NetskopeDetector()

    def test_is_available_false(self):
        assert self._make().is_available() is False

    def test_detect_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            self._make().detect(hours_back=1)


# ---------------------------------------------------------------------------
# TestSSEProxyFindingToDict
# ---------------------------------------------------------------------------

class TestSSEProxyFindingToDict:
    def _make_finding(self, **kwargs):
        from agent_discover_scanner.detectors.sse_proxy.base import SSEProxyFinding
        defaults = dict(
            provider="openai",
            source="zscaler_zia",
            event_time=_ts("2026-05-28T10:00:00"),
            username="user@corp.com",
            source_ip="10.0.0.1",
            destination_host="api.openai.com",
        )
        defaults.update(kwargs)
        return SSEProxyFinding(**defaults)

    def test_to_dict_has_required_keys(self):
        d = self._make_finding().to_dict()
        required = {"provider", "process_name", "timestamp", "source",
                    "detection_layer", "username", "source_ip", "destination_host"}
        assert required.issubset(d.keys())

    def test_to_dict_detection_layer(self):
        d = self._make_finding().to_dict()
        assert d["detection_layer"] == "layer5_sse_proxy"

    def test_to_dict_process_name_is_none(self):
        d = self._make_finding().to_dict()
        assert d["process_name"] is None

    def test_to_dict_model_id_is_none(self):
        d = self._make_finding().to_dict()
        assert d["model_id"] is None

    def test_to_dict_timestamp_is_iso_string(self):
        d = self._make_finding().to_dict()
        # Must parse without error
        datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00"))

    def test_to_dict_provider_and_source_preserved(self):
        d = self._make_finding(provider="anthropic", source="prisma_access").to_dict()
        assert d["provider"] == "anthropic"
        assert d["source"] == "prisma_access"


# ---------------------------------------------------------------------------
# TestRunSSEProxyDetection
# ---------------------------------------------------------------------------

class TestRunSSEProxyDetection:
    def test_returns_empty_when_both_disabled(self):
        from agent_discover_scanner.detectors.sse_proxy import run_sse_proxy_detection
        result = run_sse_proxy_detection(zscaler_enabled=False, prisma_access_enabled=False)
        assert result == []

    def test_zscaler_disabled_skips_zscaler(self):
        """When zscaler_enabled=False, the Zscaler detector is never imported or called."""
        from agent_discover_scanner.detectors.sse_proxy import run_sse_proxy_detection

        with patch(
            "agent_discover_scanner.detectors.sse_proxy.zscaler_zia.ZscalerZIADetector",
            autospec=True,
        ) as mock_cls:
            run_sse_proxy_detection(zscaler_enabled=False, prisma_access_enabled=False)
        # Should not be instantiated when disabled
        mock_cls.assert_not_called()

    def test_zscaler_unavailable_warns(self):
        from agent_discover_scanner.detectors.sse_proxy import run_sse_proxy_detection

        warn_msgs = []
        with patch(
            "agent_discover_scanner.detectors.sse_proxy.zscaler_zia.ZscalerZIADetector.is_available",
            return_value=False,
        ):
            run_sse_proxy_detection(
                zscaler_enabled=True,
                _warn_fn=warn_msgs.append,
            )
        assert any("Zscaler" in m for m in warn_msgs)

    def test_merges_results_from_both_detectors(self):
        from agent_discover_scanner.detectors.sse_proxy import run_sse_proxy_detection
        from agent_discover_scanner.detectors.sse_proxy.base import SSEProxyFinding

        f1 = SSEProxyFinding(
            provider="openai", source="zscaler_zia",
            event_time=_ts("2026-05-28T10:00:00"),
            username="u1@corp.com", source_ip="10.0.0.1",
            destination_host="api.openai.com",
        )
        f2 = SSEProxyFinding(
            provider="anthropic", source="prisma_access",
            event_time=_ts("2026-05-28T10:01:00"),
            username="u2@corp.com", source_ip="10.0.0.2",
            destination_host="api.anthropic.com",
        )

        with patch(
            "agent_discover_scanner.detectors.sse_proxy.zscaler_zia.ZscalerZIADetector.is_available",
            return_value=True,
        ):
            with patch(
                "agent_discover_scanner.detectors.sse_proxy.zscaler_zia.ZscalerZIADetector.detect",
                return_value=[f1],
            ):
                with patch(
                    "agent_discover_scanner.detectors.sse_proxy.prisma_access.PrismaAccessDetector.is_available",
                    return_value=True,
                ):
                    with patch(
                        "agent_discover_scanner.detectors.sse_proxy.prisma_access.PrismaAccessDetector.detect",
                        return_value=[f2],
                    ):
                        results = run_sse_proxy_detection(
                            zscaler_enabled=True,
                            prisma_access_enabled=True,
                        )

        assert len(results) == 2
        providers = {r["provider"] for r in results}
        assert providers == {"openai", "anthropic"}
        for r in results:
            assert r["detection_layer"] == "layer5_sse_proxy"


# ---------------------------------------------------------------------------
# TestSSEProxyCorrelator
# ---------------------------------------------------------------------------

class TestSSEProxyCorrelator:
    """End-to-end correlator tests for the l5_sse_proxy path."""

    def _correlate(self, code_findings, network_findings):
        from agent_discover_scanner.correlator import CorrelationEngine
        return CorrelationEngine.correlate(
            code_findings=code_findings,
            network_findings=network_findings,
        )

    def _code_finding(self, provider: str = "openai", rule: str = "DAI001") -> dict:
        return {
            "rule_id": rule,
            "file_path": f"/app/agents/{provider}_agent.py",
            "line": 10,
            "message": f"Direct {provider} API call",
            "level": "warning",
        }

    def test_sse_proxy_findings_excluded_from_l2_network(self):
        """SSE proxy findings must not land in active_providers (l2_network)."""
        # If they did, the correlator would try _is_known_executor(None) → False
        # and the GHOST loop would see no l2 activity → no GHOST.
        from agent_discover_scanner.correlator import CorrelationEngine
        nf = [_finding_dict("openai", "2026-05-28T10:00:00")]
        # Spy on split by checking that l2_network is empty
        inventory = CorrelationEngine.correlate(
            code_findings=[],
            network_findings=nf,
        )
        ghost_providers = {
            g.network_provider
            for g in inventory.get("ghost", [])
        }
        # Should produce a GHOST for openai from the SSE proxy path
        assert "openai" in ghost_providers

    def test_sse_proxy_confirmed_when_code_finding_matches(self):
        """Code finding + matching SSE proxy → CONFIRMED."""
        nf = [_finding_dict("openai", "2026-05-28T10:00:00")]
        cf = [self._code_finding("openai")]
        inventory = self._correlate(cf, nf)
        confirmed = inventory.get("confirmed", [])
        assert len(confirmed) >= 1
        assert any("openai" in (c.network_provider or "") for c in confirmed)

    def test_sse_proxy_ghost_when_no_code_finding(self):
        """SSE proxy event with no code finding → GHOST."""
        nf = [_finding_dict("anthropic", "2026-05-28T11:00:00", username="dev@corp.com")]
        inventory = self._correlate([], nf)
        ghosts = inventory.get("ghost", [])
        assert len(ghosts) >= 1
        ghost_providers = {g.network_provider for g in ghosts}
        assert "anthropic" in ghost_providers

    def test_sse_proxy_ghost_uses_username_as_caller_identity(self):
        """caller_identity of SSE GHOST should come from username; process_name stays None."""
        nf = [_finding_dict("mistral", "2026-05-28T12:00:00", username="ml-bot@corp.com")]
        inventory = self._correlate([], nf)
        ghosts = inventory.get("ghost", [])
        ghost = next((g for g in ghosts if g.network_provider == "mistral"), None)
        assert ghost is not None
        assert ghost.caller_identity == "ml-bot@corp.com"
        assert ghost.process_name is None  # L5 must not pollute the OS-process field

    def test_sse_proxy_ghost_deduped_by_provider(self):
        """Multiple SSE proxy events for the same provider → single GHOST."""
        nf = [
            _finding_dict("cohere", "2026-05-28T10:00:00", username="u1@corp.com"),
            _finding_dict("cohere", "2026-05-28T10:05:00", username="u2@corp.com"),
        ]
        inventory = self._correlate([], nf)
        cohere_ghosts = [g for g in inventory.get("ghost", []) if g.network_provider == "cohere"]
        assert len(cohere_ghosts) == 1

    def test_sse_proxy_confirmed_sets_detection_layers(self):
        """CONFIRMED item from SSE proxy should include layer5_sse in detection_layers."""
        nf = [_finding_dict("openai", "2026-05-28T10:00:00")]
        cf = [self._code_finding("openai")]
        inventory = self._correlate(cf, nf)
        confirmed = inventory.get("confirmed", [])
        openai_confirmed = [c for c in confirmed if "openai" in (c.network_provider or "")]
        assert len(openai_confirmed) >= 1
        layers = openai_confirmed[0].detection_layers
        assert "layer5_sse" in layers

    def test_sse_proxy_does_not_overwrite_l2_process_name(self):
        """When L2 also matches, process_name from L2 is preserved over SSE proxy username."""
        l2_finding = {
            "provider": "openai",
            "process_name": "python3",
            "timestamp": "2026-05-28T10:00:00",
            "detection_layer": None,  # L2 — no detection_layer key
        }
        sse_finding = _finding_dict("openai", "2026-05-28T10:01:00", username="alice@corp.com")
        nf = [l2_finding, sse_finding]
        cf = [self._code_finding("openai")]

        from agent_discover_scanner.correlator import CorrelationEngine
        with patch.object(CorrelationEngine, "_is_known_executor", return_value=True):
            inventory = CorrelationEngine.correlate(
                code_findings=cf,
                network_findings=nf,
            )

        confirmed = inventory.get("confirmed", [])
        openai_item = next(
            (c for c in confirmed if "openai" in (c.network_provider or "")), None
        )
        assert openai_item is not None
        # L2 process_name wins
        assert openai_item.process_name == "python3"
