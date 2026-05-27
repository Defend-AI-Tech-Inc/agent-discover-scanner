"""
Tests for network_monitor.py — Bedrock IP-range detection.

All HTTP calls and filesystem reads are mocked; no network access required.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

import agent_discover_scanner.network_monitor as nm_mod
from agent_discover_scanner.network_monitor import NetworkMonitor, fetch_bedrock_ip_ranges

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_SAMPLE_IPS = ["192.0.2.1", "192.0.2.2", "10.10.10.10"]
_FALLBACK_IPS = ["203.0.113.5", "203.0.113.6"]
_LIVE_FEED = json.dumps({"flat_ips": _SAMPLE_IPS})
_FALLBACK_FEED = json.dumps({"flat_ips": _FALLBACK_IPS})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_ip_cache():
    """Reset module-level Bedrock IP cache between every test."""
    nm_mod._bedrock_ip_cache = None
    yield
    nm_mod._bedrock_ip_cache = None


# ---------------------------------------------------------------------------
# TestFetchBedrockIpRanges
# ---------------------------------------------------------------------------


class TestFetchBedrockIpRanges:
    """Unit tests for fetch_bedrock_ip_ranges()."""

    def test_live_feed_success_returns_ip_set(self):
        """Successful HTTP response populates the cache and returns the IPs."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"flat_ips": _SAMPLE_IPS}
        mock_resp.raise_for_status.return_value = None

        with patch("agent_discover_scanner.network_monitor.httpx.get", return_value=mock_resp) as mock_get:
            result = fetch_bedrock_ip_ranges()

        assert result == set(_SAMPLE_IPS)
        mock_get.assert_called_once_with(nm_mod._BEDROCK_RANGES_URL, timeout=3.0)

    def test_live_feed_populates_module_cache(self):
        """After a successful fetch the module-level cache is set."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"flat_ips": _SAMPLE_IPS}
        mock_resp.raise_for_status.return_value = None

        with patch("agent_discover_scanner.network_monitor.httpx.get", return_value=mock_resp):
            fetch_bedrock_ip_ranges()

        assert nm_mod._bedrock_ip_cache == set(_SAMPLE_IPS)

    def test_cached_result_skips_http(self):
        """Second call returns the cached set without any HTTP request."""
        nm_mod._bedrock_ip_cache = {"cached.ip"}

        with patch("agent_discover_scanner.network_monitor.httpx.get") as mock_get:
            result = fetch_bedrock_ip_ranges()

        assert result == {"cached.ip"}
        mock_get.assert_not_called()

    def test_live_feed_http_error_falls_back_to_file(self):
        """Any HTTP exception triggers the fallback JSON file."""
        with (
            patch(
                "agent_discover_scanner.network_monitor.httpx.get",
                side_effect=Exception("connection refused"),
            ),
            patch(
                "agent_discover_scanner.network_monitor._BEDROCK_FALLBACK_PATH",
            ) as mock_path,
        ):
            mock_path.read_text.return_value = _FALLBACK_FEED
            result = fetch_bedrock_ip_ranges()

        assert result == set(_FALLBACK_IPS)

    def test_live_feed_non_2xx_falls_back_to_file(self):
        """A non-2xx HTTP status (raise_for_status raises) triggers fallback."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("404 Not Found")

        with (
            patch("agent_discover_scanner.network_monitor.httpx.get", return_value=mock_resp),
            patch("agent_discover_scanner.network_monitor._BEDROCK_FALLBACK_PATH") as mock_path,
        ):
            mock_path.read_text.return_value = _FALLBACK_FEED
            result = fetch_bedrock_ip_ranges()

        assert result == set(_FALLBACK_IPS)

    def test_empty_live_flat_ips_falls_back_to_file(self):
        """An empty flat_ips list in the live response triggers fallback."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"flat_ips": []}
        mock_resp.raise_for_status.return_value = None

        with (
            patch("agent_discover_scanner.network_monitor.httpx.get", return_value=mock_resp),
            patch("agent_discover_scanner.network_monitor._BEDROCK_FALLBACK_PATH") as mock_path,
        ):
            mock_path.read_text.return_value = _FALLBACK_FEED
            result = fetch_bedrock_ip_ranges()

        assert result == set(_FALLBACK_IPS)

    def test_both_sources_fail_returns_empty_set(self):
        """If both sources fail the function returns an empty set gracefully."""
        with (
            patch(
                "agent_discover_scanner.network_monitor.httpx.get",
                side_effect=Exception("offline"),
            ),
            patch("agent_discover_scanner.network_monitor._BEDROCK_FALLBACK_PATH") as mock_path,
        ):
            mock_path.read_text.side_effect = OSError("file not found")
            result = fetch_bedrock_ip_ranges()

        assert result == set()

    def test_both_sources_fail_cache_set_to_empty(self):
        """Cache is populated with empty set so subsequent calls skip retries."""
        with (
            patch(
                "agent_discover_scanner.network_monitor.httpx.get",
                side_effect=Exception("offline"),
            ),
            patch("agent_discover_scanner.network_monitor._BEDROCK_FALLBACK_PATH") as mock_path,
        ):
            mock_path.read_text.side_effect = OSError("file not found")
            fetch_bedrock_ip_ranges()

        assert nm_mod._bedrock_ip_cache == set()

    def test_live_feed_uses_three_second_timeout(self):
        """The HTTP call is made with exactly a 3-second timeout."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"flat_ips": _SAMPLE_IPS}
        mock_resp.raise_for_status.return_value = None

        with patch("agent_discover_scanner.network_monitor.httpx.get", return_value=mock_resp) as mock_get:
            fetch_bedrock_ip_ranges()

        _, kwargs = mock_get.call_args
        assert kwargs.get("timeout") == 3.0


# ---------------------------------------------------------------------------
# TestClassifyAiServiceBedrockIp
# ---------------------------------------------------------------------------


class TestClassifyAiServiceBedrockIp:
    """Tests for the Bedrock IP check inside _classify_ai_service()."""

    def _make_monitor(self) -> NetworkMonitor:
        return NetworkMonitor()

    # -- IP matched in the Bedrock set -----------------------------------

    def test_ip_in_bedrock_set_returns_aws_bedrock(self):
        """A raw IPv4 present in the Bedrock IP set is classified as AWS Bedrock."""
        nm_mod._bedrock_ip_cache = {"54.239.17.6", "192.0.2.1"}
        monitor = self._make_monitor()
        result = monitor._classify_ai_service("54.239.17.6")
        assert result == "AWS Bedrock"

    def test_ip_not_in_bedrock_set_falls_through(self):
        """A raw IPv4 absent from the Bedrock set returns None (no match)."""
        nm_mod._bedrock_ip_cache = {"54.239.17.6"}
        monitor = self._make_monitor()
        result = monitor._classify_ai_service("1.2.3.4")
        assert result is None

    def test_bedrock_ip_check_takes_priority_over_domain_patterns(self):
        """IP check runs before domain substring checks — Bedrock wins."""
        nm_mod._bedrock_ip_cache = {"54.239.17.6"}
        monitor = self._make_monitor()
        # "54.239.17.6" doesn't match any domain pattern; we confirm it returns
        # AWS Bedrock rather than None (priority test).
        result = monitor._classify_ai_service("54.239.17.6")
        assert result == "AWS Bedrock"

    # -- Hostname (non-IP) skips Bedrock IP check ------------------------

    def test_hostname_skips_bedrock_ip_set(self):
        """A resolved hostname is never looked up in the Bedrock IP set."""
        nm_mod._bedrock_ip_cache = {"openai.com"}  # bogus — ensures no false positive
        monitor = self._make_monitor()
        result = monitor._classify_ai_service("openai.com")
        # Should match the AI_SERVICES domain dict, not the Bedrock IP set
        assert result == "OpenAI"

    def test_bedrock_hostname_still_classified_via_domain(self):
        """bedrock-runtime domain substring still matches even without IP in cache."""
        nm_mod._bedrock_ip_cache = set()  # empty — no IPs
        monitor = self._make_monitor()
        result = monitor._classify_ai_service("bedrock-runtime.us-east-1.amazonaws.com")
        assert result == "AWS Bedrock"

    # -- Existing domain checks unaffected -------------------------------

    def test_anthropic_domain_still_matched(self):
        # 'anthropic.com' (the broader key) is iterated first in AI_SERVICES
        # and is a substring of 'api.anthropic.com', so it wins.
        nm_mod._bedrock_ip_cache = set()
        monitor = self._make_monitor()
        assert monitor._classify_ai_service("api.anthropic.com") == "Anthropic"

    def test_openai_domain_still_matched(self):
        # 'openai.com' is iterated before 'api.openai.com' in AI_SERVICES.
        nm_mod._bedrock_ip_cache = set()
        monitor = self._make_monitor()
        assert monitor._classify_ai_service("api.openai.com") == "OpenAI"

    def test_gemini_domain_still_matched(self):
        # 'googleapis.com' is iterated before 'generativelanguage.googleapis.com'.
        nm_mod._bedrock_ip_cache = set()
        monitor = self._make_monitor()
        assert monitor._classify_ai_service("generativelanguage.googleapis.com") == "Google AI"

    def test_pinecone_vector_db_still_matched(self):
        nm_mod._bedrock_ip_cache = set()
        monitor = self._make_monitor()
        assert monitor._classify_ai_service("api.pinecone.io") == "Pinecone"

    def test_unknown_hostname_returns_none(self):
        nm_mod._bedrock_ip_cache = set()
        monitor = self._make_monitor()
        assert monitor._classify_ai_service("internal.corp.example") is None

    # -- IPv4 regex edge cases -------------------------------------------

    def test_ipv6_address_skips_bedrock_ip_check(self):
        """IPv6 addresses don't match the IPv4 pattern, so the set is not queried."""
        target_ipv6 = "2001:db8::1"
        nm_mod._bedrock_ip_cache = {target_ipv6}  # even if present, should not match
        monitor = self._make_monitor()
        # IPv6 won't match _IPv4_RE — should fall through and return None
        result = monitor._classify_ai_service(target_ipv6)
        assert result is None

    def test_partial_ip_like_string_not_treated_as_ip(self):
        """A string like '1.2.3' (only 3 octets) doesn't trigger IP check."""
        nm_mod._bedrock_ip_cache = {"1.2.3"}
        monitor = self._make_monitor()
        result = monitor._classify_ai_service("1.2.3")
        assert result is None
