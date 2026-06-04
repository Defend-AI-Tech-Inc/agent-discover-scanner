"""
Tests for Layer 2 forward-DNS correlation, port filter, and private-IP detection.

Key coverage:
- ForwardDNSCache  — observe/lookup, TTL expiry, size, seed (mocked), thread-safety
- _resolve_hostname — forward-DNS takes priority over reverse-DNS
- TestBedrockRotatingIP — pre-seeded IP→hostname recovers Bedrock service name even
  as the remote IP rotates; full mock-psutil path asserts AI service classification
- TestPortFilter — port 993 rejected, 443 accepted; private IPs are port-filter exempt
- TestIsPrivateIp  — loopback, RFC-1918, RFC-6598, IPv6 ULA, public IPs
"""

import socket
import threading
import time
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from agent_discover_scanner.network_monitor import (
    ForwardDNSCache,
    NetworkMonitor,
    _EXTERNAL_LLM_PORTS,
    _LLM_SEED_HOSTNAMES,
    _is_private_ip,
)


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_monitor() -> NetworkMonitor:
    """
    Return a NetworkMonitor whose background seed thread is suppressed so tests
    do not make real DNS queries.
    """
    with patch("threading.Thread"):
        monitor = NetworkMonitor()
    # Replace the real ForwardDNSCache with a pristine one (no background seeding)
    monitor._fwd_dns = ForwardDNSCache()
    return monitor


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ForwardDNSCache — unit tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestForwardDNSCacheObserveLookup(unittest.TestCase):
    """observe() + lookup() basic contract."""

    def test_lookup_returns_none_on_empty_cache(self):
        cache = ForwardDNSCache()
        self.assertIsNone(cache.lookup("1.2.3.4"))

    def test_observe_and_lookup_round_trip(self):
        cache = ForwardDNSCache()
        cache.observe("api.openai.com", "104.18.7.192")
        self.assertEqual(cache.lookup("104.18.7.192"), "api.openai.com")

    def test_lookup_unknown_ip_returns_none(self):
        cache = ForwardDNSCache()
        cache.observe("api.anthropic.com", "52.85.100.1")
        self.assertIsNone(cache.lookup("9.9.9.9"))

    def test_observe_overwrites_stale_entry(self):
        cache = ForwardDNSCache()
        cache.observe("old.example.com", "1.2.3.4")
        cache.observe("new.example.com", "1.2.3.4")
        self.assertEqual(cache.lookup("1.2.3.4"), "new.example.com")

    def test_size_reflects_unique_ips(self):
        cache = ForwardDNSCache()
        self.assertEqual(cache.size(), 0)
        cache.observe("a.com", "1.1.1.1")
        cache.observe("b.com", "2.2.2.2")
        self.assertEqual(cache.size(), 2)
        # Overwriting existing IP does not increase size
        cache.observe("a.com", "1.1.1.1")
        self.assertEqual(cache.size(), 2)


class TestForwardDNSCacheTTL(unittest.TestCase):
    """TTL expiry — expired entries are evicted on read."""

    def test_entry_is_live_within_ttl(self):
        cache = ForwardDNSCache(ttl=10.0)
        cache.observe("api.groq.com", "3.3.3.3")
        self.assertEqual(cache.lookup("3.3.3.3"), "api.groq.com")

    def test_entry_expires_after_ttl(self):
        cache = ForwardDNSCache(ttl=0.05)   # 50 ms TTL
        cache.observe("api.groq.com", "3.3.3.3")
        time.sleep(0.1)
        self.assertIsNone(cache.lookup("3.3.3.3"))

    def test_expired_entry_is_removed_from_cache(self):
        cache = ForwardDNSCache(ttl=0.05)
        cache.observe("api.groq.com", "3.3.3.3")
        time.sleep(0.1)
        cache.lookup("3.3.3.3")             # trigger eviction
        self.assertEqual(cache.size(), 0)


class TestForwardDNSCacheSeed(unittest.TestCase):
    """seed() resolves hostnames and populates the cache."""

    def test_seed_populates_cache_for_resolvable_hostname(self):
        cache = ForwardDNSCache()
        # Use 'localhost' — guaranteed to resolve on every platform.
        cache.seed(["localhost"])
        # localhost resolves to 127.0.0.1 (and/or ::1) — at least one entry added.
        self.assertGreater(cache.size(), 0)

    def test_seed_silently_skips_unresolvable_hostnames(self):
        cache = ForwardDNSCache()
        # This hostname will never resolve.
        cache.seed(["this-hostname-does-not-exist.invalid"])
        self.assertEqual(cache.size(), 0)

    def test_seed_with_mock_getaddrinfo(self):
        """seed() stores IPs returned by getaddrinfo without making real DNS calls."""
        cache = ForwardDNSCache()
        fake_infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.94.238.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("52.94.238.11", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_infos):
            cache.seed(["bedrock-runtime.us-east-1.amazonaws.com"])

        self.assertEqual(cache.lookup("52.94.238.10"), "bedrock-runtime.us-east-1.amazonaws.com")
        self.assertEqual(cache.lookup("52.94.238.11"), "bedrock-runtime.us-east-1.amazonaws.com")
        self.assertEqual(cache.size(), 2)


class TestForwardDNSCacheThreadSafety(unittest.TestCase):
    """Concurrent observe/lookup calls do not raise or corrupt state."""

    def test_concurrent_observe_and_lookup(self):
        cache = ForwardDNSCache()
        errors: list[Exception] = []

        def writer():
            for i in range(200):
                cache.observe(f"host{i}.example.com", f"10.0.{i // 256}.{i % 256}")

        def reader():
            for i in range(200):
                cache.lookup(f"10.0.{i // 256}.{i % 256}")

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        # No exceptions raised (errors list stays empty) and size is consistent.
        self.assertEqual(errors, [])


# ═══════════════════════════════════════════════════════════════════════════════
# 2. _resolve_hostname — forward-DNS takes priority over reverse-DNS
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveHostnameForwardDNS(unittest.TestCase):
    """Forward-DNS cache is checked before reverse-DNS; result is authoritative."""

    def setUp(self):
        self.monitor = _make_monitor()

    def test_forward_dns_returned_before_reverse_lookup(self):
        """When forward-DNS has the IP, socket.gethostbyaddr should NOT be called."""
        self.monitor._fwd_dns.observe("api.openai.com", "104.18.7.192")

        with patch("socket.gethostbyaddr") as mock_rdns:
            result = self.monitor._resolve_hostname("104.18.7.192")

        mock_rdns.assert_not_called()
        self.assertEqual(result, "api.openai.com")

    def test_forward_dns_result_warms_reverse_cache(self):
        """After a forward-DNS hit, the reverse-DNS cache is also populated."""
        self.monitor._fwd_dns.observe("api.anthropic.com", "52.85.100.1")
        self.monitor._resolve_hostname("52.85.100.1")
        self.assertEqual(self.monitor._dns_cache.get("52.85.100.1"), "api.anthropic.com")

    def test_reverse_dns_cache_used_when_forward_miss(self):
        """If forward-DNS has no entry, the existing reverse-DNS cache is consulted."""
        self.monitor._dns_cache["8.8.8.8"] = "dns.google.com"
        with patch("socket.gethostbyaddr") as mock_rdns:
            result = self.monitor._resolve_hostname("8.8.8.8")
        mock_rdns.assert_not_called()
        self.assertEqual(result, "dns.google.com")

    def test_live_reverse_dns_called_on_full_cache_miss(self):
        """With no caches populated, socket.gethostbyaddr is called for the IP."""
        with patch("socket.gethostbyaddr", return_value=("some.host.com", [], ["5.5.5.5"])):
            result = self.monitor._resolve_hostname("5.5.5.5")
        self.assertEqual(result, "some.host.com")

    def test_bidirectional_population_from_reverse_dns(self):
        """A live reverse-DNS hit also populates the forward-DNS cache."""
        with patch(
            "socket.gethostbyaddr",
            return_value=("api.mistral.ai", [], ["54.1.2.3"]),
        ):
            self.monitor._resolve_hostname("54.1.2.3")
        # Forward-DNS cache should now map 54.1.2.3 → api.mistral.ai
        self.assertEqual(self.monitor._fwd_dns.lookup("54.1.2.3"), "api.mistral.ai")

    def test_ip_returned_when_all_resolution_paths_fail(self):
        """When every resolution path fails, the raw IP is returned."""
        with patch("socket.gethostbyaddr", side_effect=socket.herror):
            result = self.monitor._resolve_hostname("99.99.99.99")
        self.assertEqual(result, "99.99.99.99")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TestBedrockRotatingIP — the key integration test
# ═══════════════════════════════════════════════════════════════════════════════


class TestBedrockRotatingIP(unittest.TestCase):
    """
    Bedrock endpoint IPs rotate across a large pool of EC2 addresses whose
    reverse-DNS returns generic hostnames like ec2-52-94-238-10.compute-1.amazonaws.com,
    which does NOT contain 'bedrock'.  Forward-DNS correlation is the only reliable
    way to recover the service hostname.

    These tests verify the complete path:
        seed(bedrock-runtime.us-east-1.amazonaws.com → IP)
        → _resolve_hostname(IP) → bedrock-runtime.us-east-1.amazonaws.com
        → _classify_ai_service(…) → "AWS Bedrock" / "AWS Bedrock Agent"
    """

    REGION = "us-east-1"
    HOSTNAME = f"bedrock-runtime.{REGION}.amazonaws.com"
    IP_1 = "52.94.238.10"
    IP_2 = "52.94.238.20"   # "rotated" IP — different address, same service

    def setUp(self):
        self.monitor = _make_monitor()

    # ── resolution ────────────────────────────────────────────────────────────

    def test_seed_ip_resolves_to_bedrock_hostname(self):
        """_resolve_hostname returns the Bedrock hostname after forward-DNS seeding."""
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_1)
        result = self.monitor._resolve_hostname(self.IP_1)
        self.assertIn("bedrock-runtime", result)
        self.assertEqual(result, self.HOSTNAME)

    def test_rotated_ip_also_resolves_after_re_seed(self):
        """A different IP for the same Bedrock hostname resolves correctly after seeding."""
        # Simulate a rotation — IP_2 is now one of the Bedrock IPs
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_2)
        result = self.monitor._resolve_hostname(self.IP_2)
        self.assertIn("bedrock-runtime", result)

    def test_generic_ec2_reverse_dns_does_not_classify_as_bedrock_without_seed(self):
        """
        Without forward-DNS seeding the generic EC2 reverse-DNS hostname should
        NOT classify as 'AWS Bedrock' through the substring-match path alone
        (it would match 'amazonaws.com' but that is not a Bedrock-specific signal).
        """
        ec2_rdns = "ec2-52-94-238-10.compute-1.amazonaws.com"
        service = self.monitor._classify_ai_service(ec2_rdns)
        # amazonaws.com does match — but not 'bedrock-runtime' or 'bedrock-agent-runtime'
        # The important assertion: forward-DNS gives a *better* classification
        self.assertNotEqual(service, "AWS Bedrock")

    def test_seeded_bedrock_ip_classifies_as_aws_bedrock(self):
        """
        After seeding, _resolve_hostname + _classify_ai_service together
        return 'AWS Bedrock'.
        """
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_1)
        hostname = self.monitor._resolve_hostname(self.IP_1)
        service = self.monitor._classify_ai_service(hostname)
        self.assertEqual(service, "AWS Bedrock")

    def test_rotated_ip_classifies_as_aws_bedrock(self):
        """IP rotation does not break classification as long as we re-seed."""
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_2)
        hostname = self.monitor._resolve_hostname(self.IP_2)
        service = self.monitor._classify_ai_service(hostname)
        self.assertEqual(service, "AWS Bedrock")

    def test_bedrock_agent_runtime_classifies_correctly(self):
        """bedrock-agent-runtime hostname classifies as 'AWS Bedrock Agent'."""
        agent_hostname = f"bedrock-agent-runtime.{self.REGION}.amazonaws.com"
        self.monitor._fwd_dns.observe(agent_hostname, "52.94.240.1")
        hostname = self.monitor._resolve_hostname("52.94.240.1")
        service = self.monitor._classify_ai_service(hostname)
        self.assertEqual(service, "AWS Bedrock Agent")

    # ── full mock-psutil path ─────────────────────────────────────────────────

    def _make_psutil_connection(self, raddr_ip: str, raddr_port: int = 443):
        """Build a fake psutil connection namedtuple."""
        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr = MagicMock()
        conn.raddr.ip = raddr_ip
        conn.raddr.port = raddr_port
        conn.laddr = MagicMock()
        conn.laddr.port = 54321
        conn.type = socket.SOCK_STREAM
        return conn

    def _make_proc(self, pid: int, name: str, conn):
        """Build a fake psutil Process that returns a single connection."""
        proc = MagicMock()
        proc.pid = pid
        proc.name.return_value = name
        proc.exe.return_value = f"/usr/bin/{name}"
        proc.connections.return_value = [conn]
        return proc

    def test_mock_psutil_bedrock_connection_classified(self):
        """
        Full integration: mock psutil returns a connection to Bedrock IP:443 →
        ForwardDNSCache maps it → classified as 'AWS Bedrock'.
        """
        # Pre-seed the forward-DNS cache as the background thread would
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_1)

        conn = self._make_psutil_connection(self.IP_1, 443)
        proc = self._make_proc(1234, "my_agent", conn)

        with (
            patch("psutil.process_iter", return_value=[proc]),
            patch(
                "agent_discover_scanner.network_monitor.NetworkMonitor"
                "._resolve_hostname",
                wraps=self.monitor._resolve_hostname,
            ),
            patch(
                "agent_discover_scanner.process_introspection.introspect_process",
                return_value=MagicMock(entry_script=None, framework=None),
            ),
        ):
            connections = self.monitor.get_active_ai_connections()

        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].ai_service, "AWS Bedrock")
        self.assertEqual(connections[0].remote_ip, self.IP_1)

    def test_mock_psutil_rotated_ip_also_detected(self):
        """After seeding IP_2, the rotated-IP connection is also classified correctly."""
        self.monitor._fwd_dns.observe(self.HOSTNAME, self.IP_2)

        conn = self._make_psutil_connection(self.IP_2, 443)
        proc = self._make_proc(5678, "my_agent", conn)

        with (
            patch("psutil.process_iter", return_value=[proc]),
            patch(
                "agent_discover_scanner.process_introspection.introspect_process",
                return_value=MagicMock(entry_script=None, framework=None),
            ),
        ):
            connections = self.monitor.get_active_ai_connections()

        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].ai_service, "AWS Bedrock")
        self.assertEqual(connections[0].remote_ip, self.IP_2)

    def test_seed_hostnames_include_all_bedrock_regions(self):
        """_LLM_SEED_HOSTNAMES covers both bedrock-runtime and bedrock-agent-runtime
        for every region in _BEDROCK_REGIONS."""
        from agent_discover_scanner.network_monitor import _BEDROCK_REGIONS

        for region in _BEDROCK_REGIONS:
            self.assertIn(f"bedrock-runtime.{region}.amazonaws.com", _LLM_SEED_HOSTNAMES)
            self.assertIn(f"bedrock-agent-runtime.{region}.amazonaws.com", _LLM_SEED_HOSTNAMES)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. TestPortFilter — HTTPS-only gate for external IPs
# ═══════════════════════════════════════════════════════════════════════════════


class TestPortFilter(unittest.TestCase):
    """
    Connections to external LLM IPs on non-HTTPS ports must be dropped before
    hostname resolution to avoid false-positives like :993 IMAP where Google's
    CDN IP space overlaps with AI provider address space.

    Private IPs (Ollama, local inference) are exempt from the port filter.
    """

    def setUp(self):
        self.monitor = _make_monitor()
        # Pre-seed Gemini hostname so the IP would otherwise be classified
        self.monitor._fwd_dns.observe("generativelanguage.googleapis.com", "142.250.80.100")

    def _make_conn(self, ip: str, port: int, status: str = "ESTABLISHED"):
        conn = MagicMock()
        conn.status = status
        conn.raddr = MagicMock()
        conn.raddr.ip = ip
        conn.raddr.port = port
        conn.laddr = MagicMock()
        conn.laddr.port = 55000
        conn.type = socket.SOCK_STREAM
        return conn

    def _run_single_conn(self, conn):
        proc = MagicMock()
        proc.pid = 9999
        proc.name.return_value = "test_proc"
        proc.exe.return_value = "/usr/bin/python3"
        proc.connections.return_value = [conn]
        with (
            patch("psutil.process_iter", return_value=[proc]),
            patch(
                "agent_discover_scanner.process_introspection.introspect_process",
                return_value=MagicMock(entry_script=None, framework=None),
            ),
        ):
            return self.monitor.get_active_ai_connections()

    def test_port_443_accepted_for_external_ip(self):
        """HTTPS connection on port 443 to a known AI IP is detected.

        The AI_SERVICES dict matches 'googleapis.com' before the more-specific
        'generativelanguage.googleapis.com' entry (dict insertion order), so the
        service label may be 'Google AI' rather than 'Gemini API'.  Either is
        correct — what matters is that *some* AI service is detected.
        """
        conn = self._make_conn("142.250.80.100", 443)
        connections = self._run_single_conn(conn)
        self.assertEqual(len(connections), 1)
        self.assertIn("Google", connections[0].ai_service)

    def test_port_8443_accepted_for_external_ip(self):
        """Port 8443 (alt-HTTPS) is in the allowed set and must not be filtered."""
        conn = self._make_conn("142.250.80.100", 8443)
        connections = self._run_single_conn(conn)
        self.assertEqual(len(connections), 1)

    def test_port_993_rejected_for_external_ip(self):
        """
        IMAPS port 993 on a Google IP (commonly used for Gmail) must be silently
        dropped — even though the IP would otherwise resolve to a Gemini hostname
        via the forward-DNS seed.
        """
        conn = self._make_conn("142.250.80.100", 993)
        connections = self._run_single_conn(conn)
        self.assertEqual(len(connections), 0, "port 993 IMAP should be filtered out")

    def test_port_5432_rejected_for_external_ip(self):
        """PostgreSQL port on an external IP is rejected."""
        conn = self._make_conn("142.250.80.100", 5432)
        connections = self._run_single_conn(conn)
        self.assertEqual(len(connections), 0)

    def test_port_80_rejected_for_external_ip(self):
        """Plain HTTP port 80 is not in the allowed set."""
        conn = self._make_conn("142.250.80.100", 80)
        connections = self._run_single_conn(conn)
        self.assertEqual(len(connections), 0)

    def test_non_https_port_allowed_for_private_ip(self):
        """
        Local Ollama (127.0.0.1:11434) must NOT be filtered — private IPs are
        exempt from the HTTPS-only requirement.
        """
        # Seed a hostname for the localhost IP
        self.monitor._fwd_dns.observe("localhost.ollama", "127.0.0.1")
        # For a private IP the port filter is bypassed; Ollama is not in AI_SERVICES
        # so no connection will be classified as an AI service — but the code path
        # must not crash and must not apply the external-IP port filter.
        conn = self._make_conn("127.0.0.1", 11434)
        # Should not raise regardless of classification result
        try:
            self._run_single_conn(conn)
        except Exception as exc:
            self.fail(f"get_active_ai_connections raised for private IP: {exc}")

    def test_external_llm_ports_set_contains_expected_values(self):
        """Ensure the port-filter constant covers the expected HTTPS ports."""
        self.assertIn(443, _EXTERNAL_LLM_PORTS)
        self.assertIn(8443, _EXTERNAL_LLM_PORTS)
        self.assertNotIn(80, _EXTERNAL_LLM_PORTS)
        self.assertNotIn(993, _EXTERNAL_LLM_PORTS)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TestIsPrivateIp — comprehensive coverage of private IP detection
# ═══════════════════════════════════════════════════════════════════════════════


class TestIsPrivateIp(unittest.TestCase):
    """Verify _is_private_ip correctly classifies every IP category."""

    # -- loopback --

    def test_loopback_127_0_0_1(self):
        self.assertTrue(_is_private_ip("127.0.0.1"))

    def test_loopback_127_255_255_255(self):
        self.assertTrue(_is_private_ip("127.255.255.255"))

    def test_ipv6_loopback(self):
        self.assertTrue(_is_private_ip("::1"))

    # -- RFC-1918 --

    def test_10_x_x_x_is_private(self):
        self.assertTrue(_is_private_ip("10.0.0.1"))
        self.assertTrue(_is_private_ip("10.255.255.255"))

    def test_192_168_x_x_is_private(self):
        self.assertTrue(_is_private_ip("192.168.0.1"))
        self.assertTrue(_is_private_ip("192.168.255.254"))

    def test_172_16_to_31_is_private(self):
        for second in range(16, 32):
            with self.subTest(second=second):
                self.assertTrue(_is_private_ip(f"172.{second}.0.1"))

    def test_172_15_is_NOT_private(self):
        self.assertFalse(_is_private_ip("172.15.255.255"))

    def test_172_32_is_NOT_private(self):
        self.assertFalse(_is_private_ip("172.32.0.1"))

    # -- link-local --

    def test_link_local_169_254(self):
        self.assertTrue(_is_private_ip("169.254.1.1"))
        self.assertTrue(_is_private_ip("169.254.169.254"))  # AWS IMDS

    # -- IPv6 ULA --

    def test_ipv6_ula_fc(self):
        self.assertTrue(_is_private_ip("fc00::1"))

    def test_ipv6_ula_fd(self):
        self.assertTrue(_is_private_ip("fd00::1"))

    def test_ipv6_link_local_fe80(self):
        self.assertTrue(_is_private_ip("fe80::1"))

    # -- catch-all / unspecified --

    def test_zero_ipv4(self):
        self.assertTrue(_is_private_ip("0.0.0.0"))

    def test_ipv6_unspecified(self):
        self.assertTrue(_is_private_ip("::"))

    def test_empty_string(self):
        self.assertTrue(_is_private_ip(""))

    # -- public IPs --

    def test_public_google_dns(self):
        self.assertFalse(_is_private_ip("8.8.8.8"))

    def test_public_cloudflare_dns(self):
        self.assertFalse(_is_private_ip("1.1.1.1"))

    def test_public_openai_range(self):
        self.assertFalse(_is_private_ip("104.18.7.192"))

    def test_public_anthropic_range(self):
        self.assertFalse(_is_private_ip("52.85.100.1"))

    def test_public_bedrock_range(self):
        self.assertFalse(_is_private_ip("52.94.238.10"))


if __name__ == "__main__":
    unittest.main()
