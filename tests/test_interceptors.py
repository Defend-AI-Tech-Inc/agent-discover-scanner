"""
Tests for the interceptors/ module:
  - NetworkInterceptor base class and InterceptorResult shape
  - Individual SSE vendor plugins (unit, no live process scan)
  - detect_network_interceptors() auto-discovery
  - correlate_bedrock_findings() classification rules
"""

from unittest.mock import MagicMock, patch

import pytest

from agent_discover_scanner.correlator import CorrelationEngine
from agent_discover_scanner.interceptors import detect_network_interceptors
from agent_discover_scanner.interceptors.base import InterceptorResult, NetworkInterceptor
from agent_discover_scanner.interceptors.sse.netskope import NetskopeInterceptor
from agent_discover_scanner.interceptors.sse.prisma_access import PrismaAccessInterceptor
from agent_discover_scanner.interceptors.sse.umbrella import UmbrellaInterceptor
from agent_discover_scanner.interceptors.sse.zscaler import ZscalerInterceptor

# ---------------------------------------------------------------------------
# InterceptorResult shape
# ---------------------------------------------------------------------------


class TestInterceptorResult:
    def test_fields_present(self):
        r = InterceptorResult(
            vendor="Zscaler",
            confidence="high",
            evidence=["process:ZSATunnel"],
            fallback_strategy="bedrock_resource_api",
        )
        assert r.vendor == "Zscaler"
        assert r.confidence == "high"
        assert isinstance(r.evidence, list)
        assert isinstance(r.fallback_strategy, str)


# ---------------------------------------------------------------------------
# Individual plugin contracts
# ---------------------------------------------------------------------------


class TestVendorPluginContracts:
    @pytest.mark.parametrize("cls,vendor,proc,required_env_prefix", [
        (ZscalerInterceptor, "Zscaler", ["ZSATunnel", "ZSAService", "ZSAUpdater"], "ZIA_CLOUD"),
        (NetskopeInterceptor, "Netskope", ["nsClientUI", "nssvc"], "NSS_"),
        (PrismaAccessInterceptor, "Palo Alto Prisma Access", ["PanGPS", "pangps"], "PANGPS_"),
        (UmbrellaInterceptor, "Cisco Umbrella", ["Umbrella_RC"], "UMBRELLA_"),
    ])
    def test_plugin_properties(self, cls, vendor, proc, required_env_prefix):
        plugin = cls()
        assert plugin.vendor == vendor
        assert plugin.process_names == proc
        assert required_env_prefix in plugin.env_var_patterns

    def test_all_plugins_have_fallback_strategies(self):
        all_plugins = (
            ZscalerInterceptor, NetskopeInterceptor, PrismaAccessInterceptor, UmbrellaInterceptor
        )
        for cls in all_plugins:
            plugin = cls()
            strategies = plugin.fallback_strategies
            assert isinstance(strategies, list)
            assert len(strategies) > 0
            assert "process_env_scan" in strategies


# ---------------------------------------------------------------------------
# Detection logic — process list (mocked)
# ---------------------------------------------------------------------------


class TestProcessDetection:
    def _mock_process(self, name: str):
        proc = MagicMock()
        proc.info = {"name": name}
        proc.environ.return_value = {}
        return proc

    def test_zscaler_detected_via_process(self):
        plugin = ZscalerInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_process("ZSATunnel")]):
            result = plugin._check_process_list()
        assert result == "ZSATunnel"

    def test_netskope_detected_via_process(self):
        plugin = NetskopeInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_process("nsClientUI")]):
            result = plugin._check_process_list()
        assert result == "nsClientUI"

    def test_prisma_detected_via_process(self):
        plugin = PrismaAccessInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_process("PanGPS")]):
            result = plugin._check_process_list()
        assert result == "PanGPS"

    def test_umbrella_detected_via_process(self):
        plugin = UmbrellaInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_process("Umbrella_RC")]):
            result = plugin._check_process_list()
        assert result == "Umbrella_RC"

    def test_no_match_returns_none(self):
        plugin = ZscalerInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_process("Safari")]):
            result = plugin._check_process_list()
        assert result is None


# ---------------------------------------------------------------------------
# Full detect() — mocked process list
# ---------------------------------------------------------------------------


class TestInterceptorDetect:
    def _mock_proc(self, name: str):
        proc = MagicMock()
        proc.info = {"name": name}
        proc.environ.return_value = {}
        return proc

    def test_detect_returns_result_when_process_found(self):
        plugin = ZscalerInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_proc("ZSATunnel")]):
            result = plugin.detect()
        assert result is not None
        assert result.vendor == "Zscaler"
        assert result.confidence == "high"
        assert any("process:ZSATunnel" in e for e in result.evidence)
        assert isinstance(result.fallback_strategy, str)

    def test_detect_returns_none_when_no_process(self):
        plugin = ZscalerInterceptor()
        with patch("psutil.process_iter", return_value=[self._mock_proc("chrome")]):
            result = plugin.detect()
        assert result is None


# ---------------------------------------------------------------------------
# Auto-discovery via detect_network_interceptors()
# ---------------------------------------------------------------------------


class TestAutoDiscovery:
    def test_returns_list(self):
        with patch("psutil.process_iter", return_value=[]):
            results = detect_network_interceptors()
        assert isinstance(results, list)

    def test_detects_zscaler_when_process_running(self):
        proc = MagicMock()
        proc.info = {"name": "ZSATunnel"}
        proc.environ.return_value = {}
        with patch("psutil.process_iter", return_value=[proc]):
            results = detect_network_interceptors()
        vendors = [r.vendor for r in results]
        assert "Zscaler" in vendors

    def test_no_interceptors_when_no_proxy_processes(self):
        proc = MagicMock()
        proc.info = {"name": "python3"}
        proc.environ.return_value = {}
        with patch("psutil.process_iter", return_value=[proc]):
            results = detect_network_interceptors()
        assert results == []


# ---------------------------------------------------------------------------
# Shared fallback strategies
# ---------------------------------------------------------------------------


class TestFallbackStrategies:
    def test_process_env_scan_returns_list(self):
        proc = MagicMock()
        proc.pid = 1234
        proc.info = {"name": "python3"}
        proc.environ.return_value = {
            "AWS_DEFAULT_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "AKIAXXXXXXXXXXXXXXXX",
            "HOME": "/home/user",
        }
        with patch("psutil.process_iter", return_value=[proc]):
            results = NetworkInterceptor.run_process_env_scan()
        assert isinstance(results, list)
        assert any(r.get("region") == "us-east-1" for r in results)

    def test_process_env_scan_ignores_non_aws_processes(self):
        proc = MagicMock()
        proc.pid = 999
        proc.info = {"name": "chrome"}
        proc.environ.return_value = {"HOME": "/home/user", "PATH": "/usr/bin"}
        with patch("psutil.process_iter", return_value=[proc]):
            results = NetworkInterceptor.run_process_env_scan()
        assert results == []

    def test_dns_cache_scan_returns_list(self):
        # Should return a list without crashing even on unsupported platforms
        results = NetworkInterceptor.run_dns_cache_scan()
        assert isinstance(results, list)

    def test_bedrock_resource_api_no_boto3(self):
        # Should return the safe empty dict without crashing when boto3 absent
        with patch.dict("sys.modules", {"boto3": None}):
            result = NetworkInterceptor.run_bedrock_resource_api()
        assert result["available"] is False
        assert result["agents"] == []

    def test_cloudtrail_api_no_boto3(self):
        with patch.dict("sys.modules", {"boto3": None}):
            result = NetworkInterceptor.run_cloudtrail_api()
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# correlate_bedrock_findings() classification rules
# ---------------------------------------------------------------------------


class TestCorrelateBedrockFindings:
    def _l1(self, file_path: str = "app.py", line: int = 10, rule_id: str = "DAI007",
             message: str = "AWS Bedrock boto3 client instantiation detected") -> dict:
        return {"file_path": file_path, "line": line, "rule_id": rule_id, "message": message}

    def _l2(self, provider: str = "bedrock", process_name: str = "python3",
             timestamp: str = "2026-05-26T10:00:00") -> dict:
        return {"provider": provider, "process_name": process_name, "timestamp": timestamp}

    def test_layer1_plus_layer2_is_confirmed(self):
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[self._l1()],
            layer2_findings=[self._l2()],
        )
        assert len(items) == 1
        assert items[0].classification == "confirmed"
        assert "layer1" in items[0].detection_layers
        assert "layer2" in items[0].detection_layers
        assert items[0].network_provider == "bedrock"

    def test_layer2_only_is_ghost(self):
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[],
            layer2_findings=[self._l2()],
        )
        assert len(items) == 1
        assert items[0].classification == "ghost"
        assert items[0].risk_level == "critical"
        assert items[0].detection_layers == ["layer2"]

    def test_layer1_only_is_zombie(self):
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[self._l1()],
            layer2_findings=[],
        )
        assert len(items) == 1
        assert items[0].classification == "zombie"
        assert items[0].detection_layers == ["layer1"]
        assert items[0].network_provider is None

    def test_neither_returns_empty(self):
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[],
            layer2_findings=[],
        )
        assert items == []

    def test_framework_detection_langgraph(self):
        l1 = self._l1(
            rule_id="DAI003",
            message="LangGraph StateGraph detected (complex stateful workflow)",
        )
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1],
            layer2_findings=[self._l2()],
        )
        assert items[0].framework == "LangGraph"

    def test_framework_detection_langchain(self):
        l1 = self._l1(
            rule_id="DAI003",
            message="LangChain agent initialization detected",
        )
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1],
            layer2_findings=[self._l2()],
        )
        assert items[0].framework == "LangChain"

    def test_framework_detection_chatbedrock(self):
        l1 = self._l1(
            rule_id="DAI007",
            message="AWS Bedrock LLM client detected (ChatBedrock)",
        )
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1],
            layer2_findings=[self._l2()],
        )
        assert items[0].framework == "LangChain"

    def test_framework_detection_aws_sdk(self):
        l1 = self._l1(
            rule_id="DAI007",
            message="AWS Bedrock boto3 client instantiation detected",
        )
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[l1],
            layer2_findings=[self._l2()],
        )
        assert items[0].framework == "AWS SDK"

    def test_multiple_layer1_unmatched_become_zombies(self):
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[self._l1("a.py", 1), self._l1("b.py", 2)],
            layer2_findings=[self._l2()],
        )
        classifications = {i.classification for i in items}
        # One L2 hit → first L1 confirmed, second L1 becomes zombie
        assert "confirmed" in classifications
        assert "zombie" in classifications

    def test_bedrock_hostname_in_layer2_remote_host(self):
        l2 = {
            "remote_host": "bedrock-runtime.us-east-1.amazonaws.com",
            "process_name": "python3",
            "provider": "unknown",
        }
        items = CorrelationEngine.correlate_bedrock_findings(
            layer1_findings=[],
            layer2_findings=[l2],
        )
        assert len(items) == 1
        assert items[0].classification == "ghost"


# ---------------------------------------------------------------------------
# LLM_HOSTNAME_TO_PROVIDER — Bedrock endpoint matching
# ---------------------------------------------------------------------------


class TestBedrockHostnameInference:
    @pytest.mark.parametrize("hostname", [
        "bedrock-runtime.us-east-1.amazonaws.com",
        "bedrock-runtime.eu-west-1.amazonaws.com",
        "bedrock-runtime.ap-southeast-1.amazonaws.com",
        "bedrock-agent-runtime.us-west-2.amazonaws.com",
        "bedrock-agent-runtime.ap-northeast-1.amazonaws.com",
    ])
    def test_bedrock_endpoint_resolves_to_bedrock(self, hostname: str):
        provider = CorrelationEngine._infer_provider_from_address(hostname)
        assert provider == "bedrock", f"{hostname!r} should resolve to 'bedrock', got {provider!r}"

    def test_s3_endpoint_does_not_resolve_as_bedrock(self):
        provider = CorrelationEngine._infer_provider_from_address("s3.us-east-1.amazonaws.com")
        assert provider != "bedrock"

    def test_bedrock_in_providers_set(self):
        assert "bedrock" in CorrelationEngine._PROVIDERS
