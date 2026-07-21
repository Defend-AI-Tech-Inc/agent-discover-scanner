"""
Tests for generation/sampling parameter detection + threshold flags.

Covers:
  signatures.py
    - GenerationParamsSignature (DAI009) — literal/resolved_constant explicit
      detection across OpenAI/Anthropic/LangChain call shapes
  generation_defaults.py
    - resolve_generation_params — framework_default / not_applicable / unknown
      backfill tiers, reasoning-model handling, LangChain vs raw-SDK
      disambiguation, Bedrock nested model-family lookup
    - compute_threshold_flags — HIGH_TEMPERATURE / ZERO_TEMPERATURE /
      UNBOUNDED_MAX_TOKENS
  correlator.py
    - DAI009 findings never become their own inventory item, and merge onto
      same-file framework/provider findings even when on a different line
  aibom.py / audit_reports.py
    - generation_param facts appear in aibom.json; threshold flags never do
      (flags only in generation-params.md)
"""

import ast
import json

import pytest

from agent_discover_scanner.correlator import AgentInventoryItem, CorrelationEngine
from agent_discover_scanner.generation_defaults import (
    classify_bedrock_family,
    classify_wrapper_key,
    compute_threshold_flags,
    is_reasoning_model,
    resolve_generation_params,
)
from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
from agent_discover_scanner.visitor import ContextAwareVisitor


def _visit(source: str, filename: str = "test.py") -> ContextAwareVisitor:
    tree = ast.parse(source, filename=filename)
    visitor = ContextAwareVisitor(filename, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    return visitor


def _dai009(source: str):
    return [f for f in _visit(source).findings if f.rule_id == "DAI009"]


# ---------------------------------------------------------------------------
# DAI009 — explicit literal / resolved_constant detection
# ---------------------------------------------------------------------------


class TestGenerationParamsExplicitDetection:
    def test_openai_temperature_top_p_literal(self):
        code = """
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model="gpt-4o", temperature=0.2, top_p=0.5, messages=[])
"""
        findings = _dai009(code)
        assert len(findings) == 1
        params = findings[0].extracted["generation_params"]
        assert params["temperature"] == {"value": 0.2, "source": "literal"}
        assert params["top_p"] == {"value": 0.5, "source": "literal"}
        assert findings[0].extracted.get("wrapper_hint") == "openai_raw_sdk"

    def test_anthropic_max_tokens_literal(self):
        code = """
import anthropic
client = anthropic.Anthropic()
resp = client.messages.create(model="claude-3-opus-20240229", max_tokens=1024, temperature=0.3)
"""
        findings = _dai009(code)
        assert len(findings) == 1
        params = findings[0].extracted["generation_params"]
        assert params["max_tokens"] == {"value": 1024, "source": "literal"}
        assert params["temperature"] == {"value": 0.3, "source": "literal"}
        assert findings[0].extracted.get("wrapper_hint") == "anthropic_raw_sdk"

    def test_langchain_chatopenai_temperature_literal(self):
        code = """
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4", temperature=0.9)
"""
        findings = _dai009(code)
        assert len(findings) == 1
        params = findings[0].extracted["generation_params"]
        assert params["temperature"] == {"value": 0.9, "source": "literal"}
        assert findings[0].extracted.get("wrapper_hint") == "langchain_chatopenai"

    def test_max_tokens_provider_variants_map_to_canonical(self):
        code = """
resp1 = some_call(max_output_tokens=500)
resp2 = other_call(max_completion_tokens=750)
"""
        findings = _dai009(code)
        assert len(findings) == 2
        assert findings[0].extracted["generation_params"]["max_tokens"] == {
            "value": 500,
            "source": "literal",
        }
        assert findings[1].extracted["generation_params"]["max_tokens"] == {
            "value": 750,
            "source": "literal",
        }

    def test_resolved_constant_temperature(self):
        code = """
TEMP = 0.1
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model="gpt-4o", temperature=TEMP, messages=[])
"""
        findings = _dai009(code)
        assert len(findings) == 1
        params = findings[0].extracted["generation_params"]
        assert params["temperature"] == {"value": 0.1, "source": "resolved_constant"}

    def test_stop_list_literal(self):
        code = """
resp = some_call(stop=["\\n", "END"])
"""
        findings = _dai009(code)
        assert len(findings) == 1
        params = findings[0].extracted["generation_params"]
        assert params["stop"] == {"value": ["\n", "END"], "source": "literal"}

    def test_unresolvable_value_left_absent(self):
        code = """
temp = get_temperature_from_config()
resp = some_call(temperature=temp)
"""
        findings = _dai009(code)
        assert len(findings) == 0

    def test_no_recognized_kwarg_no_finding(self):
        code = """
resp = some_call(model="gpt-4o", messages=[])
"""
        findings = _dai009(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# generation_defaults.resolve_generation_params — provenance tiers
# ---------------------------------------------------------------------------


class TestResolveGenerationParamsTiers:
    def test_openai_raw_sdk_backfills_documented_defaults(self):
        result = resolve_generation_params("openai_raw_sdk", None, {})
        assert result["temperature"] == {"value": 1.0, "source": "framework_default"}
        assert result["top_p"] == {"value": 1.0, "source": "framework_default"}
        assert result["frequency_penalty"] == {"value": 0, "source": "framework_default"}
        assert result["presence_penalty"] == {"value": 0, "source": "framework_default"}
        assert result["top_k"] == {"source": "not_applicable"}
        assert result["max_tokens"] == {"source": "unknown"}

    def test_reasoning_model_never_backfills_temperature_as_default(self):
        """Reasoning models: temperature/top_p/n tagged not_applicable, never framework_default."""
        assert is_reasoning_model("o3-mini") is True
        assert is_reasoning_model("gpt-5-nano") is True
        assert is_reasoning_model("gpt-4o") is False

        wrapper_key = classify_wrapper_key(
            "DAI004", "Unmanaged OpenAI client detected", None, "o3-mini"
        )
        assert wrapper_key == "openai_reasoning"

        result = resolve_generation_params(wrapper_key, "o3-mini", {})
        assert result["temperature"] == {"source": "not_applicable"}
        assert result["top_p"] == {"source": "not_applicable"}
        assert result["n"] == {"source": "not_applicable"}
        assert "value" not in result["temperature"]

    def test_anthropic_max_tokens_absent_is_unknown_not_framework_default(self):
        result = resolve_generation_params("anthropic_raw_sdk", "claude-3-opus-20240229", {})
        assert result["max_tokens"] == {"source": "unknown"}
        # temperature DOES have a documented Anthropic default (1.0)
        assert result["temperature"] == {"value": 1.0, "source": "framework_default"}
        # frequency/presence penalty and n/seed aren't Anthropic API params at all
        assert result["frequency_penalty"] == {"source": "not_applicable"}
        assert result["n"] == {"source": "not_applicable"}

    def test_langchain_chatopenai_vs_raw_openai_sdk_disambiguation(self):
        """Same missing temperature, different backfilled default depending on wrapper."""
        langchain_result = resolve_generation_params("langchain_chatopenai", None, {})
        raw_sdk_result = resolve_generation_params("openai_raw_sdk", None, {})

        assert langchain_result["temperature"] == {"value": 0.7, "source": "framework_default"}
        assert raw_sdk_result["temperature"] == {"value": 1.0, "source": "framework_default"}
        assert langchain_result["temperature"] != raw_sdk_result["temperature"]

    def test_explicit_value_never_overwritten_by_backfill(self):
        explicit = {"temperature": {"value": 0.42, "source": "literal"}}
        result = resolve_generation_params("openai_raw_sdk", None, explicit)
        assert result["temperature"] == {"value": 0.42, "source": "literal"}
        # Other params still get backfilled normally.
        assert result["top_p"] == {"value": 1.0, "source": "framework_default"}

    def test_bedrock_titan_family_backfill(self):
        family = classify_bedrock_family("amazon.titan-text-express-v1")
        assert family == "amazon.titan"
        result = resolve_generation_params("bedrock", "amazon.titan-text-express-v1", {})
        assert result["temperature"] == {"value": 0.7, "source": "framework_default"}
        assert result["top_p"] == {"value": 0.9, "source": "framework_default"}
        assert result["max_tokens"] == {"value": 512, "source": "framework_default"}
        assert result["top_k"] == {"source": "not_applicable"}

    def test_bedrock_unrecognized_family_is_unknown(self):
        result = resolve_generation_params("bedrock", "some.unrecognized-model-v1", {})
        for param in result.values():
            assert param.get("source") == "unknown"

    def test_no_wrapper_key_all_unknown(self):
        result = resolve_generation_params(None, None, {})
        for param in result.values():
            assert param.get("source") == "unknown"
            assert "value" not in param


# ---------------------------------------------------------------------------
# generation_defaults.compute_threshold_flags — informational only
# ---------------------------------------------------------------------------


class TestThresholdFlags:
    def test_high_temperature_flag(self):
        params = resolve_generation_params("openai_raw_sdk", None, {})  # temp 1.0
        flags = compute_threshold_flags(params)
        flag_names = [f["flag"] for f in flags]
        assert "HIGH_TEMPERATURE" in flag_names
        assert "not inherently wrong" in next(
            f["message"] for f in flags if f["flag"] == "HIGH_TEMPERATURE"
        )

    def test_zero_temperature_flag_is_informational(self):
        explicit = {"temperature": {"value": 0, "source": "literal"}}
        params = resolve_generation_params("openai_raw_sdk", None, explicit)
        flags = compute_threshold_flags(params)
        flag_names = [f["flag"] for f in flags]
        assert "ZERO_TEMPERATURE" in flag_names
        assert "HIGH_TEMPERATURE" not in flag_names

    def test_unbounded_max_tokens_flag_when_unknown(self):
        params = resolve_generation_params("openai_raw_sdk", None, {})  # max_tokens -> unknown
        flags = compute_threshold_flags(params)
        assert "UNBOUNDED_MAX_TOKENS" in [f["flag"] for f in flags]

    def test_no_unbounded_flag_when_framework_default_applies(self):
        params = resolve_generation_params("bedrock", "amazon.titan-text-express-v1", {})
        flags = compute_threshold_flags(params)
        assert "UNBOUNDED_MAX_TOKENS" not in [f["flag"] for f in flags]

    def test_no_flags_for_not_applicable_reasoning_model_temperature(self):
        """not_applicable never gets a value, so HIGH/ZERO_TEMPERATURE can't fire on it."""
        params = resolve_generation_params("openai_reasoning", "o3-mini", {})
        flags = compute_threshold_flags(params)
        flag_names = [f["flag"] for f in flags]
        assert "HIGH_TEMPERATURE" not in flag_names
        assert "ZERO_TEMPERATURE" not in flag_names


# ---------------------------------------------------------------------------
# correlator.py — DAI009 merges onto same-file findings, never its own item
# ---------------------------------------------------------------------------


class TestCorrelatorGenerationParamsMerge:
    def test_dai009_merges_across_different_line_same_file(self):
        """Realistic shape: temperature set on the ChatOpenAI() line, agent
        initialized on a different line -- must still merge via same-file index."""
        code_findings = [
            {
                "rule_id": "DAI009",
                "file_path": "agent.py",
                "line": 4,
                "message": "Generation parameters declared: temperature",
                "level": "note",
                "extracted": {
                    "generation_params": {"temperature": {"value": 0, "source": "literal"}},
                    "wrapper_hint": "langchain_chatopenai",
                },
            },
            {
                "rule_id": "DAI003",
                "file_path": "agent.py",
                "line": 6,
                "message": "LangChain agent initialization detected",
                "level": "warning",
            },
        ]
        inventory = CorrelationEngine.correlate(code_findings=code_findings)
        all_items = [item for items in inventory.values() for item in items]

        assert not any(item.rule_id == "DAI009" for item in all_items)

        langchain_items = [item for item in all_items if item.rule_id == "DAI003"]
        assert len(langchain_items) == 1
        item = langchain_items[0]
        assert item.generation_params is not None
        assert item.generation_params["temperature"] == {"value": 0, "source": "literal"}
        # Backfilled from the langchain_chatopenai table for unset params.
        assert item.generation_params["n"] == {"value": 1, "source": "framework_default"}
        flag_names = [f["flag"] for f in item.generation_param_flags]
        assert "ZERO_TEMPERATURE" in flag_names

    def test_dai009_without_signal_produces_no_generation_params(self):
        """No explicit params and no resolvable wrapper -> generation_params stays None
        (avoids blanket 'unknown' noise for agents we know nothing about)."""
        code_findings = [
            {
                "rule_id": "DAI002",
                "file_path": "crew.py",
                "line": 5,
                "message": "CrewAI Agent detected",
                "level": "warning",
            },
        ]
        inventory = CorrelationEngine.correlate(code_findings=code_findings)
        all_items = [item for items in inventory.values() for item in items]
        assert len(all_items) == 1
        assert all_items[0].generation_params is None
        assert all_items[0].generation_param_flags == []

    def test_dai009_without_colocated_or_same_file_finding_produces_no_item(self):
        code_findings = [
            {
                "rule_id": "DAI009",
                "file_path": "agent.py",
                "line": 5,
                "message": "Generation parameters declared: temperature",
                "level": "note",
                "extracted": {
                    "generation_params": {"temperature": {"value": 0.5, "source": "literal"}}
                },
            },
        ]
        inventory = CorrelationEngine.correlate(code_findings=code_findings)
        all_items = [item for items in inventory.values() for item in items]
        assert len(all_items) == 0


# ---------------------------------------------------------------------------
# aibom.py / audit_reports.py — flags never appear in aibom.json
# ---------------------------------------------------------------------------


class TestAibomExcludesThresholdFlags:
    def test_generation_param_facts_in_aibom_but_flags_excluded(self, tmp_path):
        from agent_discover_scanner.aibom import generate_aibom

        item = AgentInventoryItem(
            agent_id="agent.py:6",
            classification="unknown",
            risk_level="medium",
            framework="LangChain/LangGraph",
            rule_id="DAI003",
            generation_params={
                "temperature": {"value": 1.0, "source": "framework_default"},
                "max_tokens": {"source": "unknown"},
            },
            generation_param_flags=[
                {"flag": "HIGH_TEMPERATURE", "message": "elevated ..."},
                {"flag": "UNBOUNDED_MAX_TOKENS", "message": "cost signal ..."},
            ],
        )
        inventory_path = tmp_path / "agent_inventory.json"
        inventory_path.write_text(
            json.dumps({"inventory": {"unknown": [item.to_dict()]}}), encoding="utf-8"
        )
        aibom_path = tmp_path / "aibom.json"
        generate_aibom(inventory_path, aibom_path)

        aibom_text = aibom_path.read_text(encoding="utf-8")
        assert "HIGH_TEMPERATURE" not in aibom_text
        assert "UNBOUNDED_MAX_TOKENS" not in aibom_text
        assert "agent-discover:declared_temperature" in aibom_text
        assert "agent-discover:declared_temperature_source" in aibom_text

        aibom_data = json.loads(aibom_text)
        props = aibom_data["components"][0]["properties"]
        prop_names = {p["name"] for p in props}
        assert "agent-discover:declared_temperature" in prop_names
        assert "agent-discover:declared_max_tokens_source" in prop_names
        # max_tokens has no numeric value (unknown tier) -> no declared_max_tokens property
        assert "agent-discover:declared_max_tokens" not in prop_names

    def test_generation_params_report_includes_flags(self, tmp_path):
        from agent_discover_scanner.audit_reports import write_generation_params_markdown

        item = AgentInventoryItem(
            agent_id="agent.py:6",
            classification="unknown",
            risk_level="medium",
            framework="LangChain/LangGraph",
            rule_id="DAI003",
            generation_params={
                "temperature": {"value": 1.0, "source": "framework_default"},
            },
            generation_param_flags=[
                {"flag": "HIGH_TEMPERATURE", "message": "elevated relative to typical use"},
            ],
        )
        inventory_path = tmp_path / "agent_inventory.json"
        inventory_path.write_text(
            json.dumps({"inventory": {"unknown": [item.to_dict()]}}), encoding="utf-8"
        )
        dest = tmp_path / "generation-params.md"
        write_generation_params_markdown(inventory_path, dest)

        report_text = dest.read_text(encoding="utf-8")
        assert "HIGH_TEMPERATURE" in report_text
        assert "informational" in report_text.lower()
        assert "agent.py:6" in report_text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
