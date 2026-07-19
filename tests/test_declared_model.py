"""
Tests for tiered model identification (declared_model / runtime_env_model).

Covers:
  signatures.py
    - DeclaredModelSignature (DAI008) — literal model-kwarg detection across
      OpenAI/Anthropic/Azure/Bedrock call shapes
    - resolved_constant kwarg resolution via ContextAwareVisitor.constant_map
    - negative case: unresolvable Name (loaded from a function call) never
      populates declared_model
  process_introspection.py
    - _extract_runtime_env_model — allowlist/denylist enforcement so that API
      keys/secrets never leak into the returned result
  correlator.py
    - DAI008 findings never become their own inventory item, and instead merge
      onto a co-located framework/provider finding
"""

import ast
from unittest.mock import MagicMock, patch

import psutil
import pytest

from agent_discover_scanner.correlator import CorrelationEngine
from agent_discover_scanner.process_introspection import _extract_runtime_env_model
from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
from agent_discover_scanner.visitor import ContextAwareVisitor


def _visit(source: str, filename: str = "test.py") -> ContextAwareVisitor:
    tree = ast.parse(source, filename=filename)
    visitor = ContextAwareVisitor(filename, signature_registry=SIGNATURE_REGISTRY)
    visitor.visit(tree)
    return visitor


def _dai008(source: str):
    return [f for f in _visit(source).findings if f.rule_id == "DAI008"]


# ---------------------------------------------------------------------------
# DAI008 — literal declared_model detection
# ---------------------------------------------------------------------------


class TestDeclaredModelLiteral:
    def test_openai_model_kwarg(self):
        code = """
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model="gpt-4o", messages=[])
"""
        findings = _dai008(code)
        assert len(findings) == 1
        # wrapper_hint is additive metadata (v2.10.0+, used to backfill
        # generation-param defaults) — declared_model/_source are unaffected.
        assert findings[0].extracted["declared_model"] == "gpt-4o"
        assert findings[0].extracted["declared_model_source"] == "literal"
        assert findings[0].extracted.get("wrapper_hint") == "openai_raw_sdk"

    def test_anthropic_model_kwarg(self):
        code = """
import anthropic
client = anthropic.Anthropic()
resp = client.messages.create(model="claude-3-opus-20240229", max_tokens=10)
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "claude-3-opus-20240229"
        assert findings[0].extracted["declared_model_source"] == "literal"

    def test_azure_deployment_name_kwarg(self):
        code = """
from langchain_openai import AzureChatOpenAI
llm = AzureChatOpenAI(deployment_name="my-gpt4-deployment")
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "my-gpt4-deployment"
        assert findings[0].extracted["declared_model_source"] == "literal"

    def test_azure_deployment_kwarg(self):
        code = """
from openai import AzureOpenAI
client = AzureOpenAI(azure_deployment="prod-gpt4o")
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "prod-gpt4o"

    def test_bedrock_model_id_kwarg(self):
        code = """
import boto3
client = boto3.client("bedrock-runtime")
response = client.invoke_model(modelId="anthropic.claude-3-sonnet-20240229-v1:0", body=b"")
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert findings[0].extracted["declared_model_source"] == "literal"

    def test_legacy_engine_kwarg(self):
        code = """
import openai
resp = openai.Completion.create(engine="text-davinci-003", prompt="hi")
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "text-davinci-003"

    def test_model_name_kwarg(self):
        code = """
from langchain.chat_models import ChatOpenAI
llm = ChatOpenAI(model_name="gpt-3.5-turbo")
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "gpt-3.5-turbo"


# ---------------------------------------------------------------------------
# resolved_constant — Name resolves back to a same-file constant assignment
# ---------------------------------------------------------------------------


class TestDeclaredModelResolvedConstant:
    def test_name_resolves_to_module_level_constant(self):
        code = """
MODEL_NAME = "gpt-4-turbo"
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model=MODEL_NAME, messages=[])
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "gpt-4-turbo"
        assert findings[0].extracted["declared_model_source"] == "resolved_constant"
        assert findings[0].extracted.get("wrapper_hint") == "openai_raw_sdk"

    def test_name_resolves_regardless_of_declaration_order(self):
        """Flow-insensitive prepass: constant map is built before any Call is visited."""
        code = """
import boto3
client = boto3.client("bedrock-runtime")
response = client.invoke_model(modelId=BEDROCK_MODEL_ID, body=b"")
BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
"""
        findings = _dai008(code)
        assert len(findings) == 1
        assert findings[0].extracted["declared_model"] == "amazon.titan-text-express-v1"
        assert findings[0].extracted["declared_model_source"] == "resolved_constant"


# ---------------------------------------------------------------------------
# Negative case — unresolvable Name must never populate declared_model
# ---------------------------------------------------------------------------


class TestDeclaredModelUnresolvable:
    def test_name_from_function_call_not_resolved(self):
        """Name loaded from a function call (not a literal assign) — no guessing."""
        code = """
import openai
client = openai.OpenAI()
model_id = get_model_from_config()
resp = client.chat.completions.create(model=model_id, messages=[])
"""
        findings = _dai008(code)
        assert len(findings) == 0

    def test_name_from_env_lookup_not_resolved(self):
        code = """
import os
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model=os.environ["MODEL"], messages=[])
"""
        findings = _dai008(code)
        assert len(findings) == 0

    def test_no_recognized_kwarg_no_finding(self):
        code = """
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(temperature=0.5, messages=[])
"""
        findings = _dai008(code)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# process_introspection._extract_runtime_env_model — allow/denylist safety
# ---------------------------------------------------------------------------


class TestRuntimeEnvModelReader:
    def _mock_process(self, environ: dict):
        mock_proc = MagicMock()
        mock_proc.environ.return_value = environ
        return mock_proc

    def test_model_name_extracted_api_key_never_present(self):
        environ = {
            "MODEL_NAME": "gpt-4o-mini",
            "OPENAI_API_KEY": "sk-super-secret-value",
            "PATH": "/usr/bin",
        }
        with patch("psutil.Process", return_value=self._mock_process(environ)):
            model, source = _extract_runtime_env_model(1234)

        assert model == "gpt-4o-mini"
        assert source == "MODEL_NAME"
        # The API key must never appear anywhere in the returned result.
        assert "sk-super-secret-value" not in (model or "")
        assert "sk-super-secret-value" not in (source or "")
        assert model != "sk-super-secret-value"

    def test_denylist_overrides_allowlist_on_overlap(self):
        """A key matching both allow + deny patterns (e.g. MODEL_API_KEY) must be dropped."""
        environ = {
            "MODEL_API_KEY": "sk-should-never-leak",
        }
        with patch("psutil.Process", return_value=self._mock_process(environ)):
            model, source = _extract_runtime_env_model(1234)
        assert model is None
        assert source is None

    def test_deployment_env_var_matches_allowlist(self):
        environ = {"AZURE_DEPLOYMENT": "prod-gpt4"}
        with patch("psutil.Process", return_value=self._mock_process(environ)):
            model, source = _extract_runtime_env_model(1234)
        assert model == "prod-gpt4"
        assert source == "AZURE_DEPLOYMENT"

    def test_engine_env_var_suffix_matches_allowlist(self):
        environ = {"LLM_ENGINE": "gpt-4"}
        with patch("psutil.Process", return_value=self._mock_process(environ)):
            model, source = _extract_runtime_env_model(1234)
        assert model == "gpt-4"
        assert source == "LLM_ENGINE"

    def test_no_matching_env_vars_returns_none(self):
        environ = {"PATH": "/usr/bin", "HOME": "/root"}
        with patch("psutil.Process", return_value=self._mock_process(environ)):
            model, source = _extract_runtime_env_model(1234)
        assert model is None
        assert source is None

    def test_access_denied_never_raises(self):
        with patch("psutil.Process", side_effect=psutil.AccessDenied()):
            model, source = _extract_runtime_env_model(1234)
        assert model is None
        assert source is None

    def test_no_such_process_never_raises(self):
        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(1234)):
            model, source = _extract_runtime_env_model(1234)
        assert model is None
        assert source is None

    def test_unexpected_exception_never_raises(self):
        with patch("psutil.Process", side_effect=RuntimeError("boom")):
            model, source = _extract_runtime_env_model(1234)
        assert model is None
        assert source is None


# ---------------------------------------------------------------------------
# correlator.py — DAI008 merges onto co-located finding, never its own item
# ---------------------------------------------------------------------------


class TestCorrelatorDeclaredModelMerge:
    def test_dai008_merges_onto_colocated_langchain_finding(self):
        code_findings = [
            {
                "rule_id": "DAI003",
                "file_path": "agent.py",
                "line": 10,
                "message": "LangChain agent initialization detected",
                "level": "warning",
            },
            {
                "rule_id": "DAI008",
                "file_path": "agent.py",
                "line": 10,
                "message": "Declared model identifier detected: 'gpt-4'",
                "level": "note",
                "extracted": {"declared_model": "gpt-4", "declared_model_source": "literal"},
            },
        ]
        inventory = CorrelationEngine.correlate(code_findings=code_findings)
        all_items = [item for items in inventory.values() for item in items]

        # DAI008 never becomes its own inventory item.
        assert not any(item.rule_id == "DAI008" for item in all_items)

        # Its declared_model data merges onto the co-located DAI003 item.
        langchain_items = [item for item in all_items if item.rule_id == "DAI003"]
        assert len(langchain_items) == 1
        assert langchain_items[0].declared_model == "gpt-4"
        assert langchain_items[0].declared_model_source == "literal"

    def test_dai008_without_colocated_finding_produces_no_item(self):
        code_findings = [
            {
                "rule_id": "DAI008",
                "file_path": "agent.py",
                "line": 5,
                "message": "Declared model identifier detected: 'gpt-4'",
                "level": "note",
                "extracted": {"declared_model": "gpt-4", "declared_model_source": "literal"},
            },
        ]
        inventory = CorrelationEngine.correlate(code_findings=code_findings)
        all_items = [item for items in inventory.values() for item in items]
        assert len(all_items) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
