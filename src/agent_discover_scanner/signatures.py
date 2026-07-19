"""
Signature registry for detecting AI agent frameworks and patterns.
"""

import ast
from abc import ABC, abstractmethod
from typing import Any, Optional

from agent_discover_scanner.visitor import ContextAwareVisitor, Finding

# Keyword argument names used across LLM/agent SDKs to declare which model to call.
# Kept intentionally narrow (AI-SDK-specific names) to minimize false positives.
_MODEL_KWARGS = frozenset({
    "model",            # OpenAI, Anthropic, Google Gemini, most SDKs
    "model_name",       # older LangChain ChatOpenAI et al.
    "deployment_name",  # Azure OpenAI
    "azure_deployment",  # Azure OpenAI
    "modelId",          # boto3 Bedrock invoke_model
    "engine",           # legacy OpenAI
})


def extract_declared_model(
    node: ast.Call, visitor: ContextAwareVisitor
) -> Optional[dict[str, Any]]:
    """
    Inspect a call's keyword arguments for a known model-identifier parameter.

    Returns {"declared_model": ..., "declared_model_source": "literal"} when the
    value is a string constant, or {"declared_model": ..., "declared_model_source":
    "resolved_constant"} when the value is a `Name` that resolves back to a
    same-file constant assignment (see ContextAwareVisitor.constant_map).

    Returns None when no recognized kwarg is present, or when a `Name` value
    cannot be resolved — we never guess at a model identifier.
    """
    for keyword in node.keywords:
        if keyword.arg not in _MODEL_KWARGS:
            continue

        value_node = keyword.value
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            return {"declared_model": value_node.value, "declared_model_source": "literal"}

        if isinstance(value_node, ast.Name):
            resolved = visitor.constant_map.get(value_node.id)
            if isinstance(resolved, str):
                return {"declared_model": resolved, "declared_model_source": "resolved_constant"}

    return None


# Keyword argument names for generation/sampling parameters, mapped to their
# canonical form. Several providers use different names for the same concept
# (e.g. OpenAI's `max_tokens` vs. the newer `max_completion_tokens` used by
# reasoning models, vs. Google/Vertex's `max_output_tokens`); these all
# collapse to one canonical key so the defaults table doesn't need to know
# about every provider's naming quirk.
_GENERATION_PARAM_KWARGS: dict[str, str] = {
    "temperature": "temperature",
    "top_p": "top_p",
    "top_k": "top_k",
    "max_tokens": "max_tokens",
    "max_output_tokens": "max_tokens",
    "max_completion_tokens": "max_tokens",
    "frequency_penalty": "frequency_penalty",
    "presence_penalty": "presence_penalty",
    "stop": "stop",
    "stop_sequences": "stop",  # Anthropic / Cohere naming
    "seed": "seed",
    "n": "n",
}


def _literal_value(node: ast.AST) -> tuple[Any, bool]:
    """Return (value, True) if `node` is a literal we're willing to extract, else (None, False).

    Handles plain constants (str/int/float/bool/None) and lists/tuples of
    constants (needed for `stop`, e.g. `stop=["\\n", "END"]`).
    """
    if isinstance(node, ast.Constant):
        return node.value, True
    if isinstance(node, (ast.List, ast.Tuple)):
        values = []
        for element in node.elts:
            if not isinstance(element, ast.Constant):
                return None, False
            values.append(element.value)
        return values, True
    return None, False


def extract_generation_params(
    node: ast.Call, visitor: ContextAwareVisitor
) -> dict[str, dict[str, Any]]:
    """
    Inspect a call's keyword arguments for known generation/sampling parameters.

    Same extraction rule as `extract_declared_model`: a literal value gets
    source "literal"; a `Name` resolved via the prepass constant map gets
    source "resolved_constant"; anything else is left absent — we never guess.

    Returns a dict keyed by *canonical* parameter name (see
    _GENERATION_PARAM_KWARGS), e.g. {"temperature": {"value": 0.7, "source": "literal"}}.
    Only includes parameters actually found and resolved; may be empty.
    """
    found: dict[str, dict[str, Any]] = {}
    for keyword in node.keywords:
        canonical = _GENERATION_PARAM_KWARGS.get(keyword.arg or "")
        if canonical is None:
            continue

        value_node = keyword.value
        value, is_literal = _literal_value(value_node)
        if is_literal:
            found[canonical] = {"value": value, "source": "literal"}
            continue

        if isinstance(value_node, ast.Name):
            resolved = visitor.constant_map.get(value_node.id)
            if resolved is not None:
                found[canonical] = {"value": resolved, "source": "resolved_constant"}

    return found


def _resolve_call_func_name(node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
    """Shared attribute-chain function-name resolver (mirrors each Signature's own helper)."""
    if isinstance(node.func, ast.Name):
        return visitor.resolve_name(node.func.id)
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            base = visitor.resolve_name(node.func.value.id)
            return f"{base}.{node.func.attr}"
        if isinstance(node.func.value, ast.Attribute):
            parts = [node.func.attr]
            current: ast.AST = node.func.value
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            resolved_root = visitor.resolve_name(parts[0])
            return ".".join([resolved_root] + parts[1:])
    return None


def _classify_wrapper(func_name: Optional[str]) -> Optional[str]:
    """
    Classify a call-site function name into a defaults-table wrapper key.

    This is a best-effort *hint* used by the correlator to look up the right
    entry in the generation-param defaults table (see generation_defaults.py).
    It never creates or blocks a Finding by itself.
    """
    if not func_name:
        return None
    fn = func_name.lower()

    if "chatopenai" in fn or ("langchain" in fn and "openai" in fn):
        return "langchain_chatopenai"
    if "chatanthropic" in fn:
        return "langchain_chatanthropic"
    if "chatbedrock" in fn or "bedrockllm" in fn or "bedrockchat" in fn:
        return "bedrock"
    if fn.startswith("azureopenai.") or "azure_openai" in fn or "azurechatopenai" in fn:
        return "azure_openai_raw_sdk"
    if (
        fn.startswith("openai.")
        or ".chat.completions.create" in fn
        or fn.endswith(".completions.create")
    ):
        return "openai_raw_sdk"
    if fn.startswith("anthropic.") or fn.endswith(".messages.create") or "anthropicbedrock" in fn:
        return "bedrock" if "anthropicbedrock" in fn else "anthropic_raw_sdk"
    if fn.endswith(".invoke_model") or fn == "invoke_model":
        return "bedrock"
    return None


class Signature(ABC):
    """Base class for detection signatures."""

    @abstractmethod
    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        """
        Check if this node matches the signature pattern.

        Returns:
            Finding if pattern detected, None otherwise
        """
        pass

    # Optional hook for signatures that operate on string literals / constants
    def check_constant(self, node: ast.Constant, visitor: ContextAwareVisitor) -> Optional[Finding]:  # type: ignore[override]
        return None


class AutoGenSignature(Signature):
    """
    Detect AutoGen AssistantAgent instantiations.

    Risk Level: HIGH if code_execution_config is enabled
    Target: autogen.AssistantAgent or autogen.agentchat.AssistantAgent
    """

    RULE_ID = "DAI001"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        # Get the function being called
        func_name = self._get_function_name(node, visitor)

        if not func_name:
            return None

        # Check if it's AssistantAgent
        if "AssistantAgent" not in func_name:
            return None

        # Check if it's from autogen
        if not (func_name.startswith("autogen.") or func_name.startswith("autogen_agentchat.")):
            return None

        # Check for code execution capability
        has_code_exec = self._check_code_execution(node)

        severity = "error" if has_code_exec else "warning"
        message = (
            f"AutoGen AssistantAgent detected"
            f"{' with CODE EXECUTION enabled (HIGH RISK)' if has_code_exec else ''}"
        )

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message=message,
            severity=severity,
        )

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        """Extract and resolve the function name."""
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            # Handle obj.method()
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # Handle deeply nested like autogen.agentchat.AssistantAgent
                parts = self._extract_attribute_chain(node.func)
                if parts:
                    resolved_root = visitor.resolve_name(parts[0])
                    return ".".join([resolved_root] + parts[1:])
        return None

    def _extract_attribute_chain(self, attr_node: ast.Attribute) -> list[str]:
        """Extract full attribute chain like ['autogen', 'agentchat', 'AssistantAgent']."""
        parts = [attr_node.attr]
        current = attr_node.value

        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.insert(0, current.id)

        return parts

    def _check_code_execution(self, node: ast.Call) -> bool:
        """Check if code_execution_config is enabled."""
        for keyword in node.keywords:
            if keyword.arg == "code_execution_config":
                # If it's explicitly set to False, it's safe
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    return False
                # Any other value (dict, True, etc.) means enabled
                return True
        return False


class CrewAISignature(Signature):
    """
    Detect CrewAI Agent instantiations.

    Risk Level: HIGH if allow_code_execution=True
    Target: crewai.Agent
    """

    RULE_ID = "DAI002"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)

        if not func_name:
            return None

        # Check if it's a CrewAI Agent
        if not (func_name == "crewai.Agent" or func_name.endswith(".Agent")):
            return None

        if "crewai" not in func_name.lower():
            return None

        # Check for code execution
        has_code_exec = self._check_code_execution(node, visitor)

        severity = "error" if has_code_exec else "warning"
        message = (
            f"CrewAI Agent detected"
            f"{' with CODE EXECUTION enabled (HIGH RISK)' if has_code_exec else ''}"
        )

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message=message,
            severity=severity,
        )

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        """Extract and resolve the function name."""
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
        return None

    def _check_code_execution(self, node: ast.Call, visitor: ContextAwareVisitor) -> bool:
        """Check if allow_code_execution=True or CodeInterpreterTool is used."""
        # Check allow_code_execution parameter
        for keyword in node.keywords:
            if keyword.arg == "allow_code_execution":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return True

        # Check for CodeInterpreterTool in tools parameter
        for keyword in node.keywords:
            if keyword.arg == "tools":
                if self._has_code_interpreter_tool(keyword.value, visitor):
                    return True

        return False

    def _has_code_interpreter_tool(self, node: ast.AST, visitor: ContextAwareVisitor) -> bool:
        """Check if CodeInterpreterTool is in the tools list."""
        if isinstance(node, ast.List):
            for element in node.elts:
                if isinstance(element, ast.Call):
                    func_name = self._get_function_name(element, visitor)
                    if func_name and "CodeInterpreterTool" in func_name:
                        return True
        return False


class LangChainSignature(Signature):
    """
    Detect LangChain and LangGraph agent patterns.

    Targets:
    - langchain.agents.initialize_agent (legacy)
    - langchain.agents.create_agent
    - langgraph.graph.StateGraph (complex workflows)
    - langgraph.prebuilt.ToolNode
    - add_node / add_edge method calls when langgraph is imported
    """

    RULE_ID = "DAI003"

    # LangGraph-specific class names (checked against resolved func_name)
    _LANGGRAPH_CLASSES = frozenset({"StateGraph", "ToolNode", "MessagesState"})
    # Generic method names that are LangGraph workflow orchestration when langgraph is imported
    _LANGGRAPH_METHODS = frozenset({"add_node", "add_edge"})

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)

        if not func_name:
            return None

        # LangChain agent initialization
        if "initialize_agent" in func_name or "create_agent" in func_name:
            if "langchain" in func_name:
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message="LangChain agent initialization detected",
                    severity="warning",
                )

        # StateGraph — strongest LangGraph signal
        if "StateGraph" in func_name and "langgraph" in func_name:
            return Finding(
                file_path=visitor.filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule_id=self.RULE_ID,
                message="LangGraph StateGraph detected (complex stateful workflow) - Consider enabling AgentWatch deep tracing",
                severity="note",
            )

        # ToolNode / MessagesState when imported from langgraph
        for class_name in self._LANGGRAPH_CLASSES - {"StateGraph"}:
            if class_name in func_name and "langgraph" in func_name:
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message=f"LangGraph {class_name} detected — graph is stateful and should be traced",
                    severity="note",
                )

        # add_node / add_edge — workflow construction methods; only flag when langgraph is imported
        for method in self._LANGGRAPH_METHODS:
            if func_name.endswith(f".{method}"):
                if any("langgraph" in imp for imp in visitor.imports):
                    return Finding(
                        file_path=visitor.filename,
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        rule_id=self.RULE_ID,
                        message=f"LangGraph workflow method detected ({method}) — graph is stateful and should be traced",
                        severity="note",
                    )

        return None

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        """Extract and resolve the function name."""
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                parts = self._extract_attribute_chain(node.func)
                if parts:
                    resolved_root = visitor.resolve_name(parts[0])
                    return ".".join([resolved_root] + parts[1:])
        return None

    def _extract_attribute_chain(self, attr_node: ast.Attribute) -> list[str]:
        """Extract full attribute chain."""
        parts = [attr_node.attr]
        current = attr_node.value

        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.insert(0, current.id)

        return parts


class ShadowAISignature(Signature):
    """
    Detect raw LLM client usage (Shadow AI).

    Risk: Unmanaged LLM access without DefendAI Gateway
    Targets: openai.OpenAI, anthropic.Anthropic
    """

    RULE_ID = "DAI004"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)

        if not func_name:
            return None

        # Detect OpenAI client instantiation
        if func_name in ["openai.OpenAI", "openai.AsyncOpenAI"]:
            # Check if base_url points to DefendAI Gateway
            if self._has_defendai_gateway(node):
                return None  # Safe - using gateway

            return Finding(
                file_path=visitor.filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule_id=self.RULE_ID,
                message="Unmanaged OpenAI client detected (Shadow AI) - Should use DefendAI Gateway",
                severity="error",
            )

        # Detect Anthropic client instantiation
        if func_name in ["anthropic.Anthropic", "anthropic.AsyncAnthropic"]:
            if self._has_defendai_gateway(node):
                return None

            return Finding(
                file_path=visitor.filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule_id=self.RULE_ID,
                message="Unmanaged Anthropic client detected (Shadow AI) - Should use DefendAI Gateway",
                severity="error",
            )

        return None

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        """Extract and resolve the function name."""
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
        return None

    def _has_defendai_gateway(self, node: ast.Call) -> bool:
        """Check if base_url points to DefendAI Gateway."""
        for keyword in node.keywords:
            if keyword.arg == "base_url":
                if isinstance(keyword.value, ast.Constant):
                    url = keyword.value.value
                    if isinstance(url, str) and "defendai" in url.lower():
                        return True
        return False


class DirectHttpLlmClientSignature(Signature):
    """
    Detect direct HTTP clients used for LLM access in the same file as known LLM API URLs.

    Targets:
      - httpx.AsyncClient
      - httpx.Client
      - aiohttp.ClientSession
      - requests.Session
      - requests.post / requests.get
    """

    RULE_ID = "DAI005"

    HTTP_CLIENT_TARGETS = {
        "httpx.AsyncClient",
        "httpx.Client",
        "aiohttp.ClientSession",
        "requests.Session",
        "requests.post",
        "requests.get",
    }

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)
        if not func_name:
            return None

        if func_name not in self.HTTP_CLIENT_TARGETS:
            return None

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message="Direct HTTP LLM client detected (Shadow AI) — bypasses SDK governance layer",
            severity="warning",
        )

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
        return None


class LlmApiStringSignature(Signature):
    """
    Detect known LLM API endpoint hostnames in string literals.

    This runs on all ast.Constant string nodes.
    """

    RULE_ID = "DAI006"

    LLM_API_HOSTNAMES = (
        "api.openai.com",
        "api.anthropic.com",
        "api.groq.com",
        "api.deepseek.com",
        "api.perplexity.ai",
        "generativelanguage.googleapis.com",
        "api.cohere.com",
        "api.mistral.ai",
        "api.together.xyz",
        "api.huggingface.co",
    )

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        # This signature operates on constants via check_constant
        return None

    def check_constant(self, node: ast.Constant, visitor: ContextAwareVisitor) -> Optional[Finding]:  # type: ignore[override]
        value = getattr(node, "value", None)
        if not isinstance(value, str):
            return None

        matched_hosts = [host for host in self.LLM_API_HOSTNAMES if host in value]
        if not matched_hosts:
            return None

        # Mark on the visitor that this file contains LLM API strings
        setattr(visitor, "llm_api_strings_present", True)
        if hasattr(visitor, "llm_api_hosts"):
            visitor.llm_api_hosts.update(matched_hosts)  # type: ignore[attr-defined]

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message="LLM API endpoint string detected — direct HTTP access without SDK governance",
            severity="warning",
        )


class BedrockSignature(Signature):
    """
    Detect AWS Bedrock runtime usage — Layer 1 static code analysis.

    Targets:
    - ChatBedrock, BedrockLLM, BedrockEmbeddings (langchain_aws / langchain_community)
    - boto3.client("bedrock-runtime") / boto3.client("bedrock-agent-runtime")
    - AnthropicBedrock (anthropic SDK Bedrock adapter)
    - invoke_model() when Bedrock-related imports are present
    - Model ID strings: mistral.mistral-large, anthropic.claude-, amazon.titan-, meta.llama, cohere.command
    """

    RULE_ID = "DAI007"

    _BEDROCK_CLASS_NAMES = frozenset({
        "ChatBedrock",
        "BedrockLLM",
        "BedrockChat",
        "BedrockEmbeddings",
        "AnthropicBedrock",
    })

    # Module paths that indicate Bedrock is in use
    _BEDROCK_IMPORT_MARKERS = (
        "langchain_aws",
        "langchain_community.llms.bedrock",
        "langchain_community.chat_models.bedrock",
        "boto3",
        "anthropic",
    )

    # Bedrock-specific model ID prefixes / service name substrings in string literals
    _BEDROCK_STRING_MARKERS = (
        "bedrock-runtime",
        "bedrock-agent-runtime",
        "mistral.mistral-large",
        "anthropic.claude-",
        "amazon.titan-",
        "meta.llama",
        "cohere.command",
    )

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)
        if not func_name:
            return None

        # ChatBedrock / BedrockLLM / etc.
        for class_name in self._BEDROCK_CLASS_NAMES:
            if class_name in func_name:
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message=f"AWS Bedrock LLM client detected ({class_name})",
                    severity="warning",
                )

        # boto3.client("bedrock-runtime") or boto3.client("bedrock-agent-runtime")
        if func_name.endswith(".client") and "boto3" in func_name:
            if self._has_bedrock_service_arg(node):
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message="AWS Bedrock boto3 client instantiation detected",
                    severity="warning",
                )

        # invoke_model() — only when Bedrock imports are present (avoids false positives)
        if func_name.endswith(".invoke_model") or func_name == "invoke_model":
            all_imports = " ".join(visitor.imports)
            if any(marker in all_imports for marker in self._BEDROCK_IMPORT_MARKERS):
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message="AWS Bedrock invoke_model call detected",
                    severity="warning",
                )

        return None

    # Subset of _BEDROCK_STRING_MARKERS that are model-ID prefixes (as opposed to
    # service/endpoint markers like "bedrock-runtime") — only these populate
    # `extracted.declared_model`, since the endpoint markers aren't model identifiers.
    _BEDROCK_MODEL_ID_MARKERS = frozenset({
        "mistral.mistral-large",
        "anthropic.claude-",
        "amazon.titan-",
        "meta.llama",
        "cohere.command",
    })

    def check_constant(self, node: ast.Constant, visitor: ContextAwareVisitor) -> Optional[Finding]:  # type: ignore[override]
        value = getattr(node, "value", None)
        if not isinstance(value, str):
            return None

        val_lower = value.lower()
        for marker in self._BEDROCK_STRING_MARKERS:
            if marker in val_lower:
                extracted = (
                    {"declared_model": value, "declared_model_source": "literal"}
                    if marker in self._BEDROCK_MODEL_ID_MARKERS
                    else None
                )
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message=f"AWS Bedrock model/endpoint string detected: {marker!r}",
                    severity="note",
                    extracted=extracted,
                )

        return None

    def _get_function_name(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return visitor.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base = visitor.resolve_name(node.func.value.id)
                return f"{base}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                parts = self._extract_attribute_chain(node.func)
                if parts:
                    resolved_root = visitor.resolve_name(parts[0])
                    return ".".join([resolved_root] + parts[1:])
        return None

    def _extract_attribute_chain(self, attr_node: ast.Attribute) -> list[str]:
        parts = [attr_node.attr]
        current = attr_node.value
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.insert(0, current.id)
        return parts

    def _has_bedrock_service_arg(self, node: ast.Call) -> bool:
        """Return True if boto3.client() is called with a bedrock-* service name."""
        if node.args and isinstance(node.args[0], ast.Constant):
            if "bedrock" in str(node.args[0].value).lower():
                return True
        for kw in node.keywords:
            if kw.arg == "service_name" and isinstance(kw.value, ast.Constant):
                if "bedrock" in str(kw.value.value).lower():
                    return True
        return False


class DeclaredModelSignature(Signature):
    """
    Detect declared model identifiers on any call — Layer 1 static ``declared_model``
    tier (see extract_declared_model / _MODEL_KWARGS).

    This does not by itself imply an AI agent/framework is present (it's purely a
    metadata-enrichment signal); the correlator merges its ``extracted`` payload
    onto a co-located framework/provider finding (DAI001-DAI007 at the same
    file+line) rather than treating it as an independent agent signal.
    """

    RULE_ID = "DAI008"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        extracted = extract_declared_model(node, visitor)
        if not extracted:
            return None

        wrapper_hint = _classify_wrapper(_resolve_call_func_name(node, visitor))
        if wrapper_hint:
            extracted["wrapper_hint"] = wrapper_hint

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message=f"Declared model identifier detected: {extracted['declared_model']!r}",
            severity="note",
            extracted=extracted,
        )


class GenerationParamsSignature(Signature):
    """
    Detect generation/sampling parameters declared on any call — Layer 1 static
    "explicit" tier (see extract_generation_params / _GENERATION_PARAM_KWARGS).

    Like DeclaredModelSignature (DAI008), this is a metadata-enrichment signal
    only, never an independent agent signal by itself. The correlator merges
    its `extracted` payload (raw explicit values + an optional wrapper_hint)
    onto framework/provider findings (DAI001-DAI007) found anywhere in the
    same file, since sampling params are commonly set on a different call
    (e.g. the LLM wrapper constructor) than the agent-initialization call
    that anchors the primary finding.

    Detects raw values only — the framework_default / not_applicable / unknown
    provenance backfill for parameters NOT found here happens later in
    generation_defaults.py, where framework + declared_model context is
    available.
    """

    RULE_ID = "DAI009"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        params = extract_generation_params(node, visitor)
        if not params:
            return None

        extracted: dict[str, Any] = {"generation_params": params}
        wrapper_hint = _classify_wrapper(_resolve_call_func_name(node, visitor))
        if wrapper_hint:
            extracted["wrapper_hint"] = wrapper_hint

        return Finding(
            file_path=visitor.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=self.RULE_ID,
            message=f"Generation parameters declared: {', '.join(sorted(params))}",
            severity="note",
            extracted=extracted,
        )


# Global signature registry
SIGNATURE_REGISTRY: list[Signature] = [
    AutoGenSignature(),
    CrewAISignature(),
    LangChainSignature(),
    ShadowAISignature(),
    DirectHttpLlmClientSignature(),
    LlmApiStringSignature(),
    BedrockSignature(),
    DeclaredModelSignature(),
    GenerationParamsSignature(),
]
