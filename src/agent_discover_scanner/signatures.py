"""
Signature registry for detecting AI agent frameworks and patterns.
"""

import ast
from abc import ABC, abstractmethod
from typing import Optional

from agent_discover_scanner.visitor import ContextAwareVisitor, Finding


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

    def check_constant(self, node: ast.Constant, visitor: ContextAwareVisitor) -> Optional[Finding]:  # type: ignore[override]
        value = getattr(node, "value", None)
        if not isinstance(value, str):
            return None

        val_lower = value.lower()
        for marker in self._BEDROCK_STRING_MARKERS:
            if marker in val_lower:
                return Finding(
                    file_path=visitor.filename,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    rule_id=self.RULE_ID,
                    message=f"AWS Bedrock model/endpoint string detected: {marker!r}",
                    severity="note",
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


# Global signature registry
SIGNATURE_REGISTRY: list[Signature] = [
    AutoGenSignature(),
    CrewAISignature(),
    LangChainSignature(),
    ShadowAISignature(),
    DirectHttpLlmClientSignature(),
    LlmApiStringSignature(),
    BedrockSignature(),
]
