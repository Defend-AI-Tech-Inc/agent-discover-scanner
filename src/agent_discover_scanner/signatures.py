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
    Detect LangChain agent patterns.

    Targets:
    - langchain.agents.initialize_agent (legacy)
    - langchain.agents.create_agent
    - langgraph.graph.StateGraph (complex workflows)
    """

    RULE_ID = "DAI003"

    def check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Optional[Finding]:
        func_name = self._get_function_name(node, visitor)

        if not func_name:
            return None

        # Check for agent initialization
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

        # Check for StateGraph (complex workflows)
        if "StateGraph" in func_name and "langgraph" in func_name:
            return Finding(
                file_path=visitor.filename,
                lineno=node.lineno,
                col_offset=node.col_offset,
                rule_id=self.RULE_ID,
                message="LangGraph StateGraph detected (complex stateful workflow) - Consider enabling AgentWatch deep tracing",
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


# Global signature registry
SIGNATURE_REGISTRY: list[Signature] = [
    AutoGenSignature(),
    CrewAISignature(),
    LangChainSignature(),
    ShadowAISignature(),
]
