"""
AST visitor for building import context and detecting patterns.
"""

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    """Represents a detection finding in the code."""

    file_path: str
    lineno: int
    col_offset: int
    rule_id: str
    message: str
    severity: str  # "error", "warning", "note"

    def __str__(self) -> str:
        return f"{self.file_path}:{self.lineno}:{self.col_offset} [{self.severity}] {self.rule_id}: {self.message}"


class ContextAwareVisitor(ast.NodeVisitor):
    """
    AST visitor that tracks import aliases and builds context for detection.
    """

    def __init__(self, filename: str | Path, signature_registry: list | None = None):
        self.filename = str(filename)
        self.findings: list[Finding] = []
        self._seen_finding_keys: set[tuple[str, int, int, str]] = set()

        # Map alias -> real_name (e.g., 'lc' -> 'langchain')
        self.import_map: dict[str, str] = {}

        # Track all imports for analysis
        self.imports: list[str] = []

        # Track presence of known LLM API endpoint strings in this file
        self.llm_api_strings_present: bool = False
        self.llm_api_hosts: set[str] = set()

        # Signature registry for detection
        self.signature_registry = signature_registry or []

    def visit(self, node: ast.AST):
        """
        Run a pre-pass to process imports and all string constants first,
        so llm_api_strings_present is set before any visit_Call runs (DAI005).
        """
        self._prepass_imports_and_constants(node)
        super().visit(node)

    def _prepass_imports_and_constants(self, tree: ast.AST) -> None:
        """Walk tree once to build import map and run constant checks (e.g. DAI006)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    real_name = alias.name
                    alias_name = alias.asname or alias.name
                    self.import_map[alias_name] = real_name
                    self.imports.append(real_name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_name = f"{module}.{alias.name}" if module else alias.name
                    alias_name = alias.asname or alias.name
                    self.import_map[alias_name] = full_name
                    self.imports.append(full_name)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                for signature in self.signature_registry:
                    check_constant = getattr(signature, "check_constant", None)
                    if callable(check_constant):
                        finding = check_constant(node, self)  # type: ignore[misc]
                        if finding:
                            self._append_finding(finding)

    def visit_Import(self, node: ast.Import):
        """
        Handle: import langchain as lc
        """
        for alias in node.names:
            real_name = alias.name
            alias_name = alias.asname or alias.name

            # Store the mapping
            self.import_map[alias_name] = real_name
            self.imports.append(real_name)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """
        Handle: from langchain.agents import AgentExecutor
        """
        module = node.module or ""

        for alias in node.names:
            # Construct full name: 'langchain.agents.AgentExecutor'
            full_name = f"{module}.{alias.name}" if module else alias.name
            alias_name = alias.asname or alias.name

            # Store the mapping
            self.import_map[alias_name] = full_name
            self.imports.append(full_name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """
        Visit function calls and check against signature registry.
        """
        # Run all signatures against this call
        for signature in self.signature_registry:
            finding = signature.check(node, self)
            if finding:
                self._append_finding(finding)

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        """
        Constants are handled in _prepass_imports_and_constants so that
        llm_api_strings_present is set before visit_Call runs (DAI005).
        """
        self.generic_visit(node)

    def resolve_name(self, node_id: str) -> str:
        """
        Resolves a variable/attribute name back to its full import path.

        Examples:
            'lc' -> 'langchain'
            'lc.agents' -> 'langchain.agents'
            'AgentExecutor' -> 'langchain.agents.AgentExecutor'
        """
        parts = node_id.split(".")
        root = parts[0]

        if root in self.import_map:
            resolved_root = self.import_map[root]
            # Reconstruct with remaining parts
            return ".".join([resolved_root] + parts[1:])

        return node_id

    def add_finding(self, node: ast.AST, rule_id: str, message: str, severity: str = "warning"):
        """
        Add a finding to the results.
        """
        finding = Finding(
            file_path=self.filename,
            lineno=node.lineno,
            col_offset=node.col_offset,
            rule_id=rule_id,
            message=message,
            severity=severity,
        )
        self._append_finding(finding)

    def _append_finding(self, finding: Finding) -> None:
        """
        Append a finding if we haven't already recorded an identical one.
        Keyed by (file_path, lineno, col_offset, rule_id).
        """
        key = (finding.file_path, finding.lineno, finding.col_offset, finding.rule_id)
        if key in self._seen_finding_keys:
            return
        self._seen_finding_keys.add(key)
        self.findings.append(finding)
