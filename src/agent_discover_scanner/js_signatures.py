"""
JavaScript/TypeScript agent detection signatures.
"""

from pathlib import Path
from typing import List

import esprima

from agent_discover_scanner.visitor import Finding


class JavaScriptAgentDetector:
    """Detect AI agents in JavaScript/TypeScript code."""

    # Patterns that indicate agent usage
    AGENT_PATTERNS = {
        "langchain_js": [
            "AgentExecutor",
            "initializeAgentExecutorWithOptions",
            "createOpenAIFunctionsAgent",
            "createReactAgent",
        ],
        "vercel_ai": ["streamText", "generateText", "CoreTool", "tool"],
        "openai_js": [
            "new OpenAI",
            "OpenAI(",
        ],
        "anthropic_js": ["new Anthropic", "Anthropic("],
    }

    def __init__(self, filename: str | Path):
        self.filename = str(filename)
        self.findings: List[Finding] = []
        self.imports: List[str] = []

    def scan_file(self, content: str) -> List[Finding]:
        """Scan JavaScript/TypeScript file for agent patterns."""
        try:
            # Parse JavaScript to AST
            ast = esprima.parseScript(content, {"loc": True, "tolerant": True})

            # Extract imports
            self._extract_imports(content)

            # Detect patterns
            self._detect_langchain(content, ast)
            self._detect_vercel_ai(content, ast)
            self._detect_shadow_ai(content, ast)

        except Exception:
            # Handle syntax errors gracefully
            pass

        return self.findings

    def _extract_imports(self, content: str):
        """Extract import statements."""
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("import ") or line.startswith("require("):
                self.imports.append(line)

    def _detect_langchain(self, content: str, ast):
        """Detect LangChain.js usage."""
        has_langchain_import = any("langchain" in imp for imp in self.imports)

        if not has_langchain_import:
            return

        for pattern in self.AGENT_PATTERNS["langchain_js"]:
            if pattern in content:
                # Try to find line number
                lineno = self._find_line_number(content, pattern)

                finding = Finding(
                    file_path=self.filename,
                    lineno=lineno,
                    col_offset=0,
                    rule_id="DAI003",
                    message=f"LangChain.js agent detected: {pattern}",
                    severity="warning",
                )
                self.findings.append(finding)

    def _detect_vercel_ai(self, content: str, ast):
        """Detect Vercel AI SDK usage."""
        has_ai_import = any("ai" in imp or "vercel" in imp for imp in self.imports)

        if not has_ai_import:
            return

        for pattern in self.AGENT_PATTERNS["vercel_ai"]:
            if pattern in content:
                lineno = self._find_line_number(content, pattern)

                finding = Finding(
                    file_path=self.filename,
                    lineno=lineno,
                    col_offset=0,
                    rule_id="DAI003",
                    message=f"Vercel AI SDK detected: {pattern}",
                    severity="warning",
                )
                self.findings.append(finding)

    def _detect_shadow_ai(self, content: str, ast):
        """Detect direct LLM client usage in JavaScript."""
        # Check for OpenAI
        if "openai" in content.lower():
            for pattern in self.AGENT_PATTERNS["openai_js"]:
                if pattern in content:
                    # Check if it has baseURL pointing to gateway
                    if "defendai" not in content:
                        lineno = self._find_line_number(content, pattern)

                        finding = Finding(
                            file_path=self.filename,
                            lineno=lineno,
                            col_offset=0,
                            rule_id="DAI004",
                            message="Unmanaged OpenAI client detected in JavaScript (Shadow AI)",
                            severity="error",
                        )
                        self.findings.append(finding)

        # Check for Anthropic
        if "anthropic" in content.lower():
            for pattern in self.AGENT_PATTERNS["anthropic_js"]:
                if pattern in content:
                    if "defendai" not in content:
                        lineno = self._find_line_number(content, pattern)

                        finding = Finding(
                            file_path=self.filename,
                            lineno=lineno,
                            col_offset=0,
                            rule_id="DAI004",
                            message="Unmanaged Anthropic client detected in JavaScript (Shadow AI)",
                            severity="error",
                        )
                        self.findings.append(finding)

    def _find_line_number(self, content: str, pattern: str) -> int:
        """Find the line number where pattern appears."""
        for i, line in enumerate(content.split("\n"), 1):
            if pattern in line:
                return i
        return 1
