"""
File system traversal with gitignore support.
"""
# Add these imports at the top
import subprocess
import socket
from typing import Optional

from pathlib import Path
from typing import Iterator


class Scanner:
    """
    Recursively scans directories for Python and JavaScript files, respecting ignore patterns.
    """

    # Default patterns to ignore
    DEFAULT_IGNORE_PATTERNS = {
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "node_modules",
        ".pytest_cache",
        ".ruff_cache",
        "*.pyc",
        ".eggs",
        "build",
        "dist",
        ".tox",
        "package-lock.json",
        "yarn.lock",
    }

    # File extensions to scan
    SCAN_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}

    def __init__(self, root_path: str | Path, ignore_patterns: set[str] | None = None):
        self.root_path = Path(root_path).resolve()
        self.ignore_patterns = ignore_patterns or self.DEFAULT_IGNORE_PATTERNS

    def should_ignore(self, path: Path) -> bool:
        """
        Check if a path should be ignored based on patterns.
        """
        # Check if any parent directory matches ignore patterns
        for parent in path.parents:
            if parent.name in self.ignore_patterns:
                return True

        # Check the path itself
        if path.name in self.ignore_patterns:
            return True

        # Check wildcard patterns (simple implementation)
        for pattern in self.ignore_patterns:
            if pattern.startswith("*") and path.name.endswith(pattern[1:]):
                return True

        return False

    def scan(self) -> Iterator[Path]:
        """
        Yield all Python and JavaScript files in the directory tree.
        """
        if not self.root_path.exists():
            raise FileNotFoundError(f"Path does not exist: {self.root_path}")

        if self.root_path.is_file():
            # Single file mode
            if self.root_path.suffix in self.SCAN_EXTENSIONS:
                yield self.root_path
            return

        # Directory mode - recursively find all scannable files
        for pattern in ["**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.mjs"]:
            for file in self.root_path.glob(pattern):
                if not self.should_ignore(file):
                    yield file

    # LAYER 4

    def check_osquery_available(self) -> bool:
        """Check if osquery is installed and available."""
        try:
            result = subprocess.run(
                ["osqueryi", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan_layer4_endpoint(self) -> Optional[dict]:
        """
        Layer 4: Scan local endpoint for Shadow AI using osquery.
        
        Returns:
            Dictionary with endpoint discovery results, or None if osquery not available
        """
        if not self.check_osquery_available():
            return None
        
        from agent_discover_scanner.layer4.osquery_executor import OsqueryExecutor
        from agent_discover_scanner.layer4.result_parser import OsqueryResultParser
        
        # Execute osquery
        executor = OsqueryExecutor()
        raw_results = executor.discover_all()
        
        # Convert to model
        hostname = socket.gethostname()
        endpoint = OsqueryResultParser.create_endpoint_discovery(
            hostname=hostname,
            osquery_results=raw_results
        )
        
        # Return as dict for integration
        return {
            "hostname": endpoint.hostname,
            "os_type": endpoint.os_type,
            "os_version": endpoint.os_version,
            "username": endpoint.username,
            "total_ai_instances": endpoint.total_ai_instances,
            "risk_score": endpoint.risk_score,
            "applications": [
                {
                    "name": app.name,
                    "version": app.version,
                    "vendor": app.vendor
                }
                for app in endpoint.applications
            ],
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "package_manager": pkg.package_manager
                }
                for pkg in endpoint.packages
            ],
            "connections": [
                {
                    "process_name": conn.process_name,
                    "remote_hostname": conn.remote_hostname
                }
                for conn in endpoint.connections
            ]
    }
