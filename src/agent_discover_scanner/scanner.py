"""
File system traversal with gitignore support.
"""

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
