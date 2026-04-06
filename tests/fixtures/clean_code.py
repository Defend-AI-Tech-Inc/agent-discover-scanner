"""
Test fixture: Regular Python code with no AI agents
Should NOT trigger any findings
"""

import json
from pathlib import Path
from typing import List


def fetch_data(path: str) -> dict:
    """Load JSON from a local file (no outbound HTTP — keeps this fixture clean)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


class DataProcessor:
    """Process data without any AI."""

    def __init__(self, data: List[dict]):
        self.data = data

    def process(self):
        return [item for item in self.data if item.get("active")]
