"""
Test fixture: Regular Python code with no AI agents
Should NOT trigger any findings
"""

from typing import List

import requests


def fetch_data(url: str) -> dict:
    """Fetch data from an API."""
    response = requests.get(url)
    return response.json()


class DataProcessor:
    """Process data without any AI."""

    def __init__(self, data: List[dict]):
        self.data = data

    def process(self):
        return [item for item in self.data if item.get("active")]
