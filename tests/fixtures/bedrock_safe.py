"""
Test fixture: clean code with no AWS Bedrock or LangGraph patterns.
Should trigger: NO DAI007 findings.
"""

import os
import json


def process_data(records: list[dict]) -> list[dict]:
    return [r for r in records if r.get("active")]


def read_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


class DataPipeline:
    def add_node(self, name: str, fn) -> None:
        # Generic graph — NOT a LangGraph StateGraph (no langgraph import)
        self._nodes[name] = fn

    def add_edge(self, src: str, dst: str) -> None:
        self._edges.append((src, dst))

    def __init__(self):
        self._nodes = {}
        self._edges = []
