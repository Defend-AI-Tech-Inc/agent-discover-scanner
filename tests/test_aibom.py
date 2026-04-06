"""Tests for AIBOM export."""

import json
from pathlib import Path

from agent_discover_scanner.aibom import generate_aibom


def test_generate_aibom_uses_bucket_classification(tmp_path: Path) -> None:
    inv = tmp_path / "agent_inventory.json"
    inv.write_text(
        json.dumps(
            {
                "generated_at": "2026-01-01T00:00:00",
                "summary": {
                    "confirmed": 1,
                    "unknown": 0,
                    "ghost": 1,
                    "zombie": 0,
                    "shadow_ai_usage": 0,
                },
                "inventory": {
                    "confirmed": [
                        {
                            "agent_id": "c1",
                            "risk_level": "medium",
                            "framework": "LangChain",
                            "detection_layers": ["layer1"],
                        }
                    ],
                    "ghost": [
                        {
                            "agent_id": "g1",
                            "risk_level": "critical",
                            "network_provider": "openai",
                        }
                    ],
                    "unknown": [],
                    "zombie": [],
                    "shadow_ai_usage": [],
                },
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "aibom.json"
    bom = generate_aibom(inv, out)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) == 2
    class_values = [
        next(
            (p["value"] for p in c["properties"] if p["name"] == "agent-discover:inventory_classification"),
            "",
        )
        for c in bom["components"]
    ]
    assert "confirmed" in class_values
    assert "ghost" in class_values
    assert out.is_file()
