"""Best-effort CycloneDX 1.6–oriented AIBOM export from agent_inventory.json."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def generate_aibom(inventory_json: Path, output_path: Path) -> dict[str, Any]:
    """
    Read agent_inventory.json, iterate inventory buckets, attach classification from each bucket key,
    and write a JSON document suitable for CycloneDX 1.6 tooling (best-effort; validate if needed).
    """
    raw = json.loads(Path(inventory_json).read_text(encoding="utf-8"))
    components: list[dict[str, Any]] = []
    n = 0
    for bucket_classification, agents in (raw.get("inventory") or {}).items():
        if not isinstance(agents, list):
            continue
        for agent in agents:
            if not isinstance(agent, dict):
                continue
            n += 1
            aid = agent.get("agent_id") or f"agent-{n}"
            bom_ref = f"agent:{bucket_classification}:{n}:{aid}"
            comp: dict[str, Any] = {
                "type": "application",
                "name": str(aid),
                "bom-ref": bom_ref,
                "properties": [
                    {
                        "name": "agent-discover:inventory_classification",
                        "value": str(bucket_classification),
                    },
                    {
                        "name": "agent-discover:risk_level",
                        "value": str(agent.get("risk_level", "")),
                    },
                ],
            }
            if agent.get("framework"):
                comp["properties"].append(
                    {"name": "agent-discover:framework", "value": str(agent["framework"])}
                )
            layers = agent.get("detection_layers")
            if layers:
                comp["properties"].append(
                    {
                        "name": "agent-discover:detection_layers",
                        "value": ",".join(str(x) for x in layers),
                    }
                )
            components.append(comp)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": raw.get("generated_at"),
            "properties": [
                {
                    "name": "agent-discover:aibom_note",
                    "value": (
                        "Best-effort CycloneDX 1.6–oriented export; "
                        "validate with official tooling if strict compliance is required."
                    ),
                }
            ],
        },
        "components": components,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return bom
