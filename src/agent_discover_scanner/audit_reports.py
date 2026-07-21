"""Markdown reports for the audit command."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_ghost_agents_markdown(inventory_json: Path, dest: Path) -> None:
    data = json.loads(inventory_json.read_text(encoding="utf-8"))
    ghosts = (data.get("inventory") or {}).get("ghost") or []
    lines = [
        "# Ghost agents",
        "",
        "Runtime signals without matching source inventory (from latest correlation).",
        "",
    ]
    if not ghosts:
        lines.append("_No ghost agents in this run._")
    else:
        for g in ghosts:
            lines.append(f"## {g.get('agent_id', 'unknown')}")
            lines.append("")
            lines.append(f"- **Risk:** {g.get('risk_level', '')}")
            lines.append(f"- **Provider / framework:** {g.get('network_provider') or g.get('framework') or '—'}")
            lines.append(f"- **Process:** {g.get('process_name') or '—'}")
            lines.append(f"- **Last seen:** {g.get('last_seen') or '—'}")
            lines.append("")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_mcp_markdown(mcp_result: dict[str, Any], dest: Path) -> None:
    servers = mcp_result.get("servers") or []
    lines = [
        "# MCP servers",
        "",
        "Detected from configuration, process, registry, and optional network/endpoint context.",
        "",
        "[MCP] Enforce policies on detected servers → pip install mcpfw-defendai | mcpfw.dev",
        "",
    ]
    if not servers:
        lines.append("_No MCP servers detected in this run._")
    else:
        for s in servers:
            name = s.get("server_name") or s.get("name") or "unknown"
            lines.append(f"## {name}")
            lines.append("")
            lines.append(f"- **Vendor:** {s.get('vendor', '—')}")
            lines.append(f"- **Publisher verified:** {s.get('publisher_verified', False)}")
            lines.append(f"- **Local script:** {s.get('is_local_script', False)}")
            lines.append("")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


_GENERATION_PARAM_ORDER = (
    "temperature",
    "top_p",
    "top_k",
    "max_tokens",
    "frequency_penalty",
    "presence_penalty",
    "stop",
    "seed",
    "n",
)


def write_generation_params_markdown(inventory_json: Path, dest: Path) -> None:
    """
    Write generation/sampling parameter facts + informational threshold flags.

    This report is intentionally separate from ghost-agents.md / the SARIF
    security findings: HIGH_TEMPERATURE / UNBOUNDED_MAX_TOKENS / ZERO_TEMPERATURE
    are opinions about configuration, not security findings, and must never
    influence risk_level or agent classification (see correlator.py /
    generation_defaults.py). This file is the only place they are surfaced.
    """
    data = json.loads(inventory_json.read_text(encoding="utf-8"))
    inventory = data.get("inventory") or {}

    agents_with_params = []
    for classification, agents in inventory.items():
        if not isinstance(agents, list):
            continue
        for agent in agents:
            if isinstance(agent, dict) and agent.get("generation_params"):
                agents_with_params.append((classification, agent))

    lines = [
        "# Generation / sampling parameters",
        "",
        "Raw detected values for temperature, top_p, top_k, max_tokens, "
        "frequency_penalty, presence_penalty, stop, seed, and n, with honest "
        "provenance per parameter — explicit (found in code), framework_default "
        "(backfilled from a maintained provider/wrapper table), not_applicable "
        "(fixed/rejected by the model family), or unknown (no reliable default "
        "applies).",
        "",
        "**This report is informational only.** Flags below (HIGH_TEMPERATURE, "
        "UNBOUNDED_MAX_TOKENS, ZERO_TEMPERATURE) are configuration observations, "
        "not security findings — they do NOT affect risk_level, agent "
        "classification, or `aibom.json`. No prescriptive \"recommended value\" "
        "is given; that is a deliberately separate, out-of-scope decision.",
        "",
    ]

    if not agents_with_params:
        lines.append("_No generation/sampling parameters detected in this run._")
    else:
        for classification, agent in agents_with_params:
            lines.append(f"## {agent.get('agent_id', 'unknown')}")
            lines.append("")
            lines.append(f"- **Classification:** {classification}")
            lines.append(f"- **Framework:** {agent.get('framework') or '—'}")
            if agent.get("declared_model"):
                lines.append(f"- **Declared model:** {agent['declared_model']}")
            lines.append("")
            lines.append("| Parameter | Value | Provenance |")
            lines.append("|---|---|---|")
            params = agent.get("generation_params") or {}
            for param_name in _GENERATION_PARAM_ORDER:
                param_data = params.get(param_name)
                if not isinstance(param_data, dict):
                    continue
                source = param_data.get("source", "unknown")
                value = param_data.get("value", "—")
                lines.append(f"| `{param_name}` | {value} | {source} |")
            lines.append("")
            flags = agent.get("generation_param_flags") or []
            if flags:
                lines.append("**Notes:**")
                lines.append("")
                for flag in flags:
                    lines.append(f"- `{flag.get('flag')}`: {flag.get('message')}")
                lines.append("")

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_audit_summary(report: dict[str, Any], dest: Path, raw_dir: Path) -> None:
    s = report.get("summary") or {}
    lines = [
        "# Audit summary",
        "",
        f"**Generated:** {report.get('generated_at', '')}",
        "",
        "## Counts",
        "",
        f"- Confirmed: {s.get('confirmed', 0)}",
        f"- Unknown: {s.get('unknown', 0)}",
        f"- Ghost: {s.get('ghost', 0)}",
        f"- Zombie: {s.get('zombie', 0)}",
        f"- Shadow AI usage: {s.get('shadow_ai_usage', 0)}",
        "",
        "## Artifacts",
        "",
        f"- Raw scan directory: `{raw_dir}`",
        "- `aibom.json` — CycloneDX-oriented AIBOM",
        "- `ghost-agents.md` — Ghost agent detail",
        "- `mcp-report.md` — MCP inventory",
        "- `generation-params.md` — Generation/sampling parameter facts (informational)",
        "- `summary.md` — This file",
        "",
    ]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
