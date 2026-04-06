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
        "- `summary.md` — This file",
        "",
    ]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
