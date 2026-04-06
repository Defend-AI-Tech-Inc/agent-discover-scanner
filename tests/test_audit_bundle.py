"""Tests for audit command and markdown helpers."""

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from agent_discover_scanner.audit_reports import (
    write_audit_summary,
    write_ghost_agents_markdown,
    write_mcp_markdown,
)
from agent_discover_scanner.cli import app


def test_write_ghost_agents_markdown(tmp_path: Path) -> None:
    inv = tmp_path / "agent_inventory.json"
    inv.write_text(
        json.dumps(
            {
                "inventory": {
                    "ghost": [
                        {
                            "agent_id": "ghost-1",
                            "risk_level": "critical",
                            "network_provider": "openai",
                            "process_name": "python",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    dest = tmp_path / "ghost-agents.md"
    write_ghost_agents_markdown(inv, dest)
    text = dest.read_text(encoding="utf-8")
    assert "ghost-1" in text
    assert "openai" in text


def test_write_mcp_markdown_empty(tmp_path: Path) -> None:
    dest = tmp_path / "mcp.md"
    write_mcp_markdown({}, dest)
    assert "No MCP servers" in dest.read_text(encoding="utf-8")


def test_write_audit_summary(tmp_path: Path) -> None:
    dest = tmp_path / "summary.md"
    write_audit_summary(
        {
            "generated_at": "t",
            "summary": {
                "confirmed": 1,
                "unknown": 2,
                "ghost": 0,
                "zombie": 0,
                "shadow_ai_usage": 0,
            },
        },
        dest,
        Path("/tmp/raw"),
    )
    body = dest.read_text(encoding="utf-8")
    assert "Confirmed: 1" in body
    assert "aibom.json" in body


def test_audit_cli_writes_bundle(tmp_path: Path) -> None:
    import agent_discover_scanner.scan_runner as scan_runner

    proj = tmp_path / "proj"
    proj.mkdir()
    out = tmp_path / "audit_out"

    inv_payload = {
        "generated_at": "2026-01-01T00:00:00",
        "summary": {
            "confirmed": 0,
            "unknown": 1,
            "ghost": 0,
            "zombie": 0,
            "shadow_ai_usage": 0,
        },
        "inventory": {
            "confirmed": [],
            "unknown": [{"agent_id": "u1", "risk_level": "low"}],
            "ghost": [],
            "zombie": [],
            "shadow_ai_usage": [],
        },
    }

    def fake_execute_scan_all(*, output, **kwargs):
        output.mkdir(parents=True, exist_ok=True)
        (output / "agent_inventory.json").write_text(
            json.dumps(inv_payload),
            encoding="utf-8",
        )
        return {
            "generated_at": "2026-01-01T00:00:00",
            "summary": inv_payload["summary"],
            "risk_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 1},
        }

    with patch.object(scan_runner, "execute_scan_all", side_effect=fake_execute_scan_all):
        runner = CliRunner()
        res = runner.invoke(app, ["audit", str(proj), "--output", str(out)])

    assert res.exit_code == 0, res.output
    assert (out / "raw" / "agent_inventory.json").is_file()
    assert (out / "aibom.json").is_file()
    assert (out / "ghost-agents.md").is_file()
    assert (out / "mcp-report.md").is_file()
    assert (out / "summary.md").is_file()
