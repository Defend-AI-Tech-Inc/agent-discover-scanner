# CLAUDE.md — AgentDiscover Scanner

Open-source AI agent discovery tool (v2.7.1) published on PyPI as `agent-discover-scanner`.
Part of the [DefendAI](https://defendai.ai) platform for autonomous AI governance.
MIT licensed. Maintained by Mohamed Waseem / DefendAI.

---

## What this project does

AgentDiscover Scanner discovers, classifies, and inventories autonomous AI agents running across an infrastructure. It runs five detection layers simultaneously and correlates them into a unified agent inventory with five classifications:

| Class | Meaning | Risk |
|---|---|---|
| GHOST | Runtime AI activity — no source code found | Critical |
| CONFIRMED | Detected in code AND observed running | High |
| UNKNOWN | Found in code, not yet observed at runtime | Medium |
| SHADOW AI | Known app using AI without governance | Medium |
| ZOMBIE | Was active, no longer observed | Low |

The GHOST classification is the core value proposition — it catches AI agents making live API calls with no corresponding source code, owner, or deployment record.

---

## Repository layout

```
src/agent_discover_scanner/    # Main package
  cli.py                       # Typer CLI entry point (all commands)
  scan_runner.py               # Shared execute_scan_all() implementation
  scanner.py                   # File discovery / walk
  visitor.py                   # ContextAwareVisitor — AST-based Python detection
  signatures.py                # SignatureRegistry + individual Signature subclasses
  js_signatures.py             # JavaScript/TypeScript detection (esprima)
  correlator.py                # CorrelationEngine — cross-layer agent identity
  network_monitor.py           # Layer 2 — psutil-based network observation
  mcp_detector.py              # MCP server detection (v2.4.0+)
  high_risk_agents.py          # OpenClaw / AutoGPT / BabyAGI detection (v2.4.0+)
  known_apps.py                # Three-tier known-app resolution
  saas_detector.py             # SaaS blast radius scoring
  behavioral_patterns.py       # ReAct loops, RAG patterns, multi-turn detection
  aibom.py                     # CycloneDX 1.6-oriented AI BOM export (v2.5.0+)
  audit_reports.py             # ghost-agents.md, mcp-report.md, summary.md writers
  sarif_output.py              # SARIF generation for Layer 1
  sbom_analyzer.py             # requirements.txt / package.json scanning
  platform.py                  # DefendAI platform upload
  errors.py                    # ValidationError, CLI helpers
  models/                      # Pydantic data models
  monitors/                    # Layer 3 — K8s/Tetragon monitor
  layer4/                      # Layer 4 — osquery endpoint discovery
  reports/                     # Layer 4 report generation
  detectors/                   # Layer 5 — Cloud Audit detectors (v2.7.0+)
    cloud_audit/               # Package: base ABC, AWS CloudTrail, Azure/GCP stubs
      __init__.py              # Auto-discovery + run_cloud_audit_detection()
      base.py                  # CloudAuditDetector ABC + CloudAuditFinding dataclass
      aws_cloudtrail.py        # AWS CloudTrail + Lake — GA
      azure_monitor.py         # Azure Monitor — Preview stub
      gcp_audit.py             # GCP Cloud Audit Logs — Preview stub
    cloudtrail.py              # Backward-compat shim → re-exports from cloud_audit/

tests/                         # pytest test suite
  fixtures/                    # Python/JS files used as detection test inputs
  test_scanner.py
  test_correlator.py
  test_aibom.py
  test_audit_bundle.py
  test_behavioral_patterns.py

docs/                          # Architecture diagrams, setup guides
deployment/                    # systemd service, K8s Tetragon tracing policy
demo/                          # K8s manifests + sample repo for local demo
```

---

## Tech stack (enforce these; do not deviate)

From `.cursor/rules/tech-stack.mdc`:

- **Dependency management:** Always use `uv` commands (`uv add`, `uv run`, `uv sync`). Never `pip install` or `poetry`.
- **CLI framework:** `typer` for all CLI entry points.
- **Console output:** `rich` (Console, Table) for all stdout printing.
- **Type hints:** Python 3.12+ syntax — `list[str]`, `dict[str, int]`, `str | None`. Not `List[str]`, `Optional[str]`.
- **Data models:** `pydantic.BaseModel` for all internal data structures.

Core runtime dependencies (from `pyproject.toml`):
- `typer>=0.9.0`, `rich>=13.0.0`, `pydantic>=2.0.0`
- `sarif-om>=1.0.4` — SARIF generation
- `esprima>=4.0.1` — JavaScript AST parsing
- `psutil>=5.9.0` — network monitoring
- `kubernetes>=28.1.0` — K8s API
- `httpx>=0.27.0`, `certifi>=2024.2.2`

Dev dependencies: `pytest>=8.0.0`, `pytest-cov>=4.1.0`, `ruff>=0.1.0`

Build system: `hatchling`. Python requirement: `>=3.10`.

---

## Architecture constraints (enforce these)

From `.cursor/rules/architecture.mdc`:

1. **Stateless scanner** — reads files, processes AST, outputs results. No persistent state between scans.
2. **SARIF as primary output** — Layer 1 (code scan) always writes valid SARIF JSON to disk (`layer1_code.sarif`).
3. **SignatureRegistry pattern** — detection logic lives in `Signature` subclasses registered in `SIGNATURE_REGISTRY`. Never hardcode detection logic in the visitor or CLI.
4. **AST for code parsing** — all Python detection uses `ast.NodeVisitor`. Never use regex to parse code. JavaScript uses esprima AST.

---

## Detection layers

| Layer | What | How | Platform |
|---|---|---|---|
| 1 | Source code | Python AST (`ContextAwareVisitor`) + esprima (JS/TS) | All |
| 2 | Live network | psutil connection observation | All (Linux needs root) |
| 3 | K8s runtime | Tetragon/eBPF events or K8s API fallback | Linux (eBPF); all (K8s API) |
| 4 | Endpoint | osquery — packages, apps, connections, browser history | All (osquery required) |
| 5 | Cloud Audit | AWS CloudTrail (GA); Azure Monitor / GCP Cloud Audit Logs (stubs) | All (boto3 required for AWS) |

Layer 3 (eBPF) is Linux-only. On macOS/Windows, it is skipped automatically and the scan continues with Layers 1, 2, 4.

Layer 5 runs independently alongside Layers 1–4 (separate thread in ThreadPoolExecutor). Findings are written to `layer5_cloud_audit.json` and merged into the network findings list before correlation. Enable with `--cloud-audit` (or `--cloud-audit-hours N`).

Cross-layer correlation: an agent seen in code (L1) AND observed at runtime (L2, L3, or L5) is CONFIRMED. Runtime activity with no L1 match → GHOST.

---

## CLI commands

Both `agent-discover-scanner` and `agent-discover` are valid entry points.

```bash
# Full 5-layer scan (primary command)
agent-discover-scanner scan-all PATH [--duration 60] [--output ./results] [--format text|json]
  [--skip-layers 3] [--layer3-file PATH] [--daemon] [--verbose]
  [--platform] [--api-key KEY] [--tenant-token TOKEN]
  [--wawsdb-url URL] [--platform-interval 5]
  [--max-log-size 50] [--max-log-backups 5]
  [--layer code|network|k8s|endpoint|mcp]   # single-facet mode
  # Layer 5 — Cloud Audit (v2.7.0+)
  [--cloud-audit | --no-cloud-audit]         # enable Layer 5 Cloud Audit detection (default: false)
  [--cloud-audit-region TEXT]                # AWS region (default: us-east-1)
  [--cloud-audit-hours INTEGER]              # lookback window (default 1 when --cloud-audit set)
  [--cloud-audit-lake-arn TEXT]              # CloudTrail Lake ARN (near-real-time)
  [--azure-monitor | --no-azure-monitor]     # [Preview] Azure OpenAI detection (stub)
  [--gcp-audit | --no-gcp-audit]             # [Preview] Vertex AI detection (stub)

# Audit mode (v2.5.0) — writes aibom.json, ghost-agents.md, mcp-report.md, summary.md
# Also accepts all --cloud-audit-* options.
agent-discover-scanner audit PATH [--output ./defendai-audit] [--duration 60]
  [--cloud-audit | --no-cloud-audit] [--cloud-audit-region TEXT]
  [--cloud-audit-hours INTEGER] [--cloud-audit-lake-arn TEXT]
  [--azure-monitor] [--gcp-audit]

# Individual layers
agent-discover-scanner scan PATH             # Layer 1 only (SARIF output)
agent-discover-scanner deps PATH             # requirements.txt / package.json
agent-discover-scanner monitor               # Layer 2 only
agent-discover-scanner monitor-k8s           # Layer 3 only
agent-discover-scanner endpoint              # Layer 4 only
agent-discover-scanner correlate             # Correlate existing layer outputs
```

The `scan-all` command delegates to `scan_runner.execute_scan_all()`. Both `scan-all` and `audit` share this implementation — `audit` wraps it and writes the post-scan report bundle.

---

## Running tests

```bash
uv run pytest tests/ -v
# or with coverage (default via pyproject.toml addopts):
uv run pytest
```

Test fixtures in `tests/fixtures/` are real Python/JS files intentionally containing or omitting agent patterns. Do not remove them — they are the ground truth for detection accuracy.

Linting:
```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

Ruff config: `line-length = 100`, target `py310`, selects `E F I N W UP`.

---

## Development workflow

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner.git
cd agent-discover-scanner
uv sync                          # install all dependencies
uv run pytest tests/ -v          # run full test suite
uv run agent-discover-scanner --version
```

Building and publishing:
```bash
uv run python -m build           # produces dist/
uv run twine upload dist/*       # PyPI publish
```

Versioning follows semver. Version is set in `pyproject.toml` and read at runtime via `importlib.metadata`.

---

## Adding a new detection signature

1. Create a `Signature` subclass in `src/agent_discover_scanner/signatures.py` (or a new module).
2. Implement `check(self, node: ast.Call, visitor: ContextAwareVisitor) -> Finding | None`.
3. Register it in `SIGNATURE_REGISTRY`.
4. Add a fixture file in `tests/fixtures/` — one that should match, one that should not.
5. Add a test in `tests/test_scanner.py` covering both.
6. Include false-positive analysis in the PR description (see CONTRIBUTING.md).

For JS/TS signatures, extend `js_signatures.py` (esprima-based). For MCP patterns, extend `mcp_detector.py`. For high-risk agent detection, extend `high_risk_agents.py` — detection must use corroborated signals, never a single port or file path. For Layer 5 Cloud Audit detection, see `detectors/cloud_audit/` — the public entry point is `run_cloud_audit_detection(hours_back, region, lake_arn, _warn_fn)` in `detectors/cloud_audit/__init__.py`. Called from `scan_runner.run_layer5_once()` when `cloud_audit_enabled=True` or `cloud_audit_hours > 0` or `cloud_audit_lake_arn` is set. To add a new cloud provider: create a `CloudAuditDetector` subclass in `detectors/cloud_audit/<provider>.py` with `provider = "<name>"`, `is_available()`, and `detect(hours_back)`. Auto-discovery picks it up automatically.

---

## Key design decisions

- **No regex for code parsing.** AST only. Regex on source text fails on aliases, indirect imports, and multi-line expressions.
- **GHOST detection requires runtime observation.** The scanner watches the network and K8s runtime simultaneously with the code scan, then correlates. Static analysis alone cannot produce GHOST findings.
- **Known-app list prevents GHOST false positives.** Processes like browsers, Cursor, Claude Desktop, Slack are pre-classified as Shadow AI. Custom internal tools can be added via `~/.defendai/known_apps.txt` or downloaded from the platform tenant config.
- **SaaS blast radius is built from observed connections, not config files.** `confirmed` confidence means the connection was live-observed during the scan window.
- **High-risk agent detection (OpenClaw) requires corroborated signals.** Never classify based on a single signal (port, file, or process name alone).
- **Layer 3 eBPF is Linux-only by design.** The K8s API fallback path works on all platforms with kubectl access.

---

## Platform integration

The scanner uploads to `https://wauzeway.defendai.ai` (default `--wawsdb-url`). The upload payload is built in `platform.py` and includes `high_risk_agent` and `mcp_connections` fields (added in v2.4.0).

The platform performs cross-machine identity resolution, behavioral drift detection, and computes aggregated blast radius scores. The scanner is the discovery layer only — governance lives on the platform.

---

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `ci.yml` — runs pytest on push/PR
- `scan.yml` — runs Layer 1 code scan, uploads SARIF to GitHub Security tab
- `aibom.yml` — generates AI BOM artifact

For CI usage, skip Layer 3 (`--skip-layers 3`) since no K8s cluster is available. Layer 2 requires elevated privileges on Linux — use `--skip-layers 2,3` if running unprivileged.

---

## Security policy

Vulnerabilities in the scanner itself: email security@defendai.ai (do not open a public issue). Response target: 48 hours.

---

## Detected frameworks and providers

**AI frameworks:** LangChain, LangGraph, CrewAI, AutoGen, direct HTTP LLM clients  
**LLM providers:** OpenAI, Anthropic, Google Gemini/AI, Mistral, Cohere, Azure OpenAI, AWS Bedrock, Groq, DeepSeek  
**Vector stores:** Pinecone, Weaviate, Qdrant, Chroma  
**SaaS blast radius:** Salesforce, Slack, GitHub, GitLab, Jira, HubSpot, Notion, Airtable, Stripe, Twilio, Snowflake, Databricks, AWS, GCP, Azure, PostgreSQL, Redis, MongoDB  
**MCP clients:** Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI, OpenAI Codex, Continue.dev, Zed  
**High-risk agents:** OpenClaw (CVE-2026-25253, CVSS 8.8), AutoGPT, BabyAGI
