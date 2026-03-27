# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [2.4.0] - 2026-03-16

### Added
- **OpenClaw detection** (`high_risk_agents.py`)
  - Multi-signal corroborated detection — no false positives
  - Definitive signals: ~/.openclaw/, ~/clawd/SOUL.md, port 18789,
    npm package, launchd/systemd daemon service
  - Supports AutoGPT and BabyAGI detection
  - Console warning fires on confirmed/high confidence only
  - Never flags based on port alone (no port 8080 used)

- **MCP server detection** (`mcp_detector.py`)
  - Detects MCP across ALL AI clients: Claude Desktop, Cursor,
    Gemini CLI, OpenAI Codex, VS Code Copilot
  - Verified publisher registry: Salesforce, Microsoft, Atlassian,
    GitHub, Stripe, Anthropic reference implementations
  - Distinguishes official vendor packages from community forks
  - Network-based detection catches non-developer users (financial
    analysts connecting ChatGPT Teams to Salesforce via UI —
    no local config file required)
  - Flags unverified MCP servers and local scripts
  - Merges detected MCP SaaS into sconnections blast radius

- `high_risk_agent` and `mcp_connections` fields in upload payload
- `high_risk_agent` and `mcp_connections` on AgentInventoryItem

### Changed
- Risk flags now include `high_risk_agent_detected`,
  `mcp_filesystem_access`, `mcp_code_execution`,
  `mcp_database_access`, `mcp_remote_server`

## [2.3.2] - 2026-03-15

### Added
- `known_apps.py` module with three-tier resolution for known 
  desktop application list:
  - Tier 1: Platform list via DefendAI API (when --platform enabled)
  - Tier 2: Local override file (~/.defendai/known_apps.txt)
  - Tier 3: Built-in defaults (browsers, Office, AI desktop apps)
- `docs/known-apps-example.txt` — example local override file
- `defendai-sdk` integration for platform known apps fetch
  (requires local install until SDK is on PyPI)

### Changed
- GHOST classification now distinguishes known desktop applications
  from truly ungoverned agents
- Known desktop apps (Notes, Cursor, Chrome, Edge, Slack, etc.) 
  making AI calls are classified as `shadow_ai_usage` instead of GHOST
- `shadow_ai_usage` appears as "SHADOW AI" in the inventory table
- Layer 3 (K8s) GHOST logic unchanged — workloads are always GHOST

### Fixed
- False positive GHOST classifications for known desktop applications
- Notes.app, Cursor, OneDrive, Microsoft Edge no longer appear as
  GHOST agents when making AI API calls

## [2.3.1] - 2026-03-15

### Added
- Daemon mode now uploads to platform periodically via `--platform-interval N` flag
- Upload interval defaults to every 5 correlation cycles (~2.5 minutes)
- Platform sync cadence printed on daemon start when `--platform` is set
- Upload failures in daemon mode are logged but never crash the daemon

### Changed
- Previous behavior: daemon only uploaded to platform on shutdown
- New behavior: uploads every N cycles AND on shutdown (final state always synced)

---

## [2.3.0] - 2026-03-14

### Added
- **Multi-layer SaaS connection detection** via new `saas_detector.py`
  - Layer 1: env var key patterns, Python import analysis, `.env` file scanning
  - Layer 2: live network connections with per-agent process/framework attribution
  - Layer 4: open sockets, browser history, desktop apps, VSCode extensions
  - Detects 20+ SaaS integrations including Salesforce, Slack, GitHub, AWS, GCP, Azure, OpenAI, Anthropic, Snowflake, Databricks and more
- `saas_connections` and `risk_flags` added to `AgentInventoryItem` — flows into `agent_inventory.json`
- Confidence scoring per SaaS: `confirmed` / `high` / `medium` / `low`
- GHOST agents now show confirmed SaaS connections from live Layer 2 observed connections
- `hostname`, `username`, `os` added to platform upload payload for cross-machine correlation
- Large path warning when scan root contains 500+ Python files
- Progress indicator during correlation step (eliminates apparent hang)

### Changed
- SaaS detection uses exclusive per-agent attribution — machine-wide signals are only attributed to agents with matching process name or framework
- `active_connection` (process/framework matched) distinguished from `active_connection_unmatched`
- GHOST agents skip static analysis (no source code = no env var or import scanning)
- `.env` file search walks up to 4 directory levels to find project root

### Fixed
- Scanner no longer appears to hang during correlation on large codebases
- SaaS detections no longer bleed across all agents indiscriminately

---

## [2.2.0] - 2026-03-13

### Added
- **Platform integration** via `--platform` flag on `scan-all`
  - Uploads scan results to DefendAI platform via `/scanner/ingest`
  - Sends full agent inventory including framework, confidence, metadata
  - Includes `saas_connections` payload with blast radius signals
  - macOS certificate trust handled automatically via `certifi`
- Scanner context (hostname, OS, scanner version) included in platform uploads
- Noise filtering: test fixtures, scanner self-references, node_modules filtered before upload
- `saas_connections` payload: `has_database_access`, `has_cloud_provider`, `has_llm_provider`, `has_external_api_calls`
- Zero new dependencies for SaaS detection — stdlib only (`os`, `ast`)

---

## [2.1.7] - 2026-03-01

### Changed
- Minor correlator fixes and stability improvements

---

## [2.1.0] - 2026-02-28

### Added
- **Tetragon native file export** for production-safe Layer 3 eBPF monitoring
- Demo environment with sample agents (CrewAI, Lan, AutoGen, Direct HTTP)
- Demo pods use stdlib `urllib` — no pip install delay at startup
- Systemd service file for daemon mode deployment
- TracingPolicy auto-install for Tetragon

### Changed
- Layer 3 now uses Tetragon native file export instead of kubectl log tailing
- `scan-all` runs layers in parallel for faster completion
- Daemon mode adds retry/backoff, log rotation, disk monitoring

### Fixed
- Layer 3 parser correctly extracts pod info from `process_tracepoint` events
- Layer 3 findings written to output directory when using `--layer3-file`
- Demo pods use ConfigMap for agent scripts
- Tetragon `select`-based polling replaces busy-wait loop
- TracingPolicy filter `state=1` (ESTABLISHED) — fixes nil saddr/daddr at socket init

---

## [2.0.8] - 2026-02-26

### Added
- `scan-all` command: single command runs all 4 layers and correlates
- `--version` / `-v` flag
- Multi-layer correlation engine: GHOST detection across Layers 1+2+3
- Detection coverage report showing layer combinations

### Cha
- Expanded provider matching for broader AI service detection
- Risk escalation logic improved
- `detection_layers` field populated per agent

### Fixed
- Updated correlation engine with improved matching
- DAI005 (Shadow AI) uses two-pass AST scan to fire correctly
- Deduplicate findings across layers
- `httpx` call warning suppressed
- Auto-include Layers 2 and 3 when Kubernetes cluster detected
- Python version parsing fixed
- Handle externally-managed pip environments

---

## [2.0.5] - 2026-02-26

### Fixed
- Two-pass AST scan so DAI005 fires correctly
- Remove Cilium CNI requirement for Layer 3
- Python version parsing for externally-managed environments

---

## [2.0.3] - 2026-02-25

### Documentation
- Updated README with v2.0.2, one-command install, Layer 4 details
- Correct example scenarios for endpoint scanning
- Fixed markdown structure throughout

## [2.0.1] - 2026-02-15

### Fixed
- Improved network monitoring with psutil for better WebSocket detection
- Now catches browser AI usage (Safari, Chrome, Edge)
- Added psutil>=5.9.0 to dependencies

### Changed
- Replaced lsof-based network monitoring with psutil implementation
- Network monitor now detects active connections including WebSockets

## [2.0.0] - 2026-02-13

### Added
- **Layer 4: Endpoint Discovery** - Discover Shadow AI on developer laptops and workstations
  - New `layer4` CLI command for endpoint scanning
  - Detects desktop AI applications (ChatGPT, Claude, Cursor, GitHub Copilot)
  - Finds AI packages (pip, npm: openai, langchain, anthropic, etc.)
  - Monitors active connections to AI services
  - Tracks browser-based AI usage (chatgpt.com, claude.ai)
  - Risk scoring for endpoints (0-100 based on Shadow AI severity)
  - osquery-based implementation (Apache 2.0 license)

### Features
- New modules: `layer4/`, `models/`, `reports/`
- Comprehensive Layer 4 reporting (markdown and JSON formats)
- Graceful degradation when osquery not installed
- Platform detection (macOS, Linux, Windows)
- Integration with existing scanner architecture

### Documentation
- New: Layer 4 setup guide (`docs/layer4-setup.md`)
- New: Universal installer (`install.sh`)
- Updated: README with Layer 4 information

## [1.1.1] - 2026-01-25
...existing changelog content...
## [1.0.0-rc1] - 2025-12-20

### Added
- User-friendly error messages with troubleshooting tips
- File validation for all CLI commands (scan, deps, correlate)
- Graceful handling of missing files and empty directories
- PyPI packaging with Python 3.10+ support
- 21 comprehensive tests for Week 2 features (correlation engine, behavioral patterns)
- GitHub Actions CI/CD pipeline

### Changed
- Lowered Python requirement from 3.12 to 3.10 for broader compatibility
- Improved error messages to guide users toward solutions

### Fixed
- Edge case handling for empty directories
- Proper exception handling to avoid confusing error messages

## [1.0.0] - 2025-12-19

### Added
- Static code analysis for Python and JavaScript/TypeScript
- Detection rules for AutoGen (DAI001), CrewAI (DAI002), LangChain/LangGraph (DAI003)
- Shadow AI detection (DAI004) for unmanaged LLM clients
- Dependency scanning for requirements.txt and package.json
- Network monitoring for active agent connections
- Correlation engine to match code findings with runtime behavior
- Behavioral pattern detection (ReAct loops, RAG patterns, multi-turn conversations)
- Agent classification: CONFIRMED, UNKNOWN, ZOMBIE, GHOST
- SARIF output format for CI/CD integration
- CLI commands: scan, deps, monitor, correlate
- Comprehensive test suite (12 tests)
- MIT License
- Documentation: README, CONTRIBUTING, LICENSE

[Unreleased]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.0.0-rc1...HEAD
[1.0.0-rc1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.0.0...v1.0.0-rc1
[1.0.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/releases/tag/v1.0.0

## [1.1.1] - 2026-02-06

### Changed
- Updated package metadata for PyPI
- Changed author from "DefendAI" to "Mohamed Waseem" for proper attribution
- Improved package description to highlight Kubernetes monitoring capability
- Added comprehensive keywords for better discoverability
- Added project URLs (homepage, documentation, repository, issues, changelog)

### Fixed
- Installation instructions now work correctly via PyPI

## [2.0.2] - 2026-02-15

### Fixed
- install.sh: Fix all remaining hardcoded sudo commands
- install.sh: Properly handle Docker/root environments
- install.sh: Use $SUDO variable consistently throughout

