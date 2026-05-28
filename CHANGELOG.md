# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [2.7.1] — 2026-05-28

### Fixed

- **Correlator Bug 1 — coverage table shows `"layer2"` instead of `"layer5"`** for CloudTrail
  matches. Root cause: Layer 5 findings merged into `network_findings` were iterated by the
  Layer 2 code path and tagged `"layer2"`. Fix: `correlate()` now splits `network_findings` into
  `l2_network` / `l5_cloud_audit` using the `"detection_layer": "layer5_cloud_audit"` sentinel.
  Detection coverage reports now correctly show `"layer1,layer5"`.
- **Correlator Bug 2 — CONFIRMED not firing for L1+L5:** `_is_known_executor(None)` returned
  `False` for CloudTrail findings (`process_name=None`), blocking the match path. Added a
  dedicated Layer 5 matching step that bypasses the executor check.
- **Correlator Bug 3 — Chrome→Bedrock misclassified as GHOST when L5 findings present:**
  CloudTrail findings (process_name=None) merged into `network_findings` overwrote the
  `active_providers["bedrock"]` entry set by Layer 2 (e.g. Chrome), causing
  `is_known_desktop_app(None)` → GHOST. Fix: `active_providers` is now built from `l2_network`
  only; Layer 5 findings never mutate it.

### Added

- `CorrelationEngine._is_bedrock_finding(cf)` — classmethod returning `True` when
  `rule_id == "DAI007"` or `"bedrock"` is in the finding message.
- Layer 5 GHOST loop in `correlate()`: unmatched Bedrock CloudTrail events (no L1, not covered by
  L2) produce a GHOST item with `detection_layers=["layer5"]` and the IAM principal as
  `process_name`.
- `tests/test_correlator_layer5.py` — 26 regression tests.

---

## [2.7.0] — 2026-05-27

### Added

- **Layer 5 — Cloud Audit** (`detectors/cloud_audit/` package):
  - `CloudAuditDetector` ABC and `CloudAuditFinding` dataclass (`base.py`)
  - `AWSCloudTrailDetector` — CloudTrail LookupEvents + CloudTrail Lake GA (`aws_cloudtrail.py`)
  - `AzureMonitorDetector` Preview stub — `is_available()=False` (`azure_monitor.py`)
  - `GCPAuditLogDetector` Preview stub — `is_available()=False` (`gcp_audit.py`)
  - Auto-discovery via `pkgutil.iter_modules` + `run_cloud_audit_detection()` entry point
- New CLI flags on `scan-all` and `audit`:
  `--cloud-audit`, `--cloud-audit-region`, `--cloud-audit-hours`, `--cloud-audit-lake-arn`,
  `--azure-monitor`, `--gcp-audit`
- Layer 5 runs in its own thread (ThreadPoolExecutor max_workers raised to 5); writes
  `layer5_cloud_audit.json`.
- Backward-compat: old `--cloudtrail-*` flags and `cloudtrail_*` kwargs silently aliased.
- `detectors/cloudtrail.py` → re-export shim pointing at `cloud_audit.aws_cloudtrail`.
- 41 new tests: `tests/test_cloud_audit_layer5.py`; `tests/test_cloudtrail_wiring.py` rewritten.

---

## [2.6.4] — 2026-05-26

### Added

- Bedrock IP-based detection via `ranges.defendai.ai`: Layer 2 network monitor fetches live
  Bedrock CIDR ranges so Bedrock connections are identified even without stable reverse-DNS or
  when traffic flows through a VPC endpoint.

---

## [2.6.3] — 2026-05-26

### Added

- AWS CloudTrail + CloudTrail Lake integration for Bedrock detection:
  - `run_cloudtrail_detection()` with `LookupEvents` (5–15 min delay) and
    CloudTrail Lake `StartQuery` (near-real-time ~60 s)
  - Framework attribution from HTTP `User-Agent` header
  - CLI flags `--cloudtrail-hours` and `--cloudtrail-lake-arn`
  - Deduplication: Lake findings take precedence over standard CloudTrail
  - `tests/test_cloudtrail.py` — 38 tests

---

## [2.6.2] — 2026-05-26

### Added

- Layer 1 `DAI007` signature: `boto3` / `BedrockRuntime` calls detected
- LangGraph `StateGraph` detection with AWS Bedrock as the LLM backend
- SSE proxy fallback module for enterprise TLS-terminating proxies

---

## [2.6.1] — 2026-05-19

<!-- No git tag for this version; date derived from pyproject.toml version bump (commit ef4f740) -->

### Added

- `export-mcpfw-policy` command: export an mcpfw-compatible policy from the MCP inventory.
- `--emit-mcpfw-policy` flag on `scan-all`.

---

## [2.6.0] — 2026-05-13

### Added

- Windows agent detection, `--summary` flag for executive reporting
- GitHub Action usage section in README with inputs/outputs table

---

## [2.5.2] — 2026-05-12

### Added

- `git-scan` command, `--src-repo` flag, macOS first-scan UX

---

## [2.5.1] — 2026-05-08

### Added

- GitHub Action, dry-run flag, AIBOM fix, integration guides, SEO improvements
- ROADMAP, NIST mapping, CONTRIBUTING updates
- macOS install fixes, GHOST false positive fix

---

## [2.5.0] — 2026-04-06

### Added

- `audit` command, AIBOM export (`aibom.py`), `scan_runner` shared implementation
- README and packaging fixes

---

## [2.4.1] — 2026-03-27 (no release tag)

### Added

- MCP and high-risk agent detection

### Changed

- Hardened platform upload payload handling

---

## [2.4.0] — 2026-03-16

### Added

- OpenClaw and MCP multi-signal detection

### Fixed

- Inventory change detection in daemon mode uploads
- Three README typos and rendering issues

---

## [2.3.2] — 2026-03-15

### Added

- `--platform-interval` flag for periodic platform sync in daemon mode

### Fixed

- `shadow_ai_usage` agent_id prefix and risk level cap
- `shadow_ai_usage` classification and demo polish

---

## [2.3.0] — 2026-03-14

### Added

- Multi-layer SaaS connection detection (`saas_detector.py`)

---

## [2.2.0] — 2026-03-13 (no release tag)

### Added

- `--platform` flag: upload scan results to DefendAI platform via `/scanner/ingest`
- macOS certificate trust handling via `certifi`
- Noise filtering for test fixtures and `node_modules`

---

## [2.1.10] — 2026-03-09 (no release tag)

### Added

- Platform upload after scan via `/scanner/ingest`

---

## [2.1.9] — 2026-03-05 (no release tag)

### Changed

- eBPF first, K8s API fallback in Layer 3; `kubernetes` promoted to hard dependency

---

## [2.1.8] — 2026-03-05 (no release tag)

### Fixed

- TracingPolicy filter `state=1` (ESTABLISHED) for populated IPs
- K8s Python API fallback when Tetragon is unavailable

---

## [2.1.7] — 2026-03-01

### Fixed

- Layer 3 parser correctly extracts pod info from `process_tracepoint` events
- Minor correlator fixes

---

## [2.1.6] — 2026-02-28 (no release tag)

### Added

- Tetragon native file export for production-safe Layer 3 eBPF monitoring

---

## [2.1.5] — 2026-02-28 (no release tag)

### Fixed

- Layer 3 parser correctly extracts pod info from `process_tracepoint` events

---

## [2.1.4] — 2026-02-28 (no release tag)

### Fixed

- Layer 3 parser correctly extracts pod info from `process_tracepoint` events

---

## [2.1.3] — 2026-02-28 (no release tag)

### Added

- Demo environment with sample agents

### Fixed

- Demo pods use stdlib `urllib` (no pip install delay at startup)
- Use heredoc pattern for demo pod scripts
- Use ConfigMap for demo agent scripts
- Layer 3 findings written to output directory when using `--layer3-file`
- Layer 3 parser correctly extracts pod info from `process_tracepoint` events

---

## [2.1.1] — 2026-02-28 (no release tag)

### Fixed

- Daemon retry/backoff, log rotation, disk monitoring, Layer 3 tailing, systemd service,
  TracingPolicy install

---

## [2.1.0] — 2026-02-27 (no release tag)

### Added

- Tetragon native file export, production-safe Layer 3

---

## [2.0.9] — 2026-02-27 (no release tag)

### Added

- `scan-all` command, `--version` flag, multi-layer correlation engine

### Fixed

- Tetragon select-based polling; parallel `scan-all`, daemon mode

---

## [2.0.8] — 2026-02-26 (no release tag)

### Added

- `scan-all` command, `--version` flag
- Multi-layer correlation engine: GHOST detection across Layers 1, 2, and 3
- Detection coverage report
- Expanded provider matching, risk escalation, `detection_layers` per agent

---

## [2.0.7] — 2026-02-26 (no release tag)

### Fixed

- Warning for httpx calls
- DAI005 logic

---

## [2.0.6] — 2026-02-26 (no release tag)

### Fixed

- Deduplicate findings
- DAI005 debug logging added

---

## [2.0.5] — 2026-02-26 (no release tag)

### Fixed

- Two-pass AST scan so DAI005 fires correctly
- Remove Cilium CNI requirement
- Auto-include Layers 2 and 3 when Kubernetes detected
- install.sh: use `--help` for verification
- install.sh: remove test scan (wrong CLI syntax)

### Documentation

- Updated README with v2.0.2, one-command install, endpoint details

---

## [2.0.2] — 2026-02-15 (no release tag)

### Fixed

- install.sh: replace all hardcoded `sudo` with `$SUDO`
- install.sh: properly handle Docker/root environments

---

## [2.0.1] — 2026-02-15 (no release tag)

### Fixed

- Improved network connection detection with psutil
- Improved AI service and vector DB detection
- install.sh: handle sudo in Docker containers

---

## [2.0.0] — 2026-02-14 (no release tag)

### Added

- Layer 4: Endpoint discovery for Shadow AI detection
- Tetragon/eBPF integration merged from feature branch

### Changed

- Revised code scan results and agent classifications

### Fixed

- Remove sensitive files and demo artifacts
- Address Layer 4 code review feedback

---

## [1.1.1] — 2026-02-06

### Added

- Tetragon/eBPF integration for Kubernetes monitoring (v1.1.0)
- JSON/JSONL output format
- kubectl pod selection fix

### Changed

- Updated PyPI package metadata and release v1.1.1

---

## [1.0.0-rc2] — 2025-12-21

### Added

- GitHub Actions CI/CD pipeline and code quality tooling

---

## [1.0.0-rc1] — 2025-12-20

### Added

- User-friendly error messages with troubleshooting tips
- File validation for all CLI commands
- Graceful handling of missing files and empty directories
- PyPI packaging with Python 3.10+ support

---

## [1.0.0] — 2025-12-19

### Added

- AgentDiscover Scanner v1.0.0 — Open Source Release
- Static code analysis for Python and JavaScript/TypeScript
- Detection rules for AutoGen (DAI001), CrewAI (DAI002), LangChain/LangGraph (DAI003)
- Shadow AI detection (DAI004) for unmanaged LLM clients
- Dependency scanning for requirements.txt and package.json
- Network monitoring for active agent connections
- Correlation engine to match code findings with runtime behavior
- Behavioral pattern detection (ReAct loops, RAG patterns, multi-turn conversations)
- Agent classification: CONFIRMED, UNKNOWN, ZOMBIE, GHOST
- SARIF output format for CI/CD integration
- CLI commands: `scan`, `deps`, `monitor`, `correlate`
- MIT License

[Unreleased]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.7.1...HEAD
[2.7.1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.6.4...v2.7.0
[2.6.4]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.6.3...v2.6.4
[2.6.3]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.6.2...v2.6.3
[2.6.2]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.6.1...v2.6.2
[2.6.1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.6.0...v2.6.1
[2.6.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.5.2...v2.6.0
[2.5.2]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.5.1...v2.5.2
[2.5.1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.3.2...v2.4.0
[2.3.2]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.3.0...v2.3.2
[2.3.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v2.1.7...v2.3.0
[2.1.7]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.1.1...v2.1.7
[1.1.1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.0.0-rc2...v1.1.1
[1.0.0-rc2]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.0.0-rc1...v1.0.0-rc2
[1.0.0-rc1]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/compare/v1.0.0...v1.0.0-rc1
[1.0.0]: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/releases/tag/v1.0.0
