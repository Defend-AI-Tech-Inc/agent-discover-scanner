# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

