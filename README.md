# AgentDiscover Scanner

<div align="center">

**Open Source AI Agent Detection Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Part of the [DefendAI](https://defendai.ai) Ecosystem for AI Security*

[Features](#features) • [Quick Start](#quick-start) • [Use Cases](#use-cases) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🎯 What It Does

AgentDiscover Scanner detects autonomous AI agents and Shadow AI in your codebase through:

- 🔍 **Static Code Analysis** - AST-based detection across Python & JavaScript
- ⚙️ **eBPF Runtime Detection** - Real-time Kubernetes monitoring via Cilium Tetragon
- 🚨 **Shadow AI Detection** - Unmanaged LLM clients bypassing governance
- 🤖 **Framework Detection** - AutoGen, CrewAI, LangChain, LangGraph support
- 📦 **Dependency Scanning** - Analyze requirements.txt & package.json
- 🌐 **Network Monitoring** - Detect active agents by their API traffic (local + Kubernetes)
- 🔗 **Correlation Engine** - Match code findings with runtime behavior
- 📊 **SARIF Output** - CI/CD integration ready

## ✨ Features

**Latest:** v2.0.2 - Four-layer detection now available! 🎉

### Multi-Language Support
```bash
# Scans both Python and JavaScript/TypeScript
agent-discover-scanner scan ./my-project
```

### Detection Rules

| Rule ID | Description | Severity | Example |
|---------|-------------|----------|---------|
| **DAI001** | AutoGen AssistantAgent | ⚠️ Warning / 🔴 Error | `autogen.AssistantAgent(code_execution_config=...)` |
| **DAI002** | CrewAI Agent | ⚠️ Warning / 🔴 Error | `crewai.Agent(allow_code_execution=True)` |
| **DAI003** | LangChain/LangGraph | ⚠️ Warning / 📘 Note | `langchain.agents.initialize_agent()` |
| **DAI004** | Shadow AI (Unmanaged LLM) | 🔴 Error | `OpenAI()` without DefendAI Gateway |

### Agent Classification

- **CONFIRMED**: Found in code ✅ + Active network traffic ✅
- **UNKNOWN**: Found in code ✅ + Not yet running ⏸️
- **ZOMBIE**: Found in code ✅ + No traffic (deprecated) 🪦
- **GHOST**: Network traffic ✅ + No code found 👻 **(CRITICAL)**

## 🚀 Quick Start

### One-Command Installation (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/Defend-AI-Tech-Inc/agent-discover-scanner/main/install.sh | bash
```

This installer:
- Auto-detects your environment (macOS/Linux/Windows)
- Installs all dependencies (Python, osquery, psutil)
- Handles sudo/root automatically
- Works in Docker containers
- Sets up all four detection layers

### Manual Installation
```bash
# Option 1: Using uv (recommended)
uv tool install agent-discover-scanner

# Option 2: Using pipx
pipx install agent-discover-scanner

# Option 3: Using pip
pip install agent-discover-scanner
```

### Basic Usage
```bash
# Scan a repository
agent-discover-scanner scan /path/to/repo

# Scan with verbose output
agent-discover-scanner scan /path/to/repo --verbose

# Generate SARIF for CI/CD
agent-discover-scanner scan /path/to/repo --format sarif --output results.sarif

# Scan dependencies only
agent-discover-scanner deps /path/to/repo

# Monitor local network for active agents (30 seconds)
agent-discover-scanner monitor --duration 30
```

### Kubernetes Monitoring (v1.1.0+) 🆕

Monitor production Kubernetes clusters in real-time using Cilium Tetragon eBPF:
```bash
# Monitor cluster for AI agent activity
agent-discover-scanner monitor-k8s

# Monitor for specific duration  
agent-discover-scanner monitor-k8s --duration 60

# Save detections to JSONL file
agent-discover-scanner monitor-k8s --output detections.jsonl --format jsonl

# Monitor Tetragon in custom namespace
agent-discover-scanner monitor-k8s --namespace monitoring
```

**Detects:**
- OpenAI, Anthropic, Google AI, Cohere API connections
- Azure OpenAI, AWS Bedrock traffic  
- Vector databases (Pinecone, Weaviate, Qdrant)
- Full pod/container/workload attribution

**Requires:**
- Cilium Tetragon installed in cluster
- kubectl configured and authenticated
- See [Tetragon Setup Guide](docs/TETRAGON_SETUP.md)

**Example Detection:**
```
🚨 AI Agent Detected! production/trading-bot -> OpenAI (162.159.140.245:443)
Pod: trading/high-frequency-trader-7d8f9
Workload: Deployment/trading-bot
Binary: /usr/bin/python3
```

### Endpoint Discovery 🖥️ **NEW in v2.0!**

Discover Shadow AI on any laptops, servers and workstations:
```bash
# Scan local endpoint for Shadow AI
agent-discover-scanner endpoint

# Generate markdown report
agent-discover-scanner endpoint --format markdown --output endpoint-report.md

# JSON output for automation
agent-discover-scanner endpoint --format json
```

**Supported Platforms:**
- 💻 macOS (10.15+)
- 🐧 Linux (Ubuntu, Debian, RHEL, Fedora)
- 🪟 Windows (10, 11, Server 2019+)

**Deployment Scenarios:**
- Employee laptops (company-issued)
- Developer workstations
- Contractor machines (desktop/laptop)
- Remote worker endpoints
- Jump boxes and bastion hosts
- CI/CD runners
- Virtual Desktop Infrastructure (VDI)

**What It Finds:**

**Desktop AI Applications:**
- ChatGPT Desktop
- Claude Desktop
- Cursor IDE
- GitHub Copilot
- Continue.dev
- Windsurf
- Aider

**Installed AI Packages:**
- Python: openai, anthropic, langchain, crewai, autogen
- Node.js: @anthropic-ai/sdk, openai, langchain

**Active AI Connections:**
- Real-time API calls to OpenAI, Anthropic, Google AI
- WebSocket connections
- Browser-based AI usage (chatgpt.com, claude.ai)

**Risk Assessment:**
- 0-25: Low (minimal AI usage)
- 26-50: Medium (some AI tools)
- 51-75: High (significant Shadow AI)
- 76-100: Critical (widespread ungoverned AI)

**Requirements:**
- osquery (auto-installed by install.sh)
- Python 3.10+
- Admin/sudo access for installation
- See [Layer 4 Setup Guide](docs/layer4-setup.md)

**Detects:**
- Works on ANY laptop, workstation, or server (employee or contractor)
- Desktop AI apps: ChatGPT, Claude Desktop, Cursor, GitHub Copilot
- AI packages: pip/npm packages (openai, langchain, anthropic, crewai)
- Active AI connections: Live API calls to LLM providers
- Browser AI usage: ChatGPT, Claude, Gemini tabs
- Risk scoring: 0-100 based on Shadow AI severity

**Requires:**
- osquery (auto-installed by install.sh)
- Works on: macOS, Linux, Windows

**Example Output:**
```
🖥️  ENDPOINT SCAN RESULTS
Risk Score: 75/100 (HIGH)
Desktop Applications:
✓ ChatGPT Desktop (v1.2.3)
✓ Cursor (v0.40.1)
✓ GitHub Copilot (VS Code extension)
Installed Packages:
✓ openai (1.54.3) - pip
✓ anthropic (0.39.0) - pip
✓ langchain (0.3.11) - npm
Active Connections:
🚨 api.openai.com:443 (ChatGPT Desktop)
🚨 api.anthropic.com:443 (Python process)
Browser Activity:
✓ chatgpt.com (3 tabs open)
✓ claude.ai (1 tab)
⚠️  HIGH RISK: Multiple Shadow AI tools detected
```

```bash
# Correlate code + network findings
agent-discover-scanner correlate \
  --code-scan results.sarif \
  --network-scan network-findings.json
```

## 📊 Example Output
### Code Scan Results

**Files Analyzed:**
- Total: 1,112 files
- Python: 890 files
- JavaScript/TypeScript: 222 files

**Findings:**
- Total: 275 findings
- Errors (Shadow AI): 126
- Warnings (Agents): 127
- Notes: 22

**Detection Breakdown:**
- `DAI001` AutoGen: 5 findings
- `DAI002` CrewAI: 130 findings
- `DAI003` LangChain: 23 findings
- `DAI004` Shadow AI: 117 findings

### Correlation Report

**Agent Classifications:**

| Type | Count | Description |
|------|-------|-------------|
| ✅ **CONFIRMED** | 111 | Code + Network (Active) |
| ⚠️ **UNKNOWN** | 164 | Code Only (Not Yet Active) |
| 💀 **ZOMBIE** | 0 | Code But No Traffic |
| 👻 **GHOST** | 1 | Traffic But No Code **(CRITICAL)** |

**⚠️ GHOST AGENT ALERT**  
Active agent detected with NO corresponding code:
- Provider: Pinecone
- Process: Python
- Last Seen: 2025-12-19
- **Action Required:** Investigate unauthorized agent!

```

## 💡 Use Cases

### 1. Security Audits
```bash
# Find all Shadow AI in your organization
agent-discover-scanner scan /path/to/all/repos --format sarif
```

### 2. Compliance Enforcement
```bash
# Detect ungoverned LLM usage
agent-discover-scanner scan . | grep "DAI004"
```

### 3. CI/CD Integration
```yaml
# .github/workflows/agent-scan.yml
- name: Scan for AI Agents
  run: |
    agent-discover-scanner scan . --format sarif -o results.sarif
    
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### 4. Agent Inventory
```bash
# Create complete catalog
agent-discover-scanner scan /repos --output inventory.sarif
agent-discover-scanner monitor --duration 300
agent-discover-scanner correlate --code-scan inventory.sarif
```

## 📚 Documentation

### Commands

#### `scan` - Scan source code
```bash
agent-discover-scanner scan <path> [OPTIONS]

Options:
  --format (table|sarif|both)  Output format [default: table]
  --output PATH                SARIF output file [default: results.sarif]
  --verbose, -v                Show detailed output
```

#### `deps` - Scan dependencies
```bash
agent-discover-scanner deps <path> [OPTIONS]

Options:
  --verbose, -v  Show detailed output
```

#### `monitor` - Monitor network traffic
```bash
agent-discover-scanner monitor [OPTIONS]

Options:
  --duration SECONDS  How long to monitor [default: 60]
  --output PATH       JSON output file [default: network-findings.json]
```

#### `correlate` - Correlate findings
```bash
agent-discover-scanner correlate [OPTIONS]

Options:
  --code-scan PATH     SARIF file from code scan [required]
  --network-scan PATH  JSON file from network monitor [default: network-findings.json]
  --output PATH        Output inventory JSON [default: agent-inventory.json]
```

## 🏗️ Architecture

### Detection Strategy

**Static Analysis (AST-based)**
- Python: `ast.NodeVisitor` for precise pattern matching
- JavaScript: `esprima` parser for JS/TS support
- Import resolution handles aliasing (`import langchain as lc`)

**Network Fingerprinting**
- Passive monitoring of LLM API connections
- Behavioral pattern detection (ReAct loops, RAG patterns)
- Process-level attribution

**Correlation Engine**
- Matches code findings → runtime behavior
- Detects Ghost Agents (traffic without code)
- Risk-based classification

## 🌐 DefendAI Ecosystem

AgentDiscover Scanner is part of the DefendAI platform for AI security:

| Component | Status | Description |
|-----------|--------|-------------|
| **AgentDiscover** | ✅ Open Source | Find and catalog AI agents |
| **AgentShield** | 🚧 Coming Soon | MCP Gateway for governance |
| **ContainIQ** | 📋 Planned | Runtime isolation for agents |
| **DefendAI Platform** | 💼 Commercial | Enterprise AI security suite |

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/agent-discover-scanner.git
cd agent-discover-scanner

# Install dependencies
uv sync

# Make changes and test
uv run pytest tests/ -v

# Run linter
uv run ruff check .

# Submit PR
git push origin feature/your-feature
```

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## 🙏 Acknowledgments

Built with:
- [uv](https://github.com/astral-sh/uv) - Fast Python package manager
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [Pydantic](https://docs.pydantic.dev/) - Data validation

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/discussions)
- 📧 **Email**: support@defendai.ai
- 🌐 **Website**: [defendai.ai](https://defendai.ai)

## ⭐ Star History

If you find this tool useful, please star the repository!

---

**Built with ❤️ by the DefendAI team**

*Securing the future of autonomous AI*
