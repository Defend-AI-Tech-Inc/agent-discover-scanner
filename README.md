# AgentDiscover Scanner

<div align="center">

**Multi-Layer AI Agent Detection: Code • Network • Kubernetes**

> Find AI agents everywhere with static analysis, network monitoring, and eBPF runtime detection

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Part of the [DefendAI](https://defendai.ai) Ecosystem for AI Security*

[Features](#features) • [Quick Start](#quick-start) • [Use Cases](#use-cases) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---
## 🎯 Three Detection Layers for Complete Visibility

### 1️⃣ Static Code Analysis
Scan repositories to find AI frameworks and Shadow AI
* 🔍 Python & JavaScript/TypeScript support (AST-based)
* 🤖 Detects: AutoGen, CrewAI, LangChain, LangGraph
* 🚨 Finds ungoverned LLM clients (Shadow AI)
* 📦 Analyzes dependencies (requirements.txt, package.json)
* 📊 CI/CD ready (SARIF output for GitHub Security)

### 2️⃣ Network Traffic Monitoring  
Monitor active agents by their API connections
* 🌐 Works on local machines and servers
* 🔌 Detects: OpenAI, Anthropic, Google AI, Cohere, AWS Bedrock
* 💾 Tracks vector databases (Pinecone, Weaviate, Qdrant)
* ⚡ Real-time detection as agents make API calls

### 3️⃣ Kubernetes Runtime Detection (NEW in v1.1.0)
Get production visibility with eBPF monitoring
* ⚙️ Kernel-level visibility via Cilium Tetragon
* 🎯 Full attribution: pod, container, workload, binary
* 🚀 Zero code changes required
* 📍 Continuous cluster monitoring

### 🔗 Correlation Engine
* Matches code findings with runtime behavior
* Classifies agents: **CONFIRMED**, **UNKNOWN**, **ZOMBIE**, **GHOST**
* Creates complete agent inventory across all three layers

## 💡 Why AgentDiscover Scanner?

Most tools only cover one detection layer. AgentDiscover Scanner covers all three:

| Detection Layer | Snyk/Semgrep | Network Tools | K8s Security | AgentDiscover |
|----------------|--------------|---------------|--------------|---------------|
| **Code Scanning** | ✅ | ❌ | ❌ | ✅ |
| **Network Monitoring** | ❌ | ✅ | ❌ | ✅ |
| **K8s Runtime** | ❌ | ❌ | ✅ | ✅ |
| **Correlation Engine** | ❌ | ❌ | ❌ | ✅ |

**Result:** Complete visibility from development to production, not just one layer.

## ✨ Features

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

### Installation

```bash
# Using pipx (recommended)
pipx install agent-discover-scanner

# Using pip
pip install agent-discover-scanner
```

### Choose Your Detection Mode

#### 🔍 Scan Code (Security Audits, CI/CD)

```bash
# Scan repository
agent-discover-scanner scan /path/to/repo

# Generate SARIF for CI/CD
agent-discover-scanner scan . --format sarif --output results.sarif
```

**Detects:** AI frameworks, ungoverned LLM clients, risky dependencies

---

#### 🌐 Monitor Network (Developer Machines, Local Testing)

```bash
# Monitor network traffic for 60 seconds
agent-discover-scanner monitor --duration 60
```

**Detects:** Live API connections to OpenAI, Anthropic, Google AI, Cohere, vector databases

---

#### ⚙️ Watch Kubernetes (Production Clusters)

```bash
# Monitor K8s cluster in real-time
agent-discover-scanner monitor-k8s

# Save detections
agent-discover-scanner monitor-k8s --output detections.jsonl
```

**Detects:** AI agents with full pod/container/workload attribution

**Requires:** [Cilium Tetragon setup](docs/TETRAGON_SETUP.md)

**Example Detection:**
```
🚨 AI Agent Detected! production/trading-bot -> OpenAI (api.openai.com:443)

Detection Details:
├─ Pod: trading/high-frequency-trader-7d8f9
├─ Namespace: trading
├─ Workload: Deployment/trading-bot
├─ Container: trading-algo
├─ Binary: /usr/bin/python3
├─ Process: python3 bot.py
└─ Provider: OpenAI

Classification: CONFIRMED (code + active network)
```

---

#### 🔗 Correlate Results (Complete Inventory)

```bash
# Combine all detection layers
agent-discover-scanner correlate \
  --code-scan results.sarif \
  --network-scan network-findings.json
```

**Result:** Complete agent inventory with CONFIRMED, UNKNOWN, ZOMBIE, and GHOST classifications

---

[See full documentation →](#documentation)

# Correlate code + network findings
agent-discover-scanner correlate \
  --code-scan results.sarif \
  --network-scan network-findings.json
```

## 📊 Example Output

### Code Scan
```
Scan Complete!
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric                    ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Files Scanned             │ 1,112 │
│   • Python                │ 890   │
│   • JavaScript/TypeScript │ 222   │
│ Total Findings            │ 275   │
│   • Errors (Shadow AI)    │ 126   │
│   • Warnings (Agents)     │ 127   │
│   • Notes                 │ 22    │
└───────────────────────────┴───────┘

Findings by Rule:
  DAI001 (AutoGen):     5 finding(s)
  DAI002 (CrewAI):    130 finding(s)
  DAI003 (LangChain):  23 finding(s)
  DAI004 (Shadow AI): 117 finding(s)
```

### Correlation Report
```
Correlation Complete!
┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Classification ┃ Count ┃ Description                    ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CONFIRMED      │ 111   │ Code + Network (Active)        │
│ UNKNOWN        │ 164   │ Code Only (Not Yet Active)     │
│ ZOMBIE         │ 0     │ Code But No Traffic            │
│ GHOST          │ 1     │ Traffic But No Code (CRITICAL) │
└────────────────┴───────┴──────────────────────────────────┘

⚠️  GHOST AGENTS DETECTED!
Active agents with NO corresponding code found:
  • Provider: pinecone
    Process: python
    Last Seen: 2025-12-19T16:00:00Z
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

**Built by the DefendAI team**

*Securing the future of autonomous AI*
