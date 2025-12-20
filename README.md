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
- 🚨 **Shadow AI Detection** - Unmanaged LLM clients bypassing governance
- 🤖 **Framework Detection** - AutoGen, CrewAI, LangChain, LangGraph support
- 📦 **Dependency Scanning** - Analyze requirements.txt & package.json
- 🌐 **Network Monitoring** - Detect active agents by their API traffic
- 🔗 **Correlation Engine** - Match code findings with runtime behavior
- 📊 **SARIF Output** - CI/CD integration ready

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

# Monitor network for active agents (30 seconds)
agent-discover-scanner monitor --duration 30

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

**Built with ❤️ by the DefendAI team**

*Securing the future of autonomous AI*
