# AgentDiscover Scanner

**Open Source AI Agent Detection Tool** | Part of the [DefendAI](https://defendai.ai) Ecosystem

Static analysis tool for detecting autonomous AI agents and Shadow AI usage in codebases.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

## 🎯 What It Does

Scans your codebase to find:
- 🤖 **AI Agents** (AutoGen, CrewAI, LangChain, LangGraph)
- 🚨 **Shadow AI** (Unmanaged OpenAI/Anthropic clients)
- 📦 **Agent Dependencies** (requirements.txt, package.json)
- ⚠️ **High-Risk Configurations** (Code execution enabled)

## 🚀 Quick Start
```bash
# Install with uv (recommended)
uv tool install agent-discover-scanner

# Or with pip
pip install agent-discover-scanner

# Scan a repository
agent-discover-scanner scan /path/to/repo

# Scan dependencies only
agent-discover-scanner deps /path/to/repo

# Generate SARIF for CI/CD
agent-discover-scanner scan /path/to/repo --format sarif
```

## 📊 Example Output
```
Scan Complete!
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric                    ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Files Scanned             │ 1,112 │
│ Total Findings            │ 275   │
│   • Errors (Shadow AI)    │ 126   │
│   • Warnings (Agents)     │ 127   │
│   • Notes                 │ 22    │
└───────────────────────────┴───────┘

Findings by Rule:
  DAI001 (AutoGen):    5 finding(s)
  DAI002 (CrewAI):   130 finding(s)
  DAI003 (LangChain):  23 finding(s)
  DAI004 (Shadow AI): 117 finding(s)
```

## 💡 Use Cases

- **Security Audits**: Discover Shadow AI in your organization
- **Compliance**: Enforce AI governance policies
- **CI/CD Integration**: Block deployments with violations
- **Agent Inventory**: Catalog all AI agents across teams

## 🏗️ Architecture

Multi-language AST-based detection:
- Python: `ast.NodeVisitor` for precise pattern matching
- JavaScript/TypeScript: `esprima` parser
- Dependency analysis: Direct file parsing + SBOM support

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
- name: Scan for AI Agents
  run: |
    uv tool install agent-discover-scanner
    agent-discover-scanner scan . --format sarif -o results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## 🌐 DefendAI Ecosystem

This scanner is part of the DefendAI platform for AI security:

- **[AgentDiscover Scanner](https://github.com/yourusername/agent-discover-scanner)** (this) - Find agents
- **[AgentShield Gateway](https://github.com/yourusername/agent-shield)** - Govern agents
- **DefendAI Platform** (Commercial) - Enterprise AI security

## 📝 Detection Rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| DAI001 | AutoGen AssistantAgent detected | Warning/Error |
| DAI002 | CrewAI Agent detected | Warning/Error |
| DAI003 | LangChain/LangGraph agent | Warning/Note |
| DAI004 | Shadow AI (unmanaged LLM) | Error |

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 License

MIT License - See [LICENSE](LICENSE)

## 🙏 Acknowledgments

Thanks to the DefendAI Team!

---

**[Documentation](https://docs.defendai.ai)** | **[Website](https://defendai.ai)** | **[Support](https://github.com/yourusername/agent-discover-scanner/issues)**
