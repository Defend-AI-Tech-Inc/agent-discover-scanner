# AgentDiscover Scanner

<div align="center">

**Open-Source AI Agent Discovery for the Enterprise**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/agent-discover-scanner.svg)](https://pypi.org/project/agent-discover-scanner/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Part of the [DefendAI](https://defendai.ai) platform for autonomous AI governance*

</div>

---

> **Every enterprise is about to deploy AI systems that act autonomously.  
> Who governs them once they start acting?**

Most enterprises think AI risk means employees pasting data into ChatGPT. That's yesterday's problem.

The real risk is **AI agents with API keys, database access, and tool privileges acting independently** — without a human in the loop, without a registry, without governance.

AgentDiscover Scanner is Step 1: **find everything that's running.**

---

## What It Finds

| Classification | What It Means | Risk |
|---|---|---|
| ✅ **CONFIRMED** | Agent detected in code AND observed running at runtime | High — actively executing |
| 👻 **GHOST** | Agent observed at runtime with NO corresponding source code | **Critical — ungoverned** |
| ⚠️ **UNKNOWN** | Agent found in code, not yet observed at runtime | Medium — unverified |
| ☠️ **ZOMBIE** | Agent in code, was active, no longer observed | Low — potentially abandoned |

**GHOST agents are the most dangerous finding.** An AI system is making real API calls — consuming tokens, potentially accessing data — but your engineering team has no record of it. No code, no deployment, no owner.

---

## Quick Start

```bash
# Install
pip install agent-discover-scanner

# Scan a codebase
agent-discover-scanner scan-all /path/to/your/code
```

For Kubernetes environments (full deployment):
```bash
curl -fsSL https://raw.githubusercontent.com/Defend-AI-Tech-Inc/agent-discover-scanner/main/install.sh | sudo bash
agent-discover-scanner scan-all /path/to/code --daemon --output /var/log/defendai
```

---

## How It Works

AgentDiscover Scanner combines four detection methods and correlates them into a single agent inventory.

**Source Code Analysis**  
Static analysis of Python and JavaScript/TypeScript codebases. Detects LangChain, LangGraph, CrewAI, AutoGen, direct OpenAI/Anthropic/Gemini API usage, and any HTTP client targeting LLM provider endpoints. Handles import aliasing and indirect usage patterns.

**Network Monitoring**  
Live observation of outbound connections to AI providers — OpenAI, Anthropic, Google Gemini, Mistral, Cohere, Azure OpenAI, AWS Bedrock, and vector stores (Pinecone, Weaviate, Qdrant). No packet capture required; works passively.

**Kubernetes Runtime Monitoring**  
Kernel-level visibility into pod behavior inside your cluster. Identifies which workloads are actively making AI calls — including workloads with no corresponding source code (GHOST agents). Works with any CNI (Flannel, Calico, Weave, AWS VPC CNI, GKE CNI, and others).

**Endpoint Discovery**  
Scans developer machines, CI/CD runners, and workstations for AI tool usage — installed AI packages, desktop AI applications (ChatGPT Desktop, Claude Desktop, Cursor, GitHub Copilot), active AI connections, and browser-based AI usage.

---

## Example Output

```
🔍 Scanning for autonomous AI agents...
📂 Analyzing source code at ./my-repo
🌐 Monitoring live network connections...
☸️  Monitoring Kubernetes workloads...
🔗 Correlating findings...

🤖 Autonomous Agent Inventory
┌────────────────┬───────┬────────────────────────────────────────────────────┐
│ Classification │ Count │ Description                                        │
├────────────────┼───────┼────────────────────────────────────────────────────┤
│ CONFIRMED      │   2   │ Active — detected in code and observed at runtime  │
│ UNKNOWN        │   3   │ Code found — not yet observed at runtime           │
│ ZOMBIE         │   0   │ Inactive — code exists but no recent activity      │
│ GHOST          │   1   │ ⚠ Critical — runtime activity with no source code  │
└────────────────┴───────┴────────────────────────────────────────────────────┘

✅ Scan complete — results saved to ./results
```

**GHOST Agent Alert:**
```
👻 GHOST AGENT DETECTED
   Workload:  trading-bot (Deployment/default)
   Runtime:   Observed making live API calls to OpenAI
   Code:      No source code found in scanned repositories
   Action:    Investigate — this agent has no registered owner
```

---

## Daemon Mode

Run continuously as a background service, updating the agent inventory every 30 seconds:

```bash
# Start daemon
agent-discover-scanner scan-all /path/to/code \
  --daemon \
  --output /var/log/defendai

# Install as a systemd service (Linux)
sudo bash deployment/systemd/install-service.sh /path/to/code
systemctl status defendai-scanner
```

New agents appear in `agent_inventory.json` as they are discovered. Designed for production deployment alongside existing security tooling.

---

## CI/CD Integration

```yaml
# .github/workflows/agent-scan.yml
- name: Scan for AI Agents
  run: |
    pip install agent-discover-scanner
    agent-discover-scanner scan . --format sarif --output results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Commands

```bash
# Full scan (recommended) — code + network + Kubernetes + endpoints
agent-discover-scanner scan-all /path/to/code [OPTIONS]
  --duration SECONDS      Runtime observation window [default: 60]
  --output PATH           Results directory [default: ./results]
  --daemon                Run continuously, updating inventory every 30s
  --layer3-file PATH      Path to Kubernetes runtime log

# Code scan only
agent-discover-scanner scan /path/to/code

# Dependency scan
agent-discover-scanner deps /path/to/code

# Network monitor only
agent-discover-scanner monitor --duration 60

# Kubernetes runtime monitor only
agent-discover-scanner monitor-k8s --duration 60

# Endpoint scan (current machine)
agent-discover-scanner endpoint
```

---

## Detected Frameworks & Providers

**AI Frameworks:** LangChain, LangGraph, CrewAI, AutoGen  
**LLM Providers:** OpenAI, Anthropic, Google Gemini, Mistral, Cohere, Azure OpenAI, AWS Bedrock  
**Vector Stores:** Pinecone, Weaviate, Qdrant, Chroma  
**Direct usage:** Any HTTP client targeting known LLM API endpoints  

---

## Try the Demo

Run a complete demo with simulated AI agents in under 10 minutes:

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner
cd agent-discover-scanner/demo
./setup.sh    # deploys LangChain, CrewAI, and a shadow agent to local Kubernetes
agent-discover-scanner scan-all ./sample-repo --duration 60
```

Expected: 2 CONFIRMED agents, 1 GHOST agent (shadow-agent — running with no source code).

---

## Requirements

| Capability | Requirement |
|---|---|
| Code scanning | Python 3.10+, no additional dependencies |
| Network monitoring | Python 3.10+, root/sudo |
| Kubernetes runtime | kubectl, Helm 3+, root/sudo |
| Endpoint discovery | Python 3.10+, root/sudo |

Full Kubernetes setup: `install.sh` handles Helm, runtime monitoring setup, and permissions automatically.

---

## DefendAI Platform

AgentDiscover Scanner is the **discovery layer** of the DefendAI platform — the first step in building a governance control plane for autonomous AI.

| Component | Status | Description |
|---|---|---|
| **AgentDiscover Scanner** | ✅ Open Source | Discover and classify AI agents |
| **defendai-agent** | 🧪 Beta | MITM proxy for AI traffic governance |
| **Policy Engine** | 🚧 Coming Soon | Define and enforce agent behavior rules |
| **DefendAI Platform** | 💼 Enterprise | Full lifecycle governance for autonomous AI |

[defendai.ai](https://defendai.ai) · [playground.defendai.ai](https://playground.defendai.ai) · [support@defendai.ai](mailto:support@defendai.ai)

---

## Contributing

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner.git
cd agent-discover-scanner
uv sync
uv run pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Issues and PRs welcome.

---

## License

MIT — free to use, deploy, and modify.

---

*Built by [DefendAI](https://defendai.ai) · Securing the future of autonomous AI*
