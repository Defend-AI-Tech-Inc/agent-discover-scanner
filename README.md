# AgentDiscover Scanner

**Open-Source AI Agent Discovery for the Enterprise**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/agent-discover-scanner.svg)](https://pypi.org/project/agent-discover-scanner/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Part of the [DefendAI](https://defendai.ai) platform for autonomous AI governance*

---

## The finding that matters

```
$ agent-discover-scanner scan-all ./your-repo --duration 10

🔍 Scanning for autonomous AI agents...

📂 Analyzing source code at ./your-repo
🌐 Monitoring live network connections...
   Observing runtime behavior (10s)...
🔗 Correlating findings...
✓ Correlation complete

🤖 Autonomous Agent Inventory

┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Classification ┃ Count ┃ Description                                                    ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CONFIRMED      │ 2     │ Active — detected in code and observed at runtime              │
│ UNKNOWN        │ 3     │ Code found — not yet observed at runtime                       │
│ SHADOW AI      │ 3     │ Known app using AI — review for governance                     │
│ ZOMBIE         │ 0     │ Inactive — code exists but no recent runtime activity          │
│ GHOST          │ 1     │ ⚠ Critical — runtime activity with no source code (ungoverned) │
└────────────────┴───────┴────────────────────────────────────────────────────────────────┘
```

A GHOST agent is an AI system making real API calls — consuming tokens, potentially accessing sensitive data — with no corresponding source code, deployment record, or owner. No static analysis tool finds this. No SIEM alerts on it. AgentDiscover Scanner finds it in under 60 seconds by watching the runtime and cross-referencing it against your codebase simultaneously.

**Your engineering team thinks they know what AI is running. The GHOST classification is what they don't know.**

---

## What makes this different

Most security tools tell you what's in your code. AgentDiscover Scanner tells you what's **actually running** — and crucially, what's running that has **no business being there**.

```
👻 GHOST AGENT DETECTED
   Workload:    trading-bot (Deployment/default)
   Connected:   api.openai.com — LIVE
   SaaS:        openai — confirmed active connection
   Source code: None found in scanned repositories
   Owner:       Unknown — no deployment record, no code review

👻 GHOST AGENT DETECTED
   Workload:    shadow-agent (Pod/kube-system)
   Connected:   api.anthropic.com — LIVE
   SaaS:        anthropic — confirmed  |  gcp — active socket
   Blast radius: HIGH (cloud provider access confirmed)
   Source code: None found in scanned repositories
   Owner:       Unknown — no deployment record, no code review
```

Every detected agent also carries a **SaaS blast radius** — a live-observed map of which services it's actively connected to, derived from network traffic, not just configuration files:

```
crewai-agent (CONFIRMED)
  saas_connections:
    anthropic: confirmed  ← active_connection observed
    github:    medium     ← open socket
  risk_flags: [cloud_credentials_present]
  blast_radius: 70/100
```

`confirmed` means the connection was **live-observed** during the scan — not inferred from a config file.

---

## Agent classifications

| Classification    | What it means                              | Risk         |
| ----------------- | ------------------------------------------ | ------------ |
| 👻 **GHOST**      | Runtime AI activity — no source code found | **Critical** |
| ✅ **CONFIRMED**   | Detected in code AND observed running      | High         |
| ⚠️ **UNKNOWN**    | Found in code, not yet observed at runtime | Medium       |
| 🖥️ **SHADOW AI** | Known app using AI without governance      | Medium       |
| ☠️ **ZOMBIE**     | Was active, no longer observed             | Low          |

---

## Quick start

```bash
# macOS (recommended)
brew install python@3.12 osquery pipx
pipx install agent-discover-scanner
pipx ensurepath && source ~/.zshrc   # add ~/.local/bin to PATH

# Linux (Debian/Ubuntu)
sudo apt-get install -y python3 osquery
pip3 install agent-discover-scanner

# Linux (RHEL/Fedora)
sudo dnf install -y python3 osquery
pip3 install agent-discover-scanner

# Windows (PowerShell — elevated)
winget install Python.Python.3.12
winget install osquery.osquery
pip install agent-discover-scanner
```

> **macOS:** never use `sudo` with the installer — Homebrew refuses root and osquery silently fails.
> Use `pipx` to avoid Python environment conflicts. If `agent-discover-scanner` is not found after install, run `pipx ensurepath` and restart your terminal.

Then run your first scan:

```bash
agent-discover-scanner scan-all ~/projects --duration 30
```

To verify all layers are working before your first real scan:

```bash
agent-discover-scanner --version
osquery --version
which agent-discover-scanner   # macOS: should show ~/.local/bin/agent-discover-scanner
```

To upload results to the DefendAI platform:

```bash
agent-discover-scanner scan-all ~/projects \
  --platform \
  --api-key YOUR_API_KEY
```

---

## How it works

![GHOST detection mechanism](./docs/ghost-detection.svg)

AgentDiscover Scanner runs four detection layers simultaneously and correlates them into a single agent inventory. Each layer sees something the others can't.

![AgentDiscover detection pipeline](./docs/architecture.svg)

### Layer 1 — Source code analysis

Static analysis of Python and JavaScript/TypeScript. Detects LangChain, LangGraph, CrewAI, AutoGen, direct OpenAI/Anthropic/Gemini API usage, and any HTTP client targeting LLM endpoints. Handles import aliasing and indirect usage patterns. Generates SARIF output for CI/CD integration.

### Layer 2 — Live network monitoring

Passive observation of outbound connections to AI providers — OpenAI, Anthropic, Google Gemini, Mistral, Cohere, Azure OpenAI, AWS Bedrock, and vector stores. No packet capture. Identifies which process is making each connection, enabling per-agent SaaS attribution.

Real scan output:
```
[DETECT] Google AI connection from Mail (PID: 776) → generativelanguage.googleapis.com:993
[DETECT] OpenAI connection from Microsoft Edge Helper (PID: 4172) → api.openai.com:443
[DETECT] Anthropic connection from Cursor Helper (PID: 61436) → api.anthropic.com:443
[DETECT] OpenAI connection from OneDrive (PID: 96089) → api.openai.com:443
```

### Layer 3 — Kubernetes runtime

Kernel-level visibility into pod behavior via Tetragon. Identifies which workloads are actively making AI calls — including workloads with no corresponding source code. Works with any CNI. Falls back to Kubernetes API discovery if Tetragon is unavailable.

When Layer 1 (code) and Layer 3 (K8s runtime) both detect the same agent, it becomes **CONFIRMED**:

```
Detection Coverage:
┏━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Layers        ┃ Agents ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ layer1,layer3 │ 2      │  ← CONFIRMED: seen in code AND running in K8s
│ layer1        │ 3      │  ← UNKNOWN: code found, not yet observed at runtime
└───────────────┴────────┘
```

### Layer 3 limitations

Layer 3 (eBPF via Tetragon) is **Linux-only**. On macOS and Windows developer machines, Layer 3 is skipped automatically — the scan continues with Layers 1, 2, and 4. The K8s API monitor path works on all platforms and requires only `kubectl` with cluster read access.

### Layer 4 — Endpoint discovery

Scans developer machines, CI/CD runners, and workstations via osquery. Finds installed AI packages, desktop AI applications (ChatGPT Desktop, Claude Desktop, Cursor, GitHub Copilot), active connections, browser-based AI usage, and VSCode extensions.

### Cross-layer correlation

After all layers run, the correlator builds a unified agent identity. An agent seen in code (Layer 1), confirmed running in K8s (Layer 3), and observed making network calls (Layer 2) is a single correlated identity — not three separate findings.

Agents present at runtime with **no Layer 1 match** become GHOST agents.

### SaaS blast radius detection (v2.3.0+)

After correlation, each agent receives a `saas_connections` profile built from all four layers:

```json
{
  "detected":  ["anthropic", "gcp", "github"],
  "confirmed": ["anthropic"],
  "evidence": {
    "anthropic": ["active_connection", "open_socket"],
    "gcp":       ["open_socket"],
    "github":    ["vscode_extension_detected"]
  },
  "confidence": {
    "anthropic": "confirmed",
    "gcp":       "medium",
    "github":    "medium"
  },
  "has_cloud_provider": true,
  "has_llm_provider":   true
}
```

---

## High-risk agent detection (v2.4.0+)

The scanner detects autonomous agent platforms that carry systemic security risk by design — not misconfigurations, but architecture.

**OpenClaw** (formerly Clawdbot/Moltbot) is the primary target. It has full filesystem access, terminal execution, email and messaging integration, and runs as a persistent background daemon. CVE-2026-25253 CVSS 8.8. Gartner: "insecure by default." Microsoft: "treat as untrusted code execution."

Detection uses corroborated signals — never a single port number:

```
🚨 HIGH-RISK AGENT CONFIRMED: OpenClaw
   Autonomous agent with system-level access — filesystem,
   terminal, email, and messaging integration.
   Capabilities: filesystem, terminal, email, browser, messaging
```

---

## MCP server detection (v2.4.0+)

MCP (Model Context Protocol) is the integration layer between AI agents and enterprise SaaS. Supported by Claude, ChatGPT, Gemini, Copilot, Cursor, and VS Code.

The scanner detects MCP servers across all AI clients and classifies each by publisher verification:

```
⚠ Local MCP script detected — unknown code with tool access
⚠ Unverified MCP server: filesystem (Community/Unknown) — not from a verified publisher
⚠ Unverified MCP server: mcpfw (Unknown) — not from a verified publisher

✓ Verified: @salesforce/mcp-server (Salesforce official)
```

Supported clients: Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI, OpenAI Codex, Continue.dev, Zed, and project-level MCP configs.

**Non-developer detection:** Financial analysts connecting ChatGPT Teams to Salesforce via UI leave no local config file. The scanner detects this via Layer 2 network traffic — the only tool that catches this pattern.

Risk prioritization in reporting (guidance):
- Unverified MCP server → HIGH
- MCP filesystem access → HIGH
- MCP + production environment → CRITICAL
- OpenClaw + GHOST → CRITICAL

---

## Daemon mode

Run continuously as a background service, updating the agent inventory every 30 seconds:

```bash
agent-discover-scanner scan-all ~/projects \
  --daemon \
  --output ~/defendai-results \
  --platform \
  --platform-interval 5    # upload to platform every ~2.5 minutes
```

> **Note:** `--daemon` runs until you press Ctrl+C. Use `--output ~/defendai-results` (or any user-writable path) — avoid `/var/log/` which requires root.
> If running as root, `~/projects` resolves to root's home directory, not yours. Always run without `sudo`.

With `--platform`, the daemon syncs to the DefendAI platform every N correlation cycles (default: every 5 cycles ≈ 2.5 minutes) and always uploads a final snapshot on shutdown.

**Linux — install as a systemd service:**

```bash
sudo bash deployment/systemd/install-service.sh ~/projects
systemctl status defendai-scanner
```

---

## Customizing known applications

By default, the scanner classifies common desktop applications (browsers, Office 365, Cursor, Slack, Claude Desktop, etc.) as **Shadow AI** rather than GHOST when they make AI API calls.

Browser-based AI usage (claude.ai, chatgpt.com, copilot.microsoft.com) is detected via Layer 4 browser history — these are classified as Shadow AI automatically. Note that Layer 4 reads the browser's committed history database, not the current active session, so a tab open right now may not appear until the browser flushes its history.

To add your own internal tools:

```bash
mkdir -p ~/.defendai
echo "my-internal-ai-tool" >> ~/.defendai/known_apps.txt
echo "company-llm-client" >> ~/.defendai/known_apps.txt
```

See `docs/known-apps-example.txt` for the full format.

When connected to the DefendAI platform (`--platform` flag), the tenant-managed list is downloaded automatically on startup and merged with your local overrides.

---

## DefendAI platform integration

The scanner is the **discovery layer**. The platform is where discovered agents become governed agents.

```bash
agent-discover-scanner scan-all ~/projects \
  --platform \
  --api-key YOUR_KEY \
  --duration 30
```

When connected to the platform, each scan triggers the **correlation engine** which builds a living identity map across every machine, every environment, and every scan:

- **Agent identity resolution** — the same CrewAI agent on a laptop, in staging K8s, and in prod K8s is recognized as one agent at different lifecycle stages
- **Behavioral drift detection** — agent added `has_code_execution=true` since last week? That's a signal. Platform tracks it.
- **Cross-machine intelligence** — agent seen on 3 machines and crossed from dev into prod? Automatic risk escalation.
- **SaaS blast radius** — platform aggregates confirmed SaaS connections across all scans and computes blast radius score.

After a few scans, the DefendAI platform report shows:

```
Agent Inventory Report — acme-corp
─────────────────────────────────────────────────────────────────────
 shadow-agent    GHOST     CRITICAL   anthropic, github   blast: 85   machines: 3
                           ↑ GHOST seen in production — immediate action required

 crewai-agent    SHADOW    MEDIUM     openai              blast: 25   machines: 1
                           ↑ Unreviewed — no governance record

 langchain-agent KNOWN     LOW        openai              blast: 15   machines: 1
                           ↑ Approved — monitoring active
─────────────────────────────────────────────────────────────────────
 3 agents total · 1 critical · 1 unreviewed · 1 governed
```

---

## CI/CD integration

```yaml
# .github/workflows/agent-scan.yml
- name: Scan for AI agents (Layer 1 — source code)
  run: |
    pip install agent-discover-scanner
    agent-discover-scanner scan . --format sarif --output results.sarif

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

For a full-stack scan in CI (all layers, structured output):

```yaml
- name: Full agent scan
  run: |
    agent-discover-scanner scan-all . \
      --duration 30 \
      --output ./defendai-results \
      --skip-layers 3    # skip K8s layer in CI — no cluster available
      # Note: Layer 3 (eBPF/Tetragon) is Linux-only. Layer 2 requires elevated privileges on Linux.
```

---

## Commands

```bash
# Full scan (recommended) — all 4 layers + correlation
agent-discover-scanner scan-all PATH [OPTIONS]
  --duration/-d SECONDS      Network and K8s monitor observation window [default: 60]
  --output/-o PATH           Output directory for scan results [default: defendai-results]
  --format/-f TEXT           Output format: text|json [default: text]
                               (SARIF output is written to disk by Layer 1 as layer1_code.sarif)
  --layer3-file PATH         Use existing Tetragon JSONL output (skip live Layer 3)
  --skip-layers TEXT         Comma-separated layers to skip, e.g. '3' or '2,3'
  --verbose/-v               Include Layer 3 raw event output
  --daemon                   Run continuously, re-scanning every 30 seconds
  --platform                 Upload results to DefendAI platform after scan
  --api-key TEXT             DefendAI platform API key
  --tenant-token TEXT        DefendAI platform tenant token
  --wawsdb-url TEXT          DefendAI platform base URL [default: https://wauzeway.defendai.ai]
  --platform-interval INT    Upload every N correlation cycles in daemon mode [default: 5]
  --max-log-size INT         Rotate output files at this size in MB [default: 50]
  --max-log-backups INT      Rotated backup files to keep [default: 5]

# Individual layers
agent-discover-scanner scan PATH              # Layer 1: source code only
agent-discover-scanner deps PATH              # Dependency scanning
agent-discover-scanner monitor                # Layer 2: network monitor only
agent-discover-scanner monitor-k8s            # Layer 3: Kubernetes runtime only
agent-discover-scanner endpoint               # Layer 4: endpoint scan only
agent-discover-scanner correlate              # Correlate existing scan outputs

# Audit mode (v2.5.0+) — full report: aibom.json, ghost-agents.md, mcp-report.md
agent-discover-scanner audit PATH [OPTIONS]
  --duration/-d SECONDS      Observation window [default: 60]
  --output/-o PATH           Report output directory [default: defendai-audit]
  --layer3-file PATH         Use existing Tetragon JSONL (skip live Layer 3)
  --platform                 Upload to DefendAI platform
  --api-key TEXT             DefendAI platform API key

# Short alias (v2.5.0+) — same as agent-discover-scanner
agent-discover [COMMAND] [OPTIONS]
```

---

## Detected frameworks and providers

**AI frameworks:** LangChain, LangGraph, CrewAI, AutoGen, direct HTTP LLM clients

**LLM providers:** OpenAI, Anthropic, Google Gemini / Google AI, Mistral, Cohere, Azure OpenAI, AWS Bedrock, Groq, DeepSeek

**Vector stores:** Pinecone, Weaviate, Qdrant, Chroma

**SaaS blast radius detection (v2.3.0+):** Salesforce, Slack, GitHub, GitLab, Jira, HubSpot, Notion, Airtable, Stripe, Twilio, Snowflake, Databricks, AWS, GCP, Azure, PostgreSQL, Redis, MongoDB

---

## Try the demo

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner
cd agent-discover-scanner/demo
./setup.sh    # deploys LangChain, CrewAI, and a shadow agent to local Kubernetes
agent-discover-scanner scan-all ./sample-repo --duration 60
```

Expected output: 2 CONFIRMED agents (crewai-agent, langchain-agent), 1 GHOST agent (shadow-agent — runtime activity, no source code).

---

## Requirements

| Capability         | Requirement                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| Code scanning      | Python 3.10+, all dependencies included                                                            |
| Network monitoring | Linux: root/sudo required · macOS: no sudo (use pipx) · Windows: elevated PowerShell              |
| Kubernetes runtime | kubectl + read access (K8s API path) · Helm 3+ + root/sudo for Tetragon/eBPF (Linux only)         |
| Endpoint discovery | osquery (optional — graceful degradation if not installed)                                         |
| Layer 3 (eBPF)     | Linux only — unavailable on macOS and Windows. K8s API path works on all platforms.               |
| Platform upload    | DefendAI API key ([defendai.ai](https://defendai.ai))                                              |

Full Kubernetes setup: `install.sh` handles Helm, runtime monitoring setup, and permissions automatically.

---

## DefendAI platform

AgentDiscover Scanner is the **discovery layer** of the DefendAI platform.

| Component                 | Status         | Description                                                           |
| ------------------------- | -------------- | --------------------------------------------------------------------- |
| **AgentDiscover Scanner** | ✅ Open Source (v2.5.0) | Discover and classify AI agents across your environment  |
| **defendai-agent**        | 🧪 Beta        | MITM proxy for real-time AI traffic inspection and policy enforcement |
| **Correlation Engine**    | ✅ Available    | Cross-machine identity resolution and behavioral drift detection      |
| **Policy Engine**         | 🚧 Coming Soon | Define and enforce agent behavior rules                               |
| **DefendAI Platform**     | 💼 Enterprise  | Full lifecycle governance for autonomous AI                           |

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