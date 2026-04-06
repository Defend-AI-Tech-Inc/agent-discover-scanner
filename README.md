# AgentDiscover Scanner



**Open-Source AI Agent Discovery for the Enterprise**

[License: MIT](https://opensource.org/licenses/MIT)
[Python 3.10+](https://www.python.org/downloads/)
[PyPI](https://pypi.org/project/agent-discover-scanner/)
[PRs Welcome](CONTRIBUTING.md)

*Part of the [DefendAI](https://defendai.ai) platform for autonomous AI governance*



---

## The Finding That Matters

```
👻 GHOST AGENT DETECTED
   Workload:   trading-bot (Deployment/default)
   Connected:  api.openai.com — LIVE
   SaaS:       openai — confirmed active connection
   Source code: None found in scanned repositories
   Owner:      Unknown — no deployment record, no code review

👻 GHOST AGENT DETECTED
   Workload:   shadow-agent (Pod/kube-system)
   Connected:  api.anthropic.com — LIVE
   SaaS:       anthropic — confirmed  |  gcp — active socket
   Blast radius: HIGH (cloud provider access confirmed)
   Source code: None found in scanned repositories
   Owner:      Unknown — no deployment record, no code review
```

An AI system is making real API calls — consuming tokens, potentially accessing sensitive data — and your engineering team has no record of it. No code, no deployment, no owner. AgentDiscover Scanner finds these in under 60 seconds.

**That's the problem.** Your engineering team thinks they know what AI systems are running. They don't.

---

## What Makes This Different

Most security tools tell you what's in your code. AgentDiscover Scanner tells you what's **actually running** — and crucially, what's running that has **no business being there**.

The GHOST classification is unique: an AI system observed making real API calls with zero corresponding source code. No other static analysis tool can find this. No SIEM will alert on it. It only appears when you watch the runtime and cross-reference it against your codebase simultaneously.

As of v2.3.0, every detected agent also carries a **SaaS blast radius** — a live-observed map of which services it's actively connected to, derived from network traffic not just configuration files.

```
crewai-agent (CONFIRMED)
  saas_connections:
    anthropic: confirmed  ← active_connection observed
    github:    medium     ← open socket
  risk_flags: [cloud_credentials_present]
  blast_radius: 70/100
```

---

## Agent Classifications


| Classification    | What It Means                              | Risk         |
| ----------------- | ------------------------------------------ | ------------ |
| 👻 **GHOST**      | Runtime AI activity — no source code found | **Critical** |
| ✅ **CONFIRMED**   | Detected in code AND observed running      | High         |
| ⚠️ **UNKNOWN**    | Found in code, not yet observed at runtime | Medium       |
| 🖥️ **SHADOW AI** | Known app using AI without governance      | Medium       |
| ☠️ **ZOMBIE**     | Was active, no longer observed             | Low          |


**GHOST agents are the most dangerous finding.** An AI system is making real API calls — consuming tokens, potentially accessing sensitive data — and your engineering team has no record of it. No code, no deployment, no owner.

---

## Quick Start

```bash
pip install agent-discover-scanner
agent-discover-scanner scan-all /path/to/your/code --duration 30
```

For Kubernetes environments:

```bash
curl -fsSL https://raw.githubusercontent.com/Defend-AI-Tech-Inc/agent-discover-scanner/main/install.sh | sudo bash
agent-discover-scanner scan-all /path/to/code --daemon --output /var/log/defendai
```

To upload results to the DefendAI platform:

```bash
agent-discover-scanner scan-all /path/to/code \
  --platform \
  --api-key YOUR_API_KEY
```

---

## How It Works

AgentDiscover Scanner runs four detection layers simultaneously and correlates them into a single agent inventory. Each layer sees something the others can't.

### Layer 1 — Source Code Analysis

Static analysis of Python and JavaScript/TypeScript. Detects LangChain, LangGraph, CrewAI, AutoGen, direct OpenAI/Anthropic/Gemini API usage, and any HTTP client targeting LLM endpoints. Handles import aliasing and indirect usage patterns. Generates SARIF output for CI/CD integration.

### Layer 2 — Live Network Monitoring

Passive observation of outbound connections to AI providers — OpenAI, Anthropic, Google Gemini, Mistral, Cohere, Azure OpenAI, AWS Bedrock, and vector stores. No packet capture. Identifies which process is making each connection, enabling per-agent SaaS attribution.

### Layer 3 — Kubernetes Runtime (eBPF)

Kernel-level visibility into pod behavior via Tetragon. Identifies which workloads are actively making AI calls — including workloads with no corresponding source code. Works with any CNI. Falls back to Kubernetes API discovery if Tetragon is unavailable.

### Layer 4 — Endpoint Discovery

Scans developer machines, CI/CD runners, and workstations via osquery. Finds installed AI packages, desktop AI applications (ChatGPT Desktop, Claude Desktop, Cursor, GitHub Copilot), active connections, browser-based AI usage, and VSCode extensions.

### SaaS Blast Radius Detection (v2.3.0+)

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

`confirmed` means the connection was **live-observed** during the scan — not inferred from config files. This is the difference between "this agent is configured to use Anthropic" and "this agent is calling Anthropic right now."

---

## High-Risk Agent Detection (v2.4.0+)

The scanner detects autonomous agent platforms that carry
systemic security risk by design — not misconfigurations,
but architecture.

**OpenClaw** (formerly Clawdbot/Moltbot) is the primary target.
It has full filesystem access, terminal execution, email and
messaging integration, and runs as a persistent background daemon.
CVE-2026-25253 CVSS 8.8. Gartner: "insecure by default."
Microsoft: "treat as untrusted code execution."

Detection uses corroborated signals — never a single port number:

```
🚨 HIGH-RISK AGENT CONFIRMED: OpenClaw
   Autonomous agent with system-level access — filesystem,
   terminal, email, and messaging integration.
   Capabilities: filesystem, terminal, email, browser, messaging
```

## MCP Server Detection (v2.4.0+)

MCP (Model Context Protocol) is the integration layer between
AI agents and enterprise SaaS. Supported by Claude, ChatGPT,
Gemini, Copilot, Cursor, and VS Code.

The scanner detects MCP across supported AI clients and classifies each server using publisher verification where metadata exists:

```
⚠ Unverified MCP server: servicenow
  (echelon-ai-labs — not published by ServiceNow)

✓ Verified: @salesforce/mcp-server (Salesforce official)
```

**Non-developer detection:** Financial analysts connecting
ChatGPT Teams to Salesforce via UI leave no local config file.
The scanner detects this via Layer 2 network traffic — the only
tool that catches this pattern.

**Severity in practice:** The CLI surfaces unverified publishers, local MCP scripts, and related risk flags from correlation. Treat the list above as **guidance for triage**, not a separate policy engine baked into the open-source CLI.

## Example Output

```
🔍 Scanning for autonomous AI agents...
📂 Analyzing source code at ./my-repo
🌐 Monitoring live network connections...
☸️  Monitoring Kubernetes workloads...
💻 Scanning endpoints...
🔗 Correlating findings...
✓ Correlation complete

🤖 Autonomous Agent Inventory

 Classification  | Count | Description
-----------------|-------|--------------------------------------------------
 CONFIRMED       |   2   | Active — detected in code and observed at runtime
 UNKNOWN         |   3   | Code found — not yet observed at runtime
 SHADOW AI       |   0   | Known app using AI — review for governance
 ZOMBIE          |   0   | Inactive — code exists but no recent activity
 GHOST           |   1   | ⚠ Critical — runtime activity with no source code

Risk Breakdown:
  ● Critical: 1
  ● High:     2
  ● Medium:   3
  ● Low:      0

✅ Scan complete — results saved to ./defendai-results
```

---

## Daemon Mode

Run continuously as a background service, updating the agent inventory every 30 seconds:

```bash
agent-discover-scanner scan-all /path/to/code \
  --daemon \
  --output /var/log/defendai \
  --platform \
  --platform-interval 5    # upload to platform every ~2.5 minutes
```

With `--platform`, the daemon syncs to the DefendAI platform every N correlation 
cycles (default: every 5 cycles ≈ 2.5 minutes) and always uploads a final snapshot 
on shutdown.

Install as a systemd service:

```bash
sudo bash deployment/systemd/install-service.sh /path/to/code
systemctl status defendai-scanner

```

---

## Customizing Known Applications

By default the scanner classifies common desktop applications
(browsers, Office 365, Cursor, Slack, Claude Desktop, etc.) as
**Shadow AI** rather than GHOST when they make AI API calls.
To add your own internal tools:

```bash
mkdir -p ~/.defendai
echo "my-internal-ai-tool" >> ~/.defendai/known_apps.txt
echo "company-llm-client" >> ~/.defendai/known_apps.txt
```

See `docs/known-apps-example.txt` for the full format.

When connected to the DefendAI platform (`--platform` flag),
the tenant-managed list is downloaded automatically on startup
and merged with your local overrides.

---

## DefendAI Platform Integration

The scanner is the **discovery layer**. The platform is where discovered agents become governed agents.

```bash
agent-discover-scanner scan-all /path/to/code \
  --platform \
  --api-key YOUR_KEY \
  --duration 30
```

When connected to the platform, each scan triggers the **correlation engine** which builds a living identity map across every machine, every environment, and every scan:

- **Agent Identity Resolution** — the same CrewAI agent on a laptop, in staging k8s, and in prod k8s is recognized as one agent at different lifecycle stages
- **Behavioral Drift Detection** — agent added `has_code_execution=true` since last week? That's a signal. Platform tracks it.
- **Cross-Machine Intelligence** — an agent seen on 3 machines and crossed from dev into prod? Automatic risk escalation
- **SaaS Blast Radius** — platform aggregates confirmed SaaS connections across all scans and computes blast radius score

After a few scans, the DefendAI platform report shows:

```
Agent Inventory Report — acme-corp
─────────────────────────────
 shadow-agent    GHOST     CRITICAL   anthropic, github   blast: 85   machines: 3
                           ↑ GHOST seen in production — action required

 crewai-agent    SHADOW    MEDIUM     openai              blast: 25   machines: 1
                           ↑ Unreviewed — no governance record

 langchain-agent KNOWN     LOW        openai              blast: 15   machines: 1
                           ↑ Approved — monitoring active
─────────────────────────────────────────────────────────────────────
 3 agents total · 1 critical · 1 unreviewed · 1 governed
```

---

## CI/CD Integration

```yaml
# .github/workflows/agent-scan.yml
- name: Scan for AI Agents
  run: |
    pip install agent-discover-scanner
    agent-discover-scanner scan . --format sarif --output results.sarif
```

---

## Commands

```bash
# Same CLI entry points (either name)
agent-discover-scanner …
agent-discover …

# Full scan (recommended) — all 4 layers + correlation
agent-discover-scanner scan-all PATH [OPTIONS]
  --duration/-d SECONDS      Network and K8s monitor observation window [default: 60]
  --output/-o PATH           Output directory for scan results [default: defendai-results]
  --format/-f TEXT           Final console summary: text (default) or json (print inventory JSON).
                             Layer 1 still writes layer1_code.sarif under the output directory.
  --layer TEXT               Single facet: code | network | k8s | endpoint | mcp (not with --daemon)
  --layer3-file PATH         Use existing Tetragon JSONL output (skip live Layer 3)
  --skip-layers TEXT         Comma-separated layers to skip, e.g. '3' or '2,3'
  --daemon                   Run continuously, re-scanning every 30 seconds
  --platform                 Upload results to DefendAI platform after scan
  --api-key TEXT             DefendAI platform API key
  --tenant-token TEXT        DefendAI platform tenant token
  --wawsdb-url TEXT          DefendAI platform base URL [default: https://wauzeway.defendai.ai]
  --platform-interval INT    Upload every N correlation cycles in daemon mode [default: 5]
  --max-log-size INT         Rotate output files at this size in MB [default: 50]
  --max-log-backups INT      Rotated backup files to keep [default: 5]

# Audit bundle: full scan-all into OUTPUT/raw/, plus aibom.json and Markdown reports
agent-discover-scanner audit PATH --output OUTPUT

# Layer 1 code scan (SARIF/table/both); --format text is an alias for table
agent-discover-scanner scan PATH --format sarif --output results.sarif

# Individual layers / utilities
agent-discover-scanner scan PATH              # Layer 1: source code only
agent-discover-scanner deps PATH              # Dependency scanning
agent-discover-scanner monitor                # Layer 2: network monitor only
agent-discover-scanner monitor-k8s            # Layer 3: Kubernetes runtime only
agent-discover-scanner endpoint               # Layer 4: endpoint scan only
agent-discover-scanner correlate              # Correlate existing scan outputs
```

---

## Detected Frameworks & Providers

**AI Frameworks:** LangChain, LangGraph, CrewAI, AutoGen, direct HTTP LLM clients

**LLM Providers:** OpenAI, Anthropic, Google Gemini / Google AI, Mistral, Cohere, Azure OpenAI, AWS Bedrock, Groq, DeepSeek

**Vector Stores:** Pinecone, Weaviate, Qdrant, Chroma

**SaaS Blast Radius Detection (v2.3.0+):** Salesforce, Slack, GitHub, GitLab, Jira, HubSpot, Notion, Airtable, Stripe, Twilio, Snowflake, Databricks, AWS, GCP, Azure, PostgreSQL, Redis, MongoDB

---

## Try the Demo

```bash
git clone https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner
cd agent-discover-scanner/demo
./setup.sh    # deploys LangChain, CrewAI, and a shadow agent to local Kubernetes
agent-discover-scanner scan-all ./sample-repo --duration 60
```

Expected output: 2 CONFIRMED agents (crewai-agent, langchain-agent), 1 GHOST agent (shadow-agent — runtime activity, no source code).

---

## Requirements


| Capability         | Requirement                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| Code scanning      | Python 3.10+; install via PyPI (package pulls declared runtime dependencies) |
| Network monitoring | Python 3.10+; root/sudo often required for connection visibility          |
| Kubernetes runtime | `kubectl` for API fallback; **Helm 3+** typical when installing Tetragon via `install.sh` |
| Endpoint discovery | Python 3.10+; osquery optional (graceful degradation without it)           |
| Platform upload    | DefendAI API key — [defendai.ai](https://defendai.ai)                       |


Full Kubernetes setup: `install.sh` handles Helm, runtime monitoring setup, and permissions automatically.

---

## DefendAI Platform

AgentDiscover Scanner is the **discovery layer** of the DefendAI platform.


| Component                 | Status         | Description                                                           |
| ------------------------- | -------------- | --------------------------------------------------------------------- |
| **AgentDiscover Scanner** | ✅ Open Source  | Discover and classify AI agents across your environment               |
| **defendai-agent**        | 🧪 Beta        | MITM proxy for real-time AI traffic inspection and policy enforcement |
| **Correlation Engine**    | ✅ Available    | Cross-machine identity resolution and behavioral drift detection      |
| **Policy Engine**         | 🚧 Coming Soon | Define and enforce agent behavior rules                               |
| **DefendAI Platform**     | 💼 Enterprise  | Full lifecycle governance for autonomous AI                           |


[defendai.ai](https://defendai.ai) · [playground.defendai.ai](https://playground.defendai.ai) · [support@defendai.ai](mailto:support@defendai.ai)

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