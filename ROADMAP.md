# AgentDiscover Scanner — Public Roadmap

**File location:** `ROADMAP.md` in repo root

---

## Where we are: v2.4

Current capabilities:
- 4-layer detection pipeline (endpoint → process → K8s runtime → correlation)
- GHOST agent detection (runtime ∉ inventory)
- eBPF via Tetragon (primary K8s path)
- K8s API Monitor (managed cluster fallback — EKS, GKE, AKS)
- MCP server detection across Claude Desktop, Cursor, Windsurf
- Per-agent confidence scoring and attribution
- AIBOM export (CycloneDX 1.6)
- Audit CLI mode

---

## v2.5 — Hardening (current sprint)

- [x] GitHub Action for CI/CD AIBOM generation
- [ ] Improved MCP publisher verification (signed manifests)
- [ ] Agent framework support: PydanticAI, Smolagents, Agno
- [ ] Local model endpoint detection (Ollama, llama.cpp, vLLM) in Layer 1
- [ ] NIST AI 100-2e taxonomy alignment in audit output
- [ ] Performance: sub-10s scans on clusters up to 500 nodes

---

## v3.0 — Runtime Enforcement (Q3 2026)

This is the step from discovery to governance.

**Deterministic blocking (execution gate)**
The ability to set a policy that terminates any unauthorized tool call before it executes. Not alerting after the fact — interrupting at the boundary. This is the "hard gate" for the agentic execution boundary.

**Behavioral baselining**
After establishing an agent inventory, continuously monitor tool call patterns against a learned baseline. Anomalies (new tool scopes, unusual data access patterns, injection-shaped inputs) trigger alerts before they become incidents.

**Toxic Flow detection (runtime)**
Correlate input sources against tool calls in the same session. Flag sessions where untrusted-origin input preceded a high-privilege tool call. This is the runtime complement to the static MCP risk-scoring we ship today.

**Multi-framework agent graph**
Visualize multi-agent systems: which agents call which tools, which agents pass output to other agents, where the trust boundaries are. Necessary for understanding cross-agent contamination risk.

**AIBOM drift alerting**
Continuous comparison of runtime state against the last committed AIBOM. Any agent running outside its declared scope triggers an alert. The GHOST detection becomes continuous, not scan-based.

---

## v4.0 — AgentWatch Platform (commercial, H1 2027)

The commercial platform built on top of the open source scanner.

- Multi-cluster dashboard
- AIBOM history and compliance reporting
- Policy management UI
- SOC integration (SIEM export, webhook alerts)
- White-label assessment mode for MSPs and security consultancies

[AgentWatch private beta is open — apply at defendai.ai/beta]

---

## What shapes the roadmap

The open source roadmap is driven by what we observe in real production environments. If you're seeing something in your cluster that the scanner isn't catching, or a threat pattern that isn't on the roadmap, open an issue. Real-world data is what makes detection better.

---

## LinkedIn announcement post (for Day 29)

Published the v3.0 roadmap for AgentDiscover Scanner today.

The big move in v3.0 is from discovery to enforcement — the ability to terminate an unauthorized agent tool call at the execution boundary before it completes, not alert on it after.

We've been calling this the "deterministic blocking" layer. It's the difference between a security camera and a door lock.

v2.x finds the agents you didn't know were running.
v3.0 controls what they're allowed to do.

Roadmap: github.com/defendai-tech/agent-discover-scanner/blob/main/ROADMAP.md

If you're building agent systems in production and want early access to the enforcement layer — or if you just want to run the current scanner against your cluster — link in comments.
