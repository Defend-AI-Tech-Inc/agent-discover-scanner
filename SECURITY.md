# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in AgentDiscover Scanner, **do not open a public GitHub issue.** Please report it privately so we can investigate and release a fix before public disclosure.

**Email:** mwaseem@defendai.ai

Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept or exploit code is welcome)
- Affected versions
- Any mitigations you have identified

We read and triage all reports promptly. PGP-encrypted submissions are welcome — contact us first to exchange keys.

---

## Response SLA

| Milestone | Target |
|---|---|
| **Acknowledgement** | 48 hours of receipt |
| **Triage + severity assessment** | 5 business days |
| **Patch or mitigation** | 14 days for Critical/High; 30 days for Medium/Low |
| **Public disclosure** | Coordinated with reporter — see below |

---

## Coordinated Disclosure Policy

We follow a **90-day coordinated disclosure** window:

1. Reporter submits vulnerability privately.
2. DefendAI acknowledges within 48 hours and opens a private tracking issue.
3. We work with the reporter to understand and reproduce the issue.
4. A fix is developed and tested.
5. At the reporter's option, a CVE is requested from MITRE (we assist with the request).
6. A patched release is published.
7. A public security advisory is posted on GitHub **90 days** from the original report (or sooner if both parties agree).

If we cannot patch within 90 days, we will notify the reporter, explain the delay, and negotiate an extension. We will not ask for an extension longer than 90 additional days.

---

## Scope

The following are **in scope** for security reports:

- `agent-discover-scanner` Python package (PyPI: `agent-discover-scanner`)
- The `scan-all`, `audit`, `scan`, `monitor`, `monitor-k8s`, `endpoint`, and `correlate` CLI commands
- Detection layers 1–5 and their output files
- Platform upload (`--platform`) credential handling
- Any dependency of the above that ships as part of this package

The following are **out of scope:**

- The DefendAI platform itself (report to security@defendai.ai)
- Vulnerabilities in third-party dependencies that are not exploitable through this package
- Self-XSS or issues requiring physical access to the machine running the scanner
- Rate-limiting or DoS issues against external APIs the scanner queries

---

## Security Research at DefendAI

DefendAI conducts its own ongoing security research into autonomous AI agent platforms, high-risk agent frameworks (including CVE-2026-25253 / OpenClaw), and AI supply-chain risks.

Researchers who have responsibly disclosed vulnerabilities to us are credited in the release notes (unless they prefer to remain anonymous). We do not pay bug bounties at this time, but we do provide:

- Credit in the public security advisory and CHANGELOG
- A letter of acknowledgement for CVE submissions
- Co-authorship opportunity on any resulting public research writeup

---

## Supported Versions

We maintain security fixes for the **current major version** only. We strongly recommend always running the latest release.

| Version | Supported |
|---|---|
| 2.7.x (current) | ✅ Yes |
| 2.6.x | 🔧 Critical fixes only (90 days post-2.7.0) |
| ≤ 2.5.x | ❌ No |
