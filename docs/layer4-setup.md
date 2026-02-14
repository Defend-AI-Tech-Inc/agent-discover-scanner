# Layer 4 Setup Guide: Endpoint Discovery

Layer 4 discovers Shadow AI on developer laptops and analyst workstations using [osquery](https://osquery.io).

---

## Quick Start (5 Minutes)

### 1. Install osquery

**Automated:**
```bash
./scripts/install-layer4-osquery.sh
```

**Manual:**

**macOS:**
```bash
brew install osquery
```

**Windows:**
```powershell
choco install osquery
```

**Linux (Ubuntu/Debian):**
```bash
curl -L https://pkg.osquery.io/deb/osquery_5.11.0-1.linux_amd64.deb -o osquery.deb
sudo dpkg -i osquery.deb
```

### 2. Verify Installation
```bash
osqueryi --version
# Should show: osquery 5.11.0 or higher
```

### 3. Run Test Scan
```bash
python -m scanner.cli layer4
```

**Expected output:**
```
[Layer 4] Scanning endpoint for Shadow AI...
[Layer 4] Platform detected: darwin
[Layer 4] Running 6 osquery queries...

Found:
  - 2 desktop applications
  - 5 AI packages
  - 1 active AI connection
  
Risk Score: 35/100

Report saved to: layer4_report.md
```

---

## What Layer 4 Finds

### Desktop AI Applications
- ChatGPT Desktop (OpenAI)
- Claude Desktop (Anthropic)
- Cursor (AI code editor)
- GitHub Copilot
- Tabnine
- JetBrains AI Assistant

### AI Packages
**Python (pip):**
- openai, anthropic, langchain, llama-index
- autogen, crewai, semantic-kernel

**JavaScript (npm):**
- openai, @anthropic-ai/sdk, langchain

### Active AI Connections
Real-time network connections to:
- api.openai.com
- api.anthropic.com
- api.cohere.ai
- api.together.xyz

### Browser AI Usage
Recent visits to:
- chatgpt.com
- claude.ai
- bard.google.com / gemini.google.com
- copilot.microsoft.com
- perplexity.ai

---

## Deployment Scenarios

### Scenario 1: Single Machine (Demo/Testing)

**Use case:** Scan your own laptop to see what AI tools you have

**Setup:**
```bash
./scripts/install-layer4-osquery.sh
```

**Scan:**
```bash
python -m scanner.cli layer4
```

**Time:** 5 minutes setup, 1 minute scan

---

### Scenario 2: Small Team (10-50 Machines)

**Use case:** Security assessment for small company

**Setup:**
1. Install osquery on each machine manually
2. Run scanner on each machine
3. Aggregate results

**On each machine:**
```bash
# Install osquery
./scripts/install-layer4-osquery.sh

# Run scan, save results
python -m scanner.cli layer4 --output machine_$(hostname).json
```

**Aggregate on your machine:**
```bash
python -m scanner.cli aggregate machine_*.json
```

**Time:** 2 hours setup (for 20 machines), 30 minutes scanning

---

### Scenario 3: Enterprise (500+ Machines)

**Use case:** Continuous Shadow AI monitoring across organization

**Setup:**
1. Deploy osquery fleet manager (Fleet or Kolide)
2. Enroll all endpoints
3. Configure AgentDiscover to query fleet API

**See:** [enterprise-deployment.md](enterprise-deployment.md)

**Time:** 1-2 weeks setup, automated scanning thereafter

---

## Understanding the Output

### Risk Score

Layer 4 calculates a risk score (0-100) based on:

| Factor | Points | Reason |
|--------|--------|--------|
| Unapproved desktop app | +10 each | High risk - user actively using AI |
| Active AI connection | +5 each | Medium risk - AI in use right now |
| Browser AI usage | +2 each | Lower risk - might be research |
| AI package installed | +3 each | Development usage |

**Risk levels:**
- **0-25:** Low risk (minimal AI usage)
- **26-50:** Medium risk (moderate AI usage)
- **51-75:** High risk (extensive AI usage)
- **76-100:** Critical risk (heavy AI usage, multiple tools)

### Sample Report
```markdown
# Endpoint Scan: alice-macbook-pro

**Scan Time:** 2026-02-11 14:32:18
**Risk Score:** 45/100
**Total AI Instances:** 8

---

## Desktop Applications (2)

- Cursor v0.41.3 (Cursor Inc)
- ChatGPT Desktop v1.2.3 (OpenAI)

## AI Packages (5)

- openai v1.12.0 (pip)
- langchain v0.1.7 (pip)
- anthropic v0.18.1 (pip)
- llama-index v0.10.12 (pip)
- openai v4.28.0 (npm)

## Active Connections (1)

- cursor → api.openai.com:443 (ESTABLISHED)

## Browser Activity (3)

- https://chatgpt.com (visited 47 times, last: 2 hours ago)
- https://claude.ai (visited 12 times, last: 1 day ago)
- https://perplexity.ai (visited 5 times, last: 3 days ago)

---

## Recommendations

**Immediate Actions:**
1. Verify Cursor and ChatGPT usage is authorized
2. Review openai package usage in projects
3. Consider deploying DefendAI Gateway for policy enforcement

**Medium-term:**
4. Establish AI usage policy
5. Provide approved AI tools
6. Monitor with continuous Layer 4 scanning
```

---

## Privacy & Compliance

### What Layer 4 Collects

**✅ We collect:**
- Application names and versions
- Package names and versions
- Network connection destinations (not content)
- Browser URLs visited (not page content)

**❌ We do NOT collect:**
- Keystrokes or screen captures
- File contents or prompts
- Personal communications
- Passwords or credentials

### Legal Considerations

**Employee notification:**
- Inform employees osquery is installed
- Explain what data is collected
- Provide opt-out if legally required

**Data retention:**
- Scan results stored locally by default
- You control where results go
- No data sent to DefendAI servers

**Compliance:**
- Layer 4 is designed for security/compliance monitoring
- Consult your legal team for GDPR, CCPA, etc.
- We recommend transparency with employees

---

## Troubleshooting

### osquery not found

**Error:**
```
osqueryi: command not found
```

**Solution:**
```bash
# Verify osquery is installed
which osqueryi

# If not found, install:
./scripts/install-layer4-osquery.sh
```

---

### Permission denied

**Error:**
```
Error: Cannot access /Library/Application Support/...
Permission denied
```

**Solution:**
Some queries require elevated permissions.

**macOS/Linux:**
```bash
sudo python -m scanner.cli layer4
```

**Windows:**
Run PowerShell as Administrator

---

### No results found

**Result:**
```
Found:
  - 0 applications
  - 0 packages
  - 0 connections
```

**Possible causes:**
1. No AI tools actually installed (success!)
2. osquery permissions issue
3. Platform-specific query not working

**Debug:**
```bash
# Test osquery directly
osqueryi "SELECT name FROM apps WHERE name LIKE '%ChatGPT%';"

# Check if you have AI packages
pip list | grep -i openai
npm list | grep -i openai
```

---

## Advanced Usage

### Custom Queries

Add your own detection patterns:

**File:** `scanner/layer4/osquery_queries.py`
```python
# Add to AIDiscoveryQueries class

CUSTOM_APP = """
SELECT name, version, path 
FROM apps 
WHERE name LIKE '%YourCustomAITool%';
"""
```

### Export Results
```bash
# JSON format
python -m scanner.cli layer4 --output results.json

# CSV format
python -m scanner.cli layer4 --output results.csv
```

### Scheduled Scans

**cron (Linux/macOS):**
```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/scanner && python -m scanner.cli layer4 --output /var/log/layer4_$(date +\%Y\%m\%d).json
```

**Task Scheduler (Windows):**
```powershell
# Create scheduled task
schtasks /create /tn "Layer4Scan" /tr "python C:\scanner\scanner\cli.py layer4" /sc daily /st 02:00
```

---

## Next Steps

1. **Scan your laptop** to see baseline AI usage
2. **Review findings** and identify unauthorized tools
3. **Deploy DefendAI Gateway** for policy enforcement
4. **Set up continuous monitoring** (enterprise deployment)

**Questions?** See [FAQ](../README.md#faq) or [open an issue](https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/issues)
