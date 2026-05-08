# Using AgentDiscover Scanner with GitHub Actions

Add AI agent discovery to every pull request in 5 minutes.

---

## Quickstart — one step

The scanner ships as a reusable GitHub Action. Add this to any workflow:

```yaml
# .github/workflows/agent-scan.yml
name: AI Agent Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  security-events: write
  contents: read

jobs:
  agent-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Defend-AI-Tech-Inc/agent-discover-scanner@v2.5.0
        with:
          path: '.'
          upload-sarif: 'true'
```

That's it. Findings appear in the **Security > Code scanning** tab of your repository.

---

## What this does

The action runs **Layer 1 (source code analysis)** — AST-based detection of AI frameworks in Python and JavaScript/TypeScript. It outputs SARIF and (optionally) uploads it to the GitHub Security tab.

Layer 1 is the right choice for CI. It's fast (typically under 30 seconds on a normal codebase), requires no elevated privileges, and produces deterministic results.

Layers 2, 3, and 4 require a running environment (network access, a Kubernetes cluster, or osquery) and are better suited for scheduled scans or daemon mode on a deployed machine.

---

## Action inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `output` | `agent-scan-results.sarif` | SARIF output file path |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `python-version` | `3.12` | Python version for the scanner |

## Action outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the generated SARIF file |

---

## Full-stack scan in CI

For a complete multi-layer scan (e.g., on a self-hosted runner with cluster access):

```yaml
- name: Full agent scan
  run: |
    pip install agent-discover-scanner
    agent-discover-scanner scan-all . \
      --duration 30 \
      --output ./defendai-results \
      --skip-layers 3    # skip K8s layer if no cluster available
```

> Layer 3 (eBPF/Tetragon) is Linux-only. Layer 2 requires elevated privileges on Linux.

---

## Failing the build on new agent frameworks

Use the SARIF output to fail the build if unexpected AI frameworks are introduced:

```yaml
- name: Check for new AI agents
  run: |
    FINDINGS=$(jq '.runs[0].results | length' agent-scan-results.sarif)
    if [ "$FINDINGS" -gt 0 ]; then
      echo "::warning::$FINDINGS AI agent pattern(s) detected — review in Security tab"
    fi
```

Customize this to fail (`exit 1`) or warn based on your governance policy.

---

## Uploading the SARIF artifact

To keep the SARIF file as a workflow artifact regardless of scan outcome:

```yaml
- uses: Defend-AI-Tech-Inc/agent-discover-scanner@v2.5.0
  with:
    path: '.'

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: agent-scan-sarif
    path: agent-scan-results.sarif
    retention-days: 30
```

---

## Scheduled full-environment scan

Run a daily scan that includes Layer 4 endpoint discovery (requires osquery on the runner):

```yaml
name: Daily AI Agent Inventory

on:
  schedule:
    - cron: '0 3 * * *'

jobs:
  full-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install osquery
        run: |
          curl -L https://pkg.osquery.io/deb/osquery_5.10.2-1.linux_amd64.deb -o osquery.deb
          sudo dpkg -i osquery.deb

      - name: Run full scan
        run: |
          pip install agent-discover-scanner
          agent-discover-scanner scan-all . \
            --duration 30 \
            --skip-layers 3 \
            --output ./defendai-results

      - uses: actions/upload-artifact@v4
        with:
          name: agent-inventory
          path: defendai-results/
          retention-days: 90
```

---

## Viewing results

After the workflow runs, go to **Security > Code scanning alerts** in your repository. Each finding links to the exact file and line where an AI agent pattern was detected, with a description of why it was flagged.

For a more detailed view, download the SARIF artifact and open it in any SARIF viewer, or import it into your SIEM.
