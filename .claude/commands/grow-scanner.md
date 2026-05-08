# Grow AgentDiscover Scanner Traction

Autonomous task: increase real-world adoption of the AgentDiscover scanner.

Rules:
- NEVER fake metrics (no artificial stars, downloads, or issues)
- NEVER create fake user testimonials or reviews
- ONLY improve the product, documentation, and discoverability
- Every change must make the scanner genuinely more useful

Execute the following improvement categories in order:

## 1. First-Run Experience (highest impact)
- Audit the README.md: Can a security engineer go from zero to first scan in under 3 minutes?
- Ensure `pipx install agentdiscover && agent-discover-scanner scan-all ~/projects --duration 30` works flawlessly
- Add a "What You'll See" section with REAL example output (not mocked)
- Add a "Common Issues" section addressing known friction points
- Test the install path on a clean Python 3.10+ environment

## 2. Output Quality
- Ensure scan output is immediately actionable (not just raw data)
- Add a `--summary` flag that prints a human-readable executive summary
- Add a `--report` flag that generates a markdown report suitable for sharing with management
- Ensure AIBOM/CycloneDX output is valid and parseable by standard tools
- Add `--json` output that's clean enough to pipe into jq

## 3. CI/CD Integration
- Create a GitHub Action: `defendai/agentdiscover-action`
- Usage: add to any repo's CI to scan for AI agents on every PR
- Output: SARIF format for GitHub Security tab integration
- Create the action.yml, Dockerfile, and documentation
- Write a blog-post-ready tutorial: "Add AI Agent Discovery to Your CI Pipeline in 5 Minutes"

## 4. Comparison Content
- Create docs/comparisons/ directory
- Write honest comparisons: AgentDiscover vs Cisco DefenseClaw Skills Scanner
- Write: AgentDiscover vs manual `grep` for AI frameworks
- Write: AgentDiscover vs Nudge Security agent discovery
- Be honest about limitations — credibility > marketing

## 5. Integration Guides
- Create docs/integrations/ directory
- Write: "Using AgentDiscover with Splunk" (forward JSONL audit to Splunk HEC)
- Write: "Using AgentDiscover with Elastic/Kibana" (filebeat config for scan output)
- Write: "Using AgentDiscover in a Kubernetes cluster" (DaemonSet + Tetragon setup)
- Write: "Using AgentDiscover with GitHub Actions" (reference the action from #3)

## 6. SEO and Discoverability
- Ensure PyPI metadata is complete: description, keywords, project URLs, classifiers
- Add "AI agent security scanner" and "MCP security" to keywords
- Ensure GitHub topics include: ai-security, mcp, agent-discovery, llm-security, sbom
- Create a one-line description that's search-friendly: "Find every AI agent in your enterprise — the ones you know about and the ones you don't"

## 7. Developer Experience
- Ensure all CLI help text is clear and complete (`--help` on every subcommand)
- Add shell completion scripts (bash, zsh, fish)
- Add a `--verbose` mode that explains what each detection layer is doing in real-time
- Add a `--dry-run` mode for CI environments that just validates configuration
