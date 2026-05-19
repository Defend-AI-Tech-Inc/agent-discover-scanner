# MCP Governance — Design Document

**Status:** Phase 1 complete — mapping confirmed, implementation ready to begin  
**Branch:** `v2.6.0-mcp-governance`  
**Scanner version:** v2.6.0  
**mcpfw version:** v0.1.0  

---

## 1. What This Document Covers

AgentDiscover Scanner discovers MCP servers across all AI clients on a machine.
mcpfw is a policy-enforcing firewall proxy that sits between an MCP client and
server. This document defines how scanner findings map to mcpfw policy rules,
what the three policy stances produce, and edge cases that require human review.

The output of this work is:
- `src/agent_discover_scanner/exporters/mcpfw_policy.py` — `export_mcpfw_policy()` function
- `agent-discover-scanner export-mcpfw-policy` CLI subcommand
- `--emit-mcpfw-policy` flag on `scan-all`
- `demo/mcp-governance/sample-policy.yaml` — policy generated from scanning this repo
- `tests/test_mcpfw_export.py`

---

## 2. Scanner MCP Output Schema

`mcp_detector.detect_mcp_servers()` returns a single dict. The fields that
drive policy generation are:

```
mcp_result = {
    "servers": [
        {
            "server_name": str,          # config key — used as policy server: identifier
            "package": str | None,       # npm package, python module, URL, or script path
            "vendor": str,               # "Anthropic", "Microsoft", "GitHub", "Unknown", …
            "publisher_verified": bool,
            "risk": str,                 # "critical" | "high" | "medium" | "low"
            "saas": str | None,          # "salesforce", "stripe", "github", …
            "capability": str | None,    # "filesystem" | "database" | "code_execution"
                                         # | "browser" | "web_search" | "unknown"
            "is_local_script": bool,
            "is_remote": bool,
            "client": str,               # "Claude Desktop", "Cursor", "VS Code Copilot", …
            "source": str | None,        # "package.json" | "requirements.txt" | "process"
            "note": str | None,
        }
    ],
    "has_unverified_servers": bool,
    "has_local_scripts": bool,
    "has_remote_servers": bool,
    "has_filesystem_access": bool,
    "has_database_access": bool,
    "has_code_execution": bool,
    "has_browser_access": bool,
    "highest_risk": str | None,
    "network_detected": bool,            # True if server found via network traffic only
    "clients_with_mcp": [str],
    "saas_via_mcp": [str],
}
```

`server_name` is the key from the MCP config file (e.g. `"filesystem"`,
`"github"`, `"my-custom-server"`). It maps directly to `server:` in mcpfw
policy — this is the stable identifier.

---

## 3. mcpfw Policy Schema

A mcpfw policy YAML has this structure (all fields relevant to the exporter):

```yaml
version: 1
default_action: allow | block | log

# Global: applied to responses from ALL servers
response_rules:
  - name: <str>
    detect_patterns: [<regex>, ...]
    action: block | log
    severity: critical | warning | info
    reason: <str>

servers:
  - server: <server_name>             # matches server_name from scanner
    default_action: allow | block | log
    allowed_tools: [<tool>, ...]      # if set, all other tools blocked
    blocked_tools: [<tool>, ...]      # explicit block list (belt-and-suspenders)
    tool_rules:
      - name: <str>
        tools: [<glob>, ...]          # shell-style globs supported
        action: allow | block | log
        allow_paths: [<path>, ...]    # canonical path restriction
        block_patterns: [<regex>, ...]  # match against all argument values
        block_values: [<str>, ...]    # exact substring matches in arguments
        rate_limit:                   # advisory in v0.1.0; enforced in v0.2.0
          max_calls: <int>
          window_seconds: <int>
        severity: critical | warning | info
        reason: <str>
    response_rules:
      - ...                           # server-scoped DLP rules
```

---

## 4. Scanner Finding → mcpfw Policy Rule Mapping

### 4.1 Server-level mapping

| Scanner field | Value | mcpfw rule produced |
|---|---|---|
| `risk` | `"critical"` | `default_action: block` for that server |
| `risk` | `"high"` + `publisher_verified: false` | `allowed_tools` allowlist (strict/balanced) |
| `risk` | `"high"` + `publisher_verified: true` | `allowed_tools` allowlist (strict only) |
| `risk` | `"medium"` or `"low"` | `default_action: allow` with DLP rules |
| `publisher_verified` | `false` | `verify_server_tools: true` (global); server gets allowlist |
| `is_local_script` | `true` | `blocked_tools: [execute_command, run_script, shell]`; `allow_paths` on read/write tools |
| `source` | `"process"` | `default_action: block` — no config file means unknown tool list |
| `network_detected` | `true` (no config source) | wildcard `server: "*"` entry with DLP rules |

### 4.2 Capability → tool rules mapping

| `capability` | mcpfw rules generated |
|---|---|
| `"filesystem"` | `allow_paths` restricting reads/writes to scanned project dir + `/tmp` |
| `"database"` | response DLP (credential patterns) + rate limit (3 calls/60s) |
| `"code_execution"` | `blocked_tools: [execute_command, run_code, eval, shell]` |
| `"browser"` | `block_patterns` on URL arguments (raw IPs, known C2 patterns) |
| `"web_search"` | `block_patterns` on query arguments (credential-like base64, AWS key format) |
| `"unknown"` | `default_action: allow` with global DLP backstop |

### 4.3 SaaS → response DLP mapping

| `saas` | Response DLP patterns added |
|---|---|
| `"stripe"` | `sk_live_[0-9a-zA-Z]{24,}` — Stripe live secret key |
| `"github"` | `ghp_[A-Za-z0-9]{36}`, `github_pat_` — GitHub PAT |
| `"salesforce"` | `(?i)(client_secret\|consumer_secret)\s*=\s*\S{8,}` |
| `"google_drive"` | `(?i)(refresh_token\|access_token)\s*[:=]\s*\S{8,}` |
| `"servicenow"` | `(?i)(sn_token\|service_now_key)\s*[:=]\s*\S{8,}` |
| any | Base DLP set: AWS creds, OpenAI key, private key, prompt injection |

### 4.4 Attack class coverage

This table shows which mcpfw rules defend against each known attack scenario:

| Attack | Scenario ID | Scanner signals | mcpfw rules |
|---|---|---|---|
| Shadow Server | SS-01 | `is_local_script`, `capability: code_execution` | `blocked_tools`, `allow_paths`, response DLP |
| Rug Pull | RP-01 | `publisher_verified: false`, `is_remote` | `allowed_tools` allowlist, `verify_server_tools` |
| Shadow Exfil | SE-01 | `capability: browser/web_search`, `is_remote` | `block_patterns` on args, response DLP with credential patterns |
| Meter Is Running | MR-01 | any server, `source: process` | response DLP (retry/pagination injection), `rate_limit` |
| Overprivileged Agent | OP-01 | `capability: filesystem/database/code_execution` | `allowed_tools` allowlist, `allow_paths` |

---

## 5. Policy Stances

Three stances are supported. The stance is a parameter to `export_mcpfw_policy()`.

### 5.1 `strict` — deny-by-default

```yaml
default_action: block          # global deny unless explicitly permitted
verify_server_tools: true
```

Per server:
- `default_action: block`
- `allowed_tools` set to a **minimal** list derived from the server's known capability
  (e.g. a `web_search` server gets only `[search, query]`)
- All path rules use `allow_paths` restricted to the current scan directory
- Rate limits: 10 calls/60s for database/code_execution, 30 calls/60s otherwise
- Full DLP: credential patterns + prompt injection (action: block)

Use when: security team requires full auditability and approval of every tool
invocation. Appropriate for GHOST-classified agents or servers with
`risk: critical`.

### 5.2 `balanced` — allow with logging and DLP (default)

```yaml
default_action: allow
verify_server_tools: false
```

Per server:
- Verified publishers (`publisher_verified: true`, `risk: medium/low`): `default_action: allow` with DLP
- Unverified publishers (`publisher_verified: false`): `allowed_tools` allowlist added
- High-risk servers (`risk: high`): `allowed_tools` allowlist added
- Critical servers (`risk: critical`): `default_action: block`
- Rate limits: 60 calls/min advisory for database/code_execution servers
- DLP: credential patterns + prompt injection (action: block); no regex on search queries

Use when: teams want defence-in-depth without disrupting existing workflows.
Appropriate for most deployments during initial rollout.

### 5.3 `monitor` — log only, no blocks

```yaml
default_action: allow
verify_server_tools: false
```

Per server:
- `default_action: allow` for all servers including SHADOW-classified
- `allowed_tools` NOT set (never restricts tools)
- All DLP rules use `action: log` instead of `action: block`
- No rate limits
- No `allow_paths` restrictions

Use when: teams want observability before enforcement. Appropriate for the
first 30 days of a new deployment or when mapping existing tool usage patterns.

---

## 6. SHADOW Server Handling

A SHADOW server (in mcpfw terminology) is an unregistered server detected by
the scanner with no governance record. In scanner terms, these are servers with:
- `publisher_verified: false` AND `risk: high` or `risk: critical`
- OR `source: "process"` (detected from running process, no config file)
- OR `is_local_script: true` with `capability: "unknown"`

| Stance | SHADOW server treatment |
|---|---|
| `strict` | `default_action: block` |
| `balanced` | `allowed_tools` allowlist (narrow); no `default_action: block` |
| `monitor` | `default_action: allow` with all rules as `action: log` |

---

## 7. Global DLP Rules (All Stances)

These response_rules are always included regardless of stance. In `monitor`
stance, their action is forced to `log` instead of `block`.

```yaml
response_rules:
  - name: detect-openai-key
    detect_patterns: ['sk-[a-zA-Z0-9\-_]{20,}', 'sk-proj-[A-Za-z0-9_\-]{20,}']
    action: block   # log in monitor stance
    severity: critical
    reason: "OpenAI / LLM API key detected in MCP response"

  - name: detect-anthropic-key
    detect_patterns: ['sk-ant-[a-zA-Z0-9\-_]{20,}']
    action: block
    severity: critical
    reason: "Anthropic API key detected in MCP response"

  - name: detect-aws-credentials
    detect_patterns: ['AKIA[0-9A-Z]{16}', 'AWS_SECRET_ACCESS_KEY\s*=']
    action: block
    severity: critical
    reason: "AWS credentials detected in MCP response"

  - name: detect-private-key
    detect_patterns: ['-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----']
    action: block
    severity: critical
    reason: "Private key material in MCP response"

  - name: detect-prompt-injection
    detect_patterns:
      - '(?i)(SYSTEM\s*:|ignore (all )?previous instructions|you are now|DO NOT (inform|display|tell))'
      - '(?i)(MUST call|mandatory.*step|call .{3,40} again)'
    action: block   # log in monitor stance
    severity: critical
    reason: "Prompt-injection attempt detected in MCP response"

  - name: detect-retry-injection
    detect_patterns:
      - '(?i)(please call .{3,40} again|retry with|re-?call)'
      - '(?i)for (higher|better|improved) (accuracy|results|confidence)'
    action: log
    severity: warning
    reason: "Response instructs AI to re-invoke a tool — possible billing amplification"
```

---

## 8. Edge Cases Requiring Human Review

### 8.1 `source: "process"` — no config file

A server detected only from a running process has no config file. The scanner
cannot know its `server_name` from a client config — it derives a name from
the process command line (e.g. `"my-server"` from `my_server.py`). This name
may not match what the actual MCP client has registered.

**Impact on exporter:** The generated policy uses the derived name. If the
client config uses a different key, the policy will not match. Flag these
entries in the output YAML with a comment:

```yaml
# WARNING: server name derived from process cmdline — verify against client config
- server: "my-server"
```

### 8.2 `network_detected: true` only (no config source)

A server detected only via network traffic (e.g. ChatGPT Web connecting to
Stripe's MCP endpoint) has no `server_name` from a config file. The scanner
uses `server_name: "network:<endpoint>"` for these.

**Impact on exporter:** Generate a wildcard `server: "*"` entry with DLP rules
only — no tool restrictions, since we do not know the tool list.

### 8.3 `@modelcontextprotocol/server-everything` (risk: critical)

This package grants unrestricted filesystem, shell, and network access. The
exporter must set `default_action: block` for this server in ALL stances,
including `monitor`. This is the one case where `monitor` stance still enforces.

### 8.4 Rate limiting is advisory in mcpfw v0.1.0

The `rate_limit` field is parsed by mcpfw but not enforced. The exporter
should emit rate_limit fields with a YAML comment noting the v0.2.0
enforcement dependency. Tests must not assert on enforcement behavior.

### 8.5 Servers with both `saas` and `capability: filesystem`

Example: `@modelcontextprotocol/server-gdrive` (Google Drive — filesystem +
SaaS). These require both `allow_paths` rules AND SaaS-specific DLP. The
exporter must generate both and not let one override the other.

### 8.6 Empty MCP result

If `mcp_result["servers"]` is empty, `export_mcpfw_policy()` should return a
minimal stub with only global DLP rules. This is valid — it gives teams a
starting policy they can extend manually.

### 8.7 Multiple clients with the same server name

Two clients may configure the same logical server (e.g. both Cursor and Claude
Desktop have `"filesystem"` pointing at the same package). The scanner
deduplicates by `server_name`. The exporter should do the same — one policy
entry per unique `server_name`, using the highest risk level across all
client entries for that name.

---

## 9. Implementation Contract

`export_mcpfw_policy(scan_result: dict, stance: str = "balanced") -> dict`

- `scan_result` is the full return value of `execute_scan_all()` — the exporter
  reads `scan_result["mcp"]` (the `mcp_result` dict from `detect_mcp_servers()`).
- Returns a Python dict that serializes directly to valid mcpfw YAML via
  `ruamel.yaml` (preserves comments).
- Never raises — returns a minimal valid policy dict on any error.
- Supported stances: `"strict"`, `"balanced"`, `"monitor"`. Unknown stances
  default to `"balanced"` with a logged warning.

The returned dict structure matches the mcpfw YAML schema exactly (§3 above),
so it can be passed directly to `ruamel.yaml.dump()` without transformation.

---

## 10. File Plan

```
src/agent_discover_scanner/exporters/__init__.py         (new — empty)
src/agent_discover_scanner/exporters/mcpfw_policy.py     (new — Phase 2)
tests/test_mcpfw_export.py                               (new — Phase 4)
demo/mcp-governance/DESIGN.md                            (this file — Phase 1)
demo/mcp-governance/sample-policy.yaml                   (new — Phase 5)
demo/mcp-governance/README.md                            (new — Phase 5)
```

CLI additions (Phase 3):
- `agent-discover-scanner export-mcpfw-policy` subcommand
- `--emit-mcpfw-policy PATH` flag on `scan-all`
