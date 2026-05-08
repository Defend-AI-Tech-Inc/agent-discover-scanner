# AgentDiscover Scanner vs. `grep` for AI Framework Detection

Manual `grep` is the first thing engineers reach for when auditing a codebase for AI usage. It works for the obvious cases and fails for the ones that matter. This document is an honest comparison.

---

## What grep does well

```bash
grep -r "from langchain" ./src
grep -r "import openai" ./src
grep -r "api.openai.com" ./src
```

Fast, zero dependencies, zero configuration. For a small repo with straightforward imports, grep finds the obvious usage in seconds.

## Where grep breaks down

### Import aliasing

```python
import openai as ai_client          # grep for "openai" misses this
from langchain import chains as lc  # grep for "langchain" misses this
```

AgentDiscover Scanner uses Python AST analysis, so it sees through aliases and indirect imports at the call site — not just the import line.

### Indirect instantiation

```python
framework = os.environ.get("AGENT_FRAMEWORK", "langchain")
agent = importlib.import_module(framework).Agent()  # grep: nothing to find
```

AST + runtime correlation catches what static string matching cannot.

### What's actually running

grep tells you what's in your code. It tells you nothing about:

- Whether the code is deployed and actively making API calls right now
- AI agents running in containers with no source code in your repository (GHOST agents)
- Desktop AI applications making API calls from developer machines
- AI usage by non-engineers via browser or SaaS UI (no code at all)

A GHOST agent — a workload actively calling OpenAI with no source code anywhere you can find — is invisible to grep.

### JavaScript and TypeScript

```bash
grep -r "require('openai')" ./src      # misses ESM: import OpenAI from 'openai'
grep -r "from 'openai'" ./src          # misses CJS: require('openai')
grep -r "new OpenAI(" ./src            # misses: const client = openai.createClient()
```

AgentDiscover Scanner uses esprima AST for JavaScript and TypeScript, covering both module systems and usage patterns.

---

## Capability comparison

| Capability | grep | AgentDiscover Scanner |
|---|---|---|
| Direct import detection | ✓ | ✓ |
| Import alias detection | ✗ | ✓ |
| JavaScript/TypeScript | Partial | ✓ (esprima AST) |
| Runtime detection (what's actually running) | ✗ | ✓ (Layer 2 network) |
| GHOST agent detection | ✗ | ✓ |
| Kubernetes workload visibility | ✗ | ✓ (Layer 3) |
| Per-process attribution | ✗ | ✓ |
| SaaS blast radius | ✗ | ✓ |
| MCP server detection | ✗ | ✓ |
| SARIF output for CI/CD | ✗ | ✓ |
| AIBOM (CycloneDX) export | ✗ | ✓ |

---

## When to use each

**Use grep when:** You want a fast sanity check on a small, well-understood codebase. You're a developer and you trust that you know what's deployed.

**Use AgentDiscover Scanner when:** You need an accurate inventory. You're in a security or governance role. You suspect there's AI usage you don't know about. You need evidence — not a guess.

The scanner's Layer 1 (code analysis) strictly improves on grep. It's not slower in any meaningful way for normal repo sizes. There's no reason to use grep when the scanner is installed.
