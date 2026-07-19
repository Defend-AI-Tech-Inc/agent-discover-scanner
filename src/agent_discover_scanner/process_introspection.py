"""
Layer 2 process introspection — resolve the owning process's entry script
and run existing Layer 1 (DAI001–007) rules against it in-process.

Called from NetworkMonitor when a live AI connection is detected so that
the connection finding is enriched with framework information before being
written to layer2_network.json and passed to the correlator.

Public entry point
------------------
    result = introspect_process(pid)
    # result.framework  → e.g. "LangChain/LangGraph"
    # result.rule_ids   → ["DAI003"]
    # result.entry_script → "/app/agent.py"

Design constraints
------------------
- Zero reimplementation of detection logic: delegates 100 % to the
  production ContextAwareVisitor + SIGNATURE_REGISTRY.
- Safe to call on any live PID: never raises; returns a partial result
  on AccessDenied, NoSuchProcess, or parse errors.
- Fast: entry script is scanned first; the wider project scan is capped
  at 50 files and stops at the first framework signal found.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import psutil

_logger = logging.getLogger(__name__)

# ── Layer 2 runtime env model reader — security-critical allow/deny lists ──────
#
# introspect_process() reads the *entire* environ() of a live process via psutil.
# That dict can contain API keys, DB passwords, and other secrets. This is a
# security product — leaking credentials into our own AIBOM/inventory output
# would be a critical, embarrassing defect. To prevent that:
#   1. Only env var *names* matching the allowlist (case-insensitive substring)
#      are even considered.
#   2. Any name that also matches the denylist is dropped, even if it matched
#      the allowlist (denylist always wins).
#   3. Only the matched key name + its value are ever persisted/returned. The
#      raw environ() dict itself must never leave _extract_runtime_env_model.
_RUNTIME_ENV_ALLOWLIST = (
    re.compile(r"MODEL", re.IGNORECASE),
    re.compile(r"DEPLOYMENT", re.IGNORECASE),
    re.compile(r"_ENGINE", re.IGNORECASE),
)
_RUNTIME_ENV_DENYLIST = (
    re.compile(r"KEY", re.IGNORECASE),
    re.compile(r"SECRET", re.IGNORECASE),
    re.compile(r"TOKEN", re.IGNORECASE),
    re.compile(r"PASSWORD", re.IGNORECASE),
    re.compile(r"CREDENTIAL", re.IGNORECASE),
    re.compile(r"AUTH", re.IGNORECASE),
)

# Filesystem markers that indicate a project root
_PROJECT_ROOT_MARKERS = frozenset({
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "Pipfile",
    "poetry.lock",
    "requirements.txt",
})

# Directories to skip during project-wide scan
_SKIP_DIRS = frozenset({
    "__pycache__", ".venv", "venv", ".env", "env",
    "node_modules", ".git", "dist", "build", ".tox",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
})

# Rule-ID → human-readable framework name (mirrors CorrelationEngine.extract_framework_from_rule)
_RULE_TO_FRAMEWORK: dict[str, str] = {
    "DAI001": "AutoGen",
    "DAI002": "CrewAI",
    "DAI003": "LangChain/LangGraph",
    "DAI004": "OpenAI SDK",
    "DAI005": "Direct HTTP LLM Client",
    "DAI006": "LLM API Endpoint",
    "DAI007": "AWS Bedrock",
}

# Priority order for framework selection when multiple signals are found.
# Most-specific / highest-value framework wins.
_RULE_PRIORITY: list[str] = [
    "DAI003",  # LangChain/LangGraph — explicit orchestration framework
    "DAI002",  # CrewAI
    "DAI001",  # AutoGen
    "DAI007",  # AWS Bedrock
    "DAI004",  # Raw OpenAI/Anthropic SDK
    "DAI005",  # Direct HTTP LLM client
    "DAI006",  # LLM API string literal (weakest signal)
]

# Max project files to scan when the entry script alone yields no findings.
_MAX_PROJECT_FILES = 50


@dataclass
class ProcessIntrospectionResult:
    """Result of introspecting a live process for AI framework signals."""

    pid: int
    cmdline: list[str] = field(default_factory=list)
    cwd: str | None = None
    entry_script: str | None = None        # resolved absolute path to the Python script
    project_root: str | None = None        # nearest ancestor with a project root marker
    framework: str | None = None           # e.g. "LangChain/LangGraph", None if not detected
    framework_confidence: str | None = None  # "high" = entry script, "medium" = project scan
    rule_ids: list[str] = field(default_factory=list)  # e.g. ["DAI003"]
    # Layer 2 "runtime_env_model" tier — read live from the process's own
    # environment (psutil.Process(pid).environ()). See allow/denylist above.
    runtime_env_model: str | None = None    # e.g. "gpt-4o" read from $MODEL_NAME
    runtime_env_source: str | None = None   # the env var name that matched, e.g. "MODEL_NAME"


# ── helpers ──────────────────────────────────────────────────────────────────

def _find_project_root(start: Path) -> Path | None:
    """
    Walk up from *start* to find the nearest directory containing a project
    root marker (pyproject.toml, setup.py, package.json, …).

    Returns None if none found within 20 directory levels.
    """
    current = start if start.is_dir() else start.parent
    for _ in range(20):
        for marker in _PROJECT_ROOT_MARKERS:
            if (current / marker).exists():
                return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _resolve_entry_script(cmdline: list[str], cwd: Path | None) -> Path | None:
    """
    Extract and resolve the Python entry-script path from a process cmdline.

    Handles:
    - ``python3 /abs/path/agent.py``
    - ``python3 relative/path.py``  (resolved against cwd)
    - ``python3 -u -W ignore agent.py``  (interpreter flags stripped)

    Returns None for:
    - ``python3 -m module_name``   (module invocation, not a file)
    - ``python3 -c "code"``        (inline code)
    - Non-.py arguments (uvicorn, gunicorn entrypoints, etc.)
    - Empty or single-element cmdlines
    """
    if not cmdline or len(cmdline) < 2:
        return None

    # Flags that are consumed without a following value
    _SKIP_FLAGS = {"-u", "-O", "-OO", "-B", "-d", "-i", "-q", "-v", "-s", "-S", "-E"}
    # Flags that consume the *next* argument as their value (e.g. -W ignore, -X dev)
    _VALUE_FLAGS = {"-W", "-X", "-Q"}
    args = list(cmdline[1:])

    while args and args[0].startswith("-"):
        flag = args.pop(0)
        if flag == "-m":
            return None   # module invocation
        if flag == "-c":
            return None   # inline code string
        if flag in _VALUE_FLAGS:
            # Consume the value argument that follows (e.g. "ignore" after -W)
            if args and not args[0].startswith("-"):
                args.pop(0)
            continue
        if flag in _SKIP_FLAGS:
            continue
        # Unknown flag — consume following non-flag arg if present
        if args and not args[0].startswith("-"):
            args.pop(0)

    if not args:
        return None

    candidate = Path(args[0])
    if candidate.suffix != ".py":
        return None   # Not a plain Python script

    if candidate.is_absolute():
        return candidate if candidate.exists() else None

    # Relative path — resolve against cwd
    if cwd:
        resolved = (cwd / candidate).resolve()
        if resolved.exists():
            return resolved

    return None


# DAI008 (declared_model) and DAI009 (generation params) are metadata-enrichment
# signals, not framework signals — they must never by themselves drive
# framework/confidence selection below.
_NON_FRAMEWORK_RULE_IDS = frozenset({"DAI008", "DAI009"})


def _scan_file_for_rules(file_path: Path, rule_ids_out: list[str]) -> None:
    """
    Parse *file_path* with the production ContextAwareVisitor + SIGNATURE_REGISTRY
    and append any new rule_ids to *rule_ids_out*.
    """
    if not file_path.exists() or not file_path.is_file():
        return
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return
    except Exception as exc:
        _logger.debug("process_introspection: parse error %s: %s", file_path, exc)
        return

    try:
        from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
        from agent_discover_scanner.visitor import ContextAwareVisitor
    except ImportError:
        _logger.debug("process_introspection: L1 scanner modules unavailable")
        return

    visitor = ContextAwareVisitor(str(file_path), SIGNATURE_REGISTRY)
    visitor.visit(tree)
    for finding in visitor.findings:
        if finding.rule_id in _NON_FRAMEWORK_RULE_IDS:
            continue
        if finding.rule_id not in rule_ids_out:
            rule_ids_out.append(finding.rule_id)


def _extract_runtime_env_model(pid: int) -> tuple[str | None, str | None]:
    """
    Best-effort read of a live process's environment for a declared model
    identifier — the "runtime_env_model" tier (Layer 2, highest local-scan
    confidence since it reflects what the process actually has in memory).

    SECURITY: never raises, and never returns/logs/persists the raw environ()
    dict. Only the single matched key name + value (allowlist AND NOT denylist)
    are returned. See _RUNTIME_ENV_ALLOWLIST / _RUNTIME_ENV_DENYLIST above —
    this exists specifically to prevent a security-monitoring tool from leaking
    API keys/secrets into its own output.
    """
    try:
        environ = psutil.Process(pid).environ()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None, None
    except Exception as exc:
        _logger.debug("process_introspection: environ() read failed for pid %s: %s", pid, exc)
        return None, None

    try:
        for key, value in environ.items():
            if not isinstance(key, str) or not isinstance(value, str) or not value:
                continue
            if any(pattern.search(key) for pattern in _RUNTIME_ENV_DENYLIST):
                continue
            if any(pattern.search(key) for pattern in _RUNTIME_ENV_ALLOWLIST):
                return value, key
    except Exception as exc:
        _logger.debug("process_introspection: environ() scan failed for pid %s: %s", pid, exc)
        return None, None

    return None, None


def _scan_for_framework(
    entry: Path,
    project_root: Path | None,
) -> tuple[str | None, list[str], str | None]:
    """
    Run L1 detection rules against *entry* (and optionally sibling project files).

    Strategy:
    1. Scan the entry script directly.
    2. If no signal found and project_root is known, scan up to _MAX_PROJECT_FILES
       Python files under the project root, stopping at the first hit.

    Returns ``(framework_name, rule_ids, confidence)`` where:
    - *framework_name* is the highest-priority framework detected, or ``None``
    - *confidence* is ``"high"`` when the entry script itself contained the
      signal, ``"medium"`` when a sibling project file matched, or ``None``
      when nothing was found.

    Reuses ContextAwareVisitor + SIGNATURE_REGISTRY — no detection logic is
    reimplemented here.
    """
    found: list[str] = []
    confidence: str | None = None

    # Step 1: entry script (direct hit → high confidence)
    _scan_file_for_rules(entry, found)
    if found:
        confidence = "high"

    # Step 2: project-wide scan (capped, stops early → medium confidence)
    if not found and project_root and project_root.is_dir():
        py_files = (
            f for f in project_root.rglob("*.py")
            if f != entry
            and not any(part in _SKIP_DIRS for part in f.parts)
        )
        scanned = 0
        for py_file in py_files:
            if scanned >= _MAX_PROJECT_FILES:
                break
            _scan_file_for_rules(py_file, found)
            scanned += 1
            if found:
                confidence = "medium"
                break   # Stop at first framework signal

    if not found:
        return None, [], None

    # Select highest-priority framework
    for rule_id in _RULE_PRIORITY:
        if rule_id in found:
            return _RULE_TO_FRAMEWORK.get(rule_id), list(found), confidence

    # Fallback: first detected
    first = found[0]
    return _RULE_TO_FRAMEWORK.get(first, "Unknown"), list(found), confidence


# ── public API ───────────────────────────────────────────────────────────────

def introspect_process(pid: int) -> ProcessIntrospectionResult:
    """
    Resolve process info via psutil and run L1 framework-detection rules
    against the owning entry script.

    Cross-platform (Linux, macOS, Windows) — uses psutil throughout.
    Gracefully handles AccessDenied, NoSuchProcess, and filesystem errors.
    Never raises.

    Returns a ProcessIntrospectionResult; ``.framework`` is None when no
    AI framework was detected or when the process cannot be introspected.
    """
    result = ProcessIntrospectionResult(pid=pid)

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return result

    # Runtime env model read — best-effort, never blocks the rest of introspection.
    result.runtime_env_model, result.runtime_env_source = _extract_runtime_env_model(pid)

    # --- psutil info (each attr can fail independently) ---
    try:
        result.cmdline = proc.cmdline()
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        pass

    try:
        result.cwd = proc.cwd()
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        pass

    if not result.cmdline:
        return result   # No cmdline → can't determine entry script

    cwd_path = Path(result.cwd) if result.cwd else None
    entry = _resolve_entry_script(result.cmdline, cwd_path)
    if entry is None:
        return result   # Not a Python script invocation

    result.entry_script = str(entry)

    project_root = _find_project_root(entry)
    if project_root:
        result.project_root = str(project_root)

    framework, rule_ids, framework_confidence = _scan_for_framework(entry, project_root)
    result.framework = framework
    result.rule_ids = rule_ids
    result.framework_confidence = framework_confidence

    return result
