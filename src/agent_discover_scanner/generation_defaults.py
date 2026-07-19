"""
Generation/sampling parameter default-value resolution.

Backfills a provenance-tagged value for each tracked generation parameter
(temperature, top_p, top_k, max_tokens, frequency_penalty, presence_penalty,
stop, seed, n) when it was NOT found explicitly at a call site — see
signatures.py's ``extract_generation_params`` for the explicit-detection side.

The maintained default-value table lives in
``data/generation_param_defaults.json`` (not inline here) since these values
drift with provider API versions and need to be updatable independently of
detection logic.

This module is purely a fact-resolution layer: it never decides risk_level or
agent classification (see ``compute_threshold_flags`` for the separate,
informational-only flag layer consumed by ``audit_reports.py``).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

ALL_GENERATION_PARAMS: tuple[str, ...] = (
    "temperature",
    "top_p",
    "top_k",
    "max_tokens",
    "frequency_penalty",
    "presence_penalty",
    "stop",
    "seed",
    "n",
)

_DEFAULTS_PATH = Path(__file__).parent / "data" / "generation_param_defaults.json"

# OpenAI/Azure OpenAI reasoning-model family (o1, o3, o4, gpt-5, and future
# equivalents) — these fix/reject the standard sampling parameters entirely.
_REASONING_MODEL_PATTERN = re.compile(r"^(o1|o3|o4|gpt-5)", re.IGNORECASE)

# Bedrock model-ID prefixes, longest/most-specific first, mapped to the
# nested family key in the defaults table.
_BEDROCK_FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("anthropic.claude", "anthropic.claude"),
    ("amazon.titan", "amazon.titan"),
    ("meta.llama", "meta.llama"),
    ("mistral.", "mistral"),
    ("cohere.command", "cohere.command"),
)


@lru_cache(maxsize=1)
def _load_defaults_table() -> dict[str, Any]:
    try:
        return json.loads(_DEFAULTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"wrappers": {}, "bedrock_model_families": {}}


def is_reasoning_model(declared_model: str | None) -> bool:
    """True if ``declared_model`` matches the OpenAI/Azure reasoning-model family."""
    if not declared_model:
        return False
    return bool(_REASONING_MODEL_PATTERN.match(declared_model.strip()))


def classify_bedrock_family(declared_model: str | None) -> str | None:
    """Map a Bedrock model ID to its nested defaults-table family key, or None if unmatched."""
    if not declared_model:
        return None
    model_lower = declared_model.lower()
    for prefix, family_key in _BEDROCK_FAMILY_PREFIXES:
        if model_lower.startswith(prefix):
            return family_key
    return None


def classify_wrapper_key(
    rule_id: str | None,
    message: str | None,
    wrapper_hint: str | None,
    declared_model: str | None,
) -> str | None:
    """
    Determine which entry of the defaults table applies to a code finding.

    Priority:
    1. ``wrapper_hint`` — precise classification from the actual call-site
       func_name (see signatures.py's ``_classify_wrapper``), attached to a
       co-located/same-file DAI008 (declared_model) or DAI009 (generation
       params) finding. This is the most reliable signal since it looks at
       the exact call, not just the coarse framework/rule_id.
    2. ``rule_id`` + ``message`` heuristic fallback (mirrors the existing
       ``CorrelationEngine._detect_bedrock_framework`` pattern) when no
       wrapper_hint is available.

    Returns "bedrock" as a sentinel meaning "look up
    bedrock_model_families[classify_bedrock_family(declared_model)]" instead
    of a flat wrappers[...] entry.
    """
    reasoning = is_reasoning_model(declared_model)

    if wrapper_hint == "openai_raw_sdk":
        return "openai_reasoning" if reasoning else "openai_raw_sdk"
    if wrapper_hint == "azure_openai_raw_sdk":
        return "azure_openai_reasoning" if reasoning else "azure_openai_raw_sdk"
    if wrapper_hint in ("anthropic_raw_sdk", "langchain_chatopenai", "langchain_chatanthropic"):
        return wrapper_hint
    if wrapper_hint == "bedrock":
        return "bedrock"

    rule_id = rule_id or ""
    msg_lower = (message or "").lower()

    if rule_id == "DAI007" or "bedrock" in msg_lower:
        return "bedrock"
    if rule_id == "DAI004":
        if "openai" in msg_lower:
            return "openai_reasoning" if reasoning else "openai_raw_sdk"
        if "anthropic" in msg_lower:
            return "anthropic_raw_sdk"

    return None


def resolve_generation_params(
    wrapper_key: str | None,
    declared_model: str | None,
    explicit: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """
    Build the final, per-parameter provenance-tagged dict for all
    ``ALL_GENERATION_PARAMS``.

    ``explicit`` entries (source "literal"/"resolved_constant", from an
    actual call-site kwarg) are always kept as-is and never overwritten.
    Everything else is backfilled from the defaults table (or tagged
    "unknown" when the table has no entry for this wrapper_key/param).
    """
    explicit = explicit or {}
    table = _load_defaults_table()
    wrappers = table.get("wrappers") or {}
    bedrock_families = table.get("bedrock_model_families") or {}

    if wrapper_key == "bedrock":
        family = classify_bedrock_family(declared_model)
        table_entry = bedrock_families.get(family or "", bedrock_families.get("_unknown", {}))
    elif wrapper_key:
        table_entry = wrappers.get(wrapper_key, {})
    else:
        table_entry = {}

    result: dict[str, dict[str, Any]] = {}
    for param in ALL_GENERATION_PARAMS:
        if param in explicit:
            result[param] = explicit[param]
            continue

        entry = table_entry.get(param) if isinstance(table_entry, dict) else None
        tier = (entry or {}).get("tier", "unknown")

        if tier == "not_applicable":
            result[param] = {"source": "not_applicable"}
        elif tier == "framework_default":
            result[param] = {"value": entry.get("value"), "source": "framework_default"}
        else:
            result[param] = {"source": "unknown"}

    return result


def has_any_signal(
    wrapper_key: str | None,
    explicit: dict[str, dict[str, Any]] | None,
) -> bool:
    """
    True if we have enough signal to make ``generation_params`` meaningful for
    an agent record — either a resolvable wrapper/provider (so defaults can be
    backfilled honestly) or at least one explicit value found in code.

    Deliberately conservative: without this gate, every agent with an
    unrecognized framework would get all nine params tagged "unknown", which
    is honest but adds no signal and clutters aibom.json/agent_inventory.json.
    """
    if wrapper_key:
        return True
    return bool(explicit)


_HIGH_TEMPERATURE_THRESHOLD = 0.8


def compute_threshold_flags(generation_params: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """
    Informational-only threshold flags derived from resolved generation params.

    These are opinions, not facts: callers must NEVER merge this into
    risk_level, agent classification, or aibom.json. They belong solely in
    the separate ``generation-params.md`` audit report.
    """
    flags: list[dict[str, str]] = []

    temperature = generation_params.get("temperature") or {}
    temp_value = temperature.get("value")
    temp_source_is_explicit_or_default = temperature.get("source") in (
        "literal",
        "resolved_constant",
        "framework_default",
    )
    if temp_source_is_explicit_or_default and isinstance(temp_value, (int, float)):
        if temp_value > _HIGH_TEMPERATURE_THRESHOLD:
            flags.append(
                {
                    "flag": "HIGH_TEMPERATURE",
                    "message": (
                        f"Temperature is {temp_value} — elevated relative to typical "
                        "production/decision-support use; not inherently wrong, evaluate "
                        "against this agent's actual task."
                    ),
                }
            )
        if temp_value == 0:
            flags.append(
                {
                    "flag": "ZERO_TEMPERATURE",
                    "message": (
                        "Temperature is 0 — informational, not a warning: useful for "
                        "orgs that need to demonstrate deterministic/reproducible output "
                        "for compliance purposes."
                    ),
                }
            )

    max_tokens = generation_params.get("max_tokens") or {}
    if max_tokens.get("source") == "unknown":
        flags.append(
            {
                "flag": "UNBOUNDED_MAX_TOKENS",
                "message": (
                    "No max_tokens (or provider equivalent) detected and no provider "
                    "default applies — cost/runaway-generation signal, not a quality "
                    "judgment."
                ),
            }
        )

    return flags
