"""
Multi-signal detection for high-risk autonomous agent platforms.

OpenClaw (Clawdbot/Moltbot) and similar agents are detected via definitive
filesystem, process, port, and service signals. Only findings with at least
"medium" confidence are emitted. Port 8080 is never used (conflicts with
defendai-agent). OpenClaw's actual default gateway port is 18789.
"""

import os
import subprocess

HIGH_RISK_AGENTS = {
    "openclaw": {
        "display_name": "OpenClaw",
        "aliases": ["clawdbot", "moltbot"],
        "description": (
            "Autonomous AI agent with full system access — filesystem, "
            "terminal, email, and messaging integration. "
            "CVE-2026-25253 CVSS 8.8. Gartner: insecure by default. "
            "Microsoft: treat as untrusted code execution."
        ),
        "capabilities": ["filesystem", "terminal", "email", "browser", "messaging"],
        "risk": "high",
        "definitive_files": [
            "~/.openclaw/openclaw.json",
            "~/.openclaw/",
            "~/clawd/SOUL.md",
            "~/clawd/USER.md",
            "~/.clawdbot/",
            "~/.moltbot/",
        ],
        "definitive_dirs": [
            "~/.openclaw",
            "~/clawd",
            "~/.clawdbot",
            "~/.moltbot",
        ],
        "definitive_processes": [
            "openclaw",
            "openclaw-gateway",
        ],
        "definitive_ports": [18789],
        "definitive_services": [
            "ai.openclaw.gateway",
            "openclaw",
        ],
        "definitive_npm_packages": ["openclaw"],
        "strong_env_prefixes": ["OPENCLAW_", "CLAWDBOT_SKIP_CHANNELS"],
        "strong_service_files": [
            "~/.config/systemd/user/openclaw.service",
            "~/Library/LaunchAgents/ai.openclaw.gateway.plist",
        ],
        "strong_config_files": [
            "~/.openclaw/openclaw.json",
        ],
        "weak_ports": [3000],
        "weak_env_prefixes": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
    },
    "autogpt": {
        "display_name": "AutoGPT",
        "aliases": ["auto-gpt"],
        "description": "Autonomous agent with internet access and code execution.",
        "capabilities": ["filesystem", "terminal", "browser"],
        "risk": "high",
        "definitive_files": [],
        "definitive_dirs": ["~/.autogpt", "~/Auto-GPT"],
        "definitive_processes": ["autogpt", "autogpt-server"],
        "definitive_npm_packages": [],
        "definitive_ports": [],
        "definitive_services": [],
        "strong_env_prefixes": ["AUTOGPT_"],
        "strong_service_files": [],
        "strong_config_files": [],
        "weak_ports": [],
        "weak_env_prefixes": [],
    },
    "babyagi": {
        "display_name": "BabyAGI",
        "aliases": [],
        "description": "Autonomous task execution agent with browser and code access.",
        "capabilities": ["browser", "code_execution"],
        "risk": "high",
        "definitive_files": [],
        "definitive_dirs": ["~/.babyagi", "~/babyagi"],
        "definitive_processes": ["babyagi"],
        "definitive_npm_packages": [],
        "definitive_ports": [],
        "definitive_services": [],
        "strong_env_prefixes": ["BABYAGI_"],
        "strong_service_files": [],
        "strong_config_files": [],
        "weak_ports": [],
        "weak_env_prefixes": [],
    },
}

CONFIDENCE_LEVELS = ["confirmed", "high", "medium", "low"]


def _expand(path: str) -> str:
    return os.path.expanduser(path)


def _path_exists(path: str) -> bool:
    try:
        return os.path.exists(_expand(path))
    except Exception:
        return False


def _check_npm_global(package_name: str) -> bool:
    """
    Check if an npm package is installed globally.
    Checks common global npm prefix locations without running npm.
    Never raises.
    """
    try:
        result = subprocess.run(
            ["npm", "config", "get", "prefix"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            prefix = result.stdout.strip()
            if prefix:
                pkg_path = os.path.join(prefix, "lib", "node_modules", package_name)
                if os.path.exists(pkg_path):
                    return True
    except Exception:
        pass

    try:
        common_prefixes = [
            os.path.expanduser("~/.npm-global"),
            "/usr/local",
            "/usr",
            os.path.expanduser("~/.nvm/versions/node"),
        ]
        for prefix in common_prefixes:
            pkg_path = os.path.join(prefix, "lib", "node_modules", package_name)
            if os.path.exists(pkg_path):
                return True
    except Exception:
        pass
    return False


def _check_launchd_service(service_name: str) -> bool:
    """Check if a launchd service plist exists (macOS only)."""
    try:
        plist_path = _expand(f"~/Library/LaunchAgents/{service_name}.plist")
        return os.path.exists(plist_path)
    except Exception:
        return False


def _check_systemd_service(service_name: str) -> bool:
    """Check if a systemd user service file exists (Linux only)."""
    try:
        service_path = _expand(f"~/.config/systemd/user/{service_name}.service")
        return os.path.exists(service_path)
    except Exception:
        return False


def _check_port_listening(port: int, layer4_findings: list) -> bool:
    """
    Check if a port is listening using layer4 findings data.
    Never uses port alone as definitive signal.
    """
    try:
        for item in layer4_findings or []:
            local_port = item.get("local_port") or item.get("port")
            if local_port is not None:
                try:
                    if int(local_port) == port:
                        return True
                except (ValueError, TypeError):
                    pass
    except Exception:
        pass
    return False


def _check_process_running(
    process_names: list,
    layer4_findings: list,
) -> tuple[bool, str]:
    """
    Check if any of the given process names are running.
    Returns (found: bool, matched_name: str).
    """
    try:
        for item in layer4_findings or []:
            proc = (
                item.get("process_name")
                or item.get("name")
                or item.get("process")
                or ""
            ).lower().strip()
            for name in process_names:
                n = name.lower()
                if proc == n or proc.startswith(n + "-") or proc.startswith(n + " "):
                    return True, proc
    except Exception:
        pass
    return False, ""


def detect_high_risk_agent(
    agent_key: str,
    agent_info: dict,
    layer4_findings: list | None = None,
    network_findings: list | None = None,
) -> dict | None:
    """
    Run multi-signal detection for a specific high-risk agent.
    Returns a finding dict if confidence >= "medium", else None.

    Confidence logic:
      confirmed = ANY definitive signal present
      high      = 2+ strong signals OR 1 strong + 1 weak
      medium    = 1 strong signal alone
      low       = weak signals only → return None (never emit)
    """
    layer4 = layer4_findings or []
    signals = []
    definitive_found = False

    # --- CHECK DEFINITIVE SIGNALS ---

    for dir_path in agent_info.get("definitive_dirs", []):
        if _path_exists(dir_path):
            signals.append({
                "type": "definitive_dir",
                "value": dir_path,
                "confidence": "confirmed",
            })
            definitive_found = True
            break

    if not definitive_found:
        for file_path in agent_info.get("definitive_files", []):
            if _path_exists(file_path):
                signals.append({
                    "type": "definitive_file",
                    "value": file_path,
                    "confidence": "confirmed",
                })
                definitive_found = True
                break

    if not definitive_found:
        found, matched = _check_process_running(
            agent_info.get("definitive_processes", []),
            layer4,
        )
        if found:
            signals.append({
                "type": "definitive_process",
                "value": matched,
                "confidence": "confirmed",
            })
            definitive_found = True

    if not definitive_found:
        for port in agent_info.get("definitive_ports", []):
            if _check_port_listening(port, layer4):
                signals.append({
                    "type": "definitive_port",
                    "value": port,
                    "confidence": "confirmed",
                    "note": f"Port {port} is highly specific to this agent",
                })
                definitive_found = True
                break

    if not definitive_found:
        for pkg in agent_info.get("definitive_npm_packages", []):
            if _check_npm_global(pkg):
                signals.append({
                    "type": "definitive_npm",
                    "value": pkg,
                    "confidence": "confirmed",
                })
                definitive_found = True
                break

    if not definitive_found:
        for svc in agent_info.get("definitive_services", []):
            if _check_launchd_service(svc) or _check_systemd_service(svc):
                signals.append({
                    "type": "definitive_service",
                    "value": svc,
                    "confidence": "confirmed",
                })
                definitive_found = True
                break

    if definitive_found:
        return {
            "agent_type": agent_key,
            "display_name": agent_info["display_name"],
            "confidence": "confirmed",
            "signals": signals,
            "risk": agent_info["risk"],
            "description": agent_info["description"],
            "capabilities": agent_info["capabilities"],
        }

    # --- CHECK STRONG SIGNALS ---
    strong_count = 0

    for svc_file in agent_info.get("strong_service_files", []):
        if _path_exists(svc_file):
            signals.append({
                "type": "strong_service_file",
                "value": svc_file,
                "confidence": "high",
            })
            strong_count += 1

    try:
        env_keys = [k.upper() for k in os.environ.keys()]
        for prefix in agent_info.get("strong_env_prefixes", []):
            pu = prefix.upper()
            if any(k.startswith(pu) for k in env_keys):
                signals.append({
                    "type": "strong_env_var",
                    "value": prefix,
                    "confidence": "high",
                })
                strong_count += 1
    except Exception:
        pass

    for cfg in agent_info.get("strong_config_files", []):
        if _path_exists(cfg):
            signals.append({
                "type": "strong_config_file",
                "value": cfg,
                "confidence": "high",
            })
            strong_count += 1

    # --- CHECK WEAK SIGNALS ---
    weak_count = 0

    for port in agent_info.get("weak_ports", []):
        if _check_port_listening(port, layer4):
            signals.append({
                "type": "weak_port",
                "value": port,
                "confidence": "low",
                "note": f"Port {port} is common — not standalone evidence",
            })
            weak_count += 1

    # --- COMPUTE FINAL CONFIDENCE ---
    if strong_count >= 2:
        confidence = "high"
    elif strong_count == 1 and weak_count >= 1:
        confidence = "high"
    elif strong_count == 1:
        confidence = "medium"
    else:
        return None

    return {
        "agent_type": agent_key,
        "display_name": agent_info["display_name"],
        "confidence": confidence,
        "signals": signals,
        "risk": agent_info["risk"],
        "description": agent_info["description"],
        "capabilities": agent_info["capabilities"],
    }


def detect_all_high_risk_agents(
    layer4_findings: list | None = None,
    network_findings: list | None = None,
    scan_dir: str | None = None,
) -> dict:
    """
    Run detection for all known high-risk agent platforms.

    Returns:
        {
            "detected": ["openclaw"],
            "findings": [...],
            "is_high_risk": True,
            "highest_risk": "high",
            "all_capabilities": ["filesystem", "terminal", ...],
        }
    """
    all_findings = []

    try:
        for agent_key, agent_info in HIGH_RISK_AGENTS.items():
            try:
                finding = detect_high_risk_agent(
                    agent_key,
                    agent_info,
                    layer4_findings=layer4_findings,
                    network_findings=network_findings,
                )
                if finding:
                    all_findings.append(finding)
            except Exception:
                pass
    except Exception:
        pass

    if not all_findings:
        return {
            "detected": [],
            "findings": [],
            "is_high_risk": False,
            "highest_risk": None,
            "all_capabilities": [],
        }

    detected = [f["agent_type"] for f in all_findings]
    all_caps = list({
        cap
        for f in all_findings
        for cap in f.get("capabilities", [])
    })

    return {
        "detected": sorted(detected),
        "findings": all_findings,
        "is_high_risk": True,
        "highest_risk": "high",
        "all_capabilities": sorted(all_caps),
    }
