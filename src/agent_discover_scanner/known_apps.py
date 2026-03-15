"""
Known desktop applications list: three-tier resolution (platform, local, builtin).

# Platform: uses defendai-sdk when available, else urllib + file cache.
# Tenant-specific: returns the tenant's custom list merged with the platform defaults.
"""

import json
import os
import time

try:
    from defendai_sdk.client import WawsdbClient
    from defendai_sdk.known_apps import get_known_apps

    HAS_SDK = True
except ImportError:
    HAS_SDK = False

BUILTIN_KNOWN_APPS = frozenset({
    # Browsers
    "chrome", "google chrome", "chromium",
    "safari", "safari web content",
    "firefox", "firefox web content",
    "msedge", "microsoft edge", "microsoft edge helper",
    # Microsoft Office / 365
    "excel", "microsoft excel",
    "word", "microsoft word",
    "outlook", "microsoft outlook",
    "powerpoint", "microsoft powerpoint",
    "teams", "microsoft teams",
    "onedrive", "microsoft onedrive",
    # AI desktop apps
    "cursor", "cursor helper",
    "claude", "claude helper", "claude desktop",
    "chatgpt",
    # Apple apps
    "notes", "apple notes",
    "mail", "apple mail",
    # Developer tools
    "vscode", "visual studio code",
    "xcode",
    "terminal", "iterm", "iterm2",
    # Communication
    "slack", "zoom", "discord", "notion",
})

LOCAL_OVERRIDE_PATHS = [
    os.path.expanduser("~/.defendai/known_apps.txt"),
    os.path.join(os.getcwd(), "defendai-known-apps.txt"),
]


def load_local_known_apps() -> frozenset:
    """
    Load known apps from local override files.
    Checks ~/.defendai/known_apps.txt and ./defendai-known-apps.txt.
    File format: one app name per line, # for comments, blank lines ok.
    Returns frozenset of lowercased app names.
    Returns empty frozenset if no file found or file is unreadable.
    """
    for path in LOCAL_OVERRIDE_PATHS:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    apps = set()
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            apps.add(line.lower())
                    return frozenset(apps)
            except Exception:
                pass
    return frozenset()


def load_platform_known_apps(
    api_key: str | None = None,
    tenant_token: str | None = None,
    wawsdb_url: str = "https://wauzeway.defendai.ai",
) -> frozenset[str]:
    """
    Download known apps list from DefendAI platform using SDK.
    Falls back to file cache if SDK unavailable or call fails.
    Returns frozenset of lowercase app names. Never raises.
    """
    CACHE_PATH = os.path.expanduser("~/.defendai/known_apps_cache.txt")

    if api_key:
        if HAS_SDK:
            try:
                client = WawsdbClient(
                    wawsdb_url=wawsdb_url,
                    api_key=api_key,
                    tenant_token=tenant_token or "",
                )
                apps = get_known_apps(client, timeout=5.0)
                if apps:
                    try:
                        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
                        with open(CACHE_PATH, "w", encoding="utf-8") as f:
                            f.write(f"# cached:{time.time()}\n")
                            for app in sorted(apps):
                                f.write(f"{app}\n")
                    except Exception:
                        pass
                    return frozenset(a.lower() for a in apps)
            except Exception:
                pass
        else:
            # Urllib fallback when SDK not installed
            try:
                import urllib.request

                req = urllib.request.Request(
                    f"{wawsdb_url.rstrip('/')}/scanner/config/known-apps",
                    headers={"X-API-Key": api_key},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    apps = frozenset(a.lower() for a in data.get("known_apps", []))
                    if apps:
                        try:
                            os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
                            with open(CACHE_PATH, "w", encoding="utf-8") as f:
                                f.write(f"# cached:{time.time()}\n")
                                for app in sorted(apps):
                                    f.write(f"{app}\n")
                        except Exception:
                            pass
                        return apps
            except Exception:
                pass

    # Fall back to file cache (existing logic — keep as-is)
    try:
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if lines and lines[0].strip().startswith("# cached:"):
                cached_at = float(lines[0].split(":")[1].strip())
                if time.time() - cached_at < 86400:  # 24 hours
                    apps = frozenset(
                        ln.strip().lower()
                        for ln in lines[1:]
                        if ln.strip() and not ln.strip().startswith("#")
                    )
                    return apps
    except Exception:
        pass

    return frozenset()


def build_known_apps(
    platform_apps: frozenset | None = None,
) -> frozenset:
    """
    Merge all three tiers into final known apps set.
    Order: builtin | local_override | platform_apps
    All three are merged — they are additive, not replacing.
    """
    result = set(BUILTIN_KNOWN_APPS)
    result.update(load_local_known_apps())
    if platform_apps:
        result.update(platform_apps)
    return frozenset(result)


def is_known_desktop_app(
    process_name: str,
    known_apps: frozenset,
) -> bool:
    """
    Returns True if process_name matches a known desktop application.
    Checks exact match and prefix match (for helper processes like
    'Cursor Helper (Plugin): extension-host...').
    """
    if not process_name or not known_apps:
        return False
    try:
        pl = process_name.lower().strip()
        if pl in known_apps:
            return True
        for known in known_apps:
            if pl.startswith(known):
                return True
    except Exception:
        pass
    return False
