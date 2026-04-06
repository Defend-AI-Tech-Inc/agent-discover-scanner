"""Shared scan-all execution (CLI scan-all and audit)."""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import signal
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agent_discover_scanner.correlator import CorrelationEngine
from agent_discover_scanner.errors import ValidationError, validate_directory_exists, validate_file_exists
from agent_discover_scanner.monitors.k8s_monitor import K8sAPIMonitor
from agent_discover_scanner.network_monitor import NetworkMonitor
from agent_discover_scanner.monitors import monitor_k8s as run_monitor_k8s
from agent_discover_scanner.platform import upload_scan_results

logger = logging.getLogger(__name__)
console = Console()

_DAEMON_BACKOFF_INITIAL_SEC = 30
_DAEMON_BACKOFF_MAX_SEC = 300
_DAEMON_DISK_WARN_BYTES = 500 * 1024 * 1024
_DAEMON_DISK_CRITICAL_BYTES = 100 * 1024 * 1024
_DAEMON_DISK_RESUME_BYTES = 200 * 1024 * 1024
_DAEMON_LOG_MAX_BYTES = 20 * 1024 * 1024
_DAEMON_LOG_BACKUP_COUNT = 3


def _rotate_file_if_needed(path: Path, max_size_bytes: int, backup_count: int) -> None:
    if not path.exists() or path.stat().st_size < max_size_bytes:
        return
    for i in range(backup_count - 1, 0, -1):
        old_p = Path(f"{path!s}.{i}")
        new_p = Path(f"{path!s}.{i + 1}")
        if old_p.exists():
            if new_p.exists():
                new_p.unlink()
            shutil.move(str(old_p), str(new_p))
    if Path(f"{path!s}.1").exists():
        Path(f"{path!s}.1").unlink()
    shutil.move(str(path), f"{path!s}.1")


def _inventory_hash(report: dict) -> str:
    try:
        agents = sorted(
            a.get("agent_id", "")
            for cat in report.get("inventory", {}).values()
            for a in cat
        )
        return hashlib.sha256(json.dumps(agents, sort_keys=True).encode()).hexdigest()
    except Exception:
        return ""


def _invoke_layer1_scan(scan_root: str, layer1_sarif: str) -> None:
    import agent_discover_scanner.cli as cli_mod
    cli_mod.scan(path=scan_root, output=layer1_sarif, format="sarif", verbose=False)


def execute_scan_all(
    *,
    path: str,
    output: Path,
    duration: int,
    layer3_file: Optional[Path],
    skip_layers: Optional[str],
    daemon: bool,
    max_log_size: int,
    max_log_backups: int,
    platform: bool,
    api_key: Optional[str],
    tenant_token: Optional[str],
    wawsdb_url: str,
    platform_interval: int,
    verbose: bool,
    scan_output_format: str,
    layer: Optional[str] = None,
) -> Optional[dict]:
    """Run full or partial scan-all. Returns report dict, or None if MCP-only early exit."""
    console.print("\n[bold cyan]🔍 Scanning for autonomous AI agents...[/bold cyan]\n")

    # Validate target path
    try:
        scan_root = validate_directory_exists(path, "Scan directory")
    except ValidationError:
        raise typer.Exit(code=1)

    scan_root = scan_root.resolve()
    try:
        py_count = sum(
            1
            for _ in scan_root.rglob("*.py")
            if not any(
                skip in str(_)
                for skip in (
                    ".venv",
                    "venv",
                    "node_modules",
                    "site-packages",
                    "__pycache__",
                    ".git",
                    "dist",
                    "build",
                )
            )
        )
        if py_count > 500:
            console.print(
                f"[yellow]⚠  Large scan path detected: {py_count} Python files. "
                f"Consider scanning a specific project directory for faster results. "
                f"Example: agent-discover-scanner scan-all ./my-project[/yellow]\n"
            )
    except Exception:
        pass  # Never fail the scan because of this warning

    output_dir = output
    output_dir.mkdir(parents=True, exist_ok=True)

    layer1_sarif = output_dir / "layer1_code.sarif"
    layer2_json = output_dir / "layer2_network.json"
    layer3_jsonl = output_dir / "layer3_k8s.jsonl"
    layer4_json = output_dir / "layer4_endpoint.json"
    inventory_path = output_dir / "agent_inventory.json"

    effective_layer: Optional[str] = None
    if layer is not None and str(layer).strip():
        effective_layer = str(layer).strip().lower()
        allowed_layer = frozenset({"code", "network", "k8s", "endpoint", "mcp"})
        if effective_layer not in allowed_layer:
            console.print(
                f"[red]Invalid --layer {layer!r}; use code, network, k8s, endpoint, or mcp[/red]"
            )
            raise typer.Exit(code=1)
        if daemon:
            console.print("[red]--layer cannot be used with --daemon[/red]")
            raise typer.Exit(code=1)

    if effective_layer == "mcp":
        from agent_discover_scanner.mcp_detector import detect_mcp_servers

        nf: list = []
        l4: list = []
        try:
            if layer2_json.exists():
                data = json.loads(layer2_json.read_text())
                nf = (data.get("findings") or []) + (data.get("connections") or [])
        except (json.JSONDecodeError, OSError):
            pass
        try:
            if layer4_json.exists():
                l4 = CorrelationEngine.load_layer4_findings(layer4_json)
        except Exception:
            pass
        try:
            mcp_result = detect_mcp_servers(
                scan_dir=str(scan_root),
                network_findings=nf,
                layer4_findings=l4,
            )
            if mcp_result.get("servers"):
                if mcp_result.get("has_local_scripts"):
                    console.print(
                        "[bold red]⚠ Local MCP script detected — "
                        "unknown code with tool access[/bold red]"
                    )
                unverified = [
                    s
                    for s in mcp_result.get("servers", [])
                    if not s.get("publisher_verified") and not s.get("is_local_script")
                ]
                for s in unverified[:3]:
                    console.print(
                        f"[yellow]⚠ Unverified MCP server: "
                        f"{s.get('server_name', '?')} "
                        f"({s.get('vendor', 'unknown vendor')}) — "
                        f"not from a verified publisher[/yellow]"
                    )
                if mcp_result.get("network_detected"):
                    console.print(
                        "[dim]  ℹ MCP connections detected via network — "
                        "likely configured via AI client UI "
                        "(no local config file)[/dim]"
                    )
        except Exception:
            pass
        return None

    skip_layers_effective = skip_layers
    if effective_layer == "code":
        skip_layers_effective = "2,3,4"
    elif effective_layer == "network":
        skip_layers_effective = "1,3,4"
    elif effective_layer == "k8s":
        skip_layers_effective = "1,2,4"
    elif effective_layer == "endpoint":
        skip_layers_effective = "1,2,3"

    skip_set = set()
    if skip_layers_effective:
        for part in skip_layers_effective.split(","):
            key = part.strip().lower()
            if not key:
                continue
            if key.startswith("layer"):
                key = key[5:]
            skip_set.add(key)

    def is_skipped(layer_num: int) -> bool:
        return str(layer_num) in skip_set

    from agent_discover_scanner.known_apps import build_known_apps, load_platform_known_apps

    platform_apps = frozenset()
    if platform:
        try:
            console.print("[dim]Fetching known apps list from platform...[/dim]")
            platform_apps = load_platform_known_apps(
                api_key=api_key,
                tenant_token=tenant_token,
                wawsdb_url=wawsdb_url,
            )
            if platform_apps:
                console.print(
                    f"[dim]Platform: {len(platform_apps)} known apps loaded[/dim]"
                )
        except Exception:
            pass
    known_apps = build_known_apps(platform_apps=platform_apps)

    # Shared state for findings
    code_findings: list = []
    network_findings: list = []
    layer3_findings: list = []
    layer4_findings: list = []
    findings_lock = threading.Lock()

    stop_event = threading.Event()
    # Daemon-only: set to True when disk is critically low to pause Layer 3 logging
    pause_layer3_logging = [False]

    def run_layer1_once() -> None:
        nonlocal code_findings
        if is_skipped(1):
            console.print("[yellow]Skipping Layer 1 (code discovery) per configuration[/yellow]")
            return
        try:
            _invoke_layer1_scan(str(scan_root), str(layer1_sarif))
            from agent_discover_scanner.correlator import CorrelationEngine as _CE

            new_findings = _CE.load_code_findings(layer1_sarif)
            if not daemon:
                with findings_lock:
                    code_findings = new_findings
        except Exception as e:
            console.print(f"[red]Layer 1 scan failed:[/red] {e}")

    max_log_size_bytes = max_log_size * 1024 * 1024

    def run_layer2_once() -> None:
        nonlocal network_findings
        if is_skipped(2):
            console.print("[yellow]Skipping Layer 2 (network discovery) per configuration[/yellow]")
            return
        console.print("[bold green]🌐 Monitoring live network connections...[/bold green]")
        try:
            net_monitor = NetworkMonitor()
            summary = net_monitor.monitor(duration_seconds=duration)
            providers = getattr(CorrelationEngine, "_PROVIDERS", set())
            nf = []
            for conn in summary.get("connections", []):
                service = (conn.get("service") or "").lower()
                host = (conn.get("remote_host") or "").lower()
                provider = None
                for slug in providers:
                    if slug in service or slug in host:
                        provider = slug
                        break
                if not provider:
                    continue
                nf.append(
                    {
                        "provider": provider,
                        "process_name": conn.get("process"),
                        "timestamp": conn.get("timestamp"),
                    }
                )
            summary_with_findings = {**summary, "findings": nf}
            _rotate_file_if_needed(layer2_json, max_log_size_bytes, max_log_backups)
            layer2_json.write_text(json.dumps(summary_with_findings, indent=2))
            if not daemon:
                with findings_lock:
                    network_findings = nf
        except ImportError:
            console.print("[red]psutil not installed; skipping Layer 2 network discovery[/red]")
        except Exception as e:
            console.print(f"[red]Layer 2 monitoring failed:[/red] {e}")

    def run_layer3_once() -> None:
        nonlocal layer3_findings
        if is_skipped(3):
            console.print("[yellow]Skipping Layer 3 (Kubernetes discovery) per configuration[/yellow]")
            return

        # --layer3-file: bypass both Tetragon and K8s API, load directly
        if layer3_file:
            try:
                validated = validate_file_exists(str(layer3_file), "Layer 3 findings file")
                file_findings = CorrelationEngine.load_layer3_findings(validated)
                _rotate_file_if_needed(layer3_jsonl, max_log_size_bytes, max_log_backups)
                with open(layer3_jsonl, "w") as f:
                    for finding in file_findings:
                        f.write(json.dumps(finding) + "\n")
                if not daemon:
                    with findings_lock:
                        layer3_findings = file_findings
                console.print("[cyan]   Runtime data loaded[/cyan]\n")
            except ValidationError:
                console.print("[red]Provided --layer3-file not found; skipping Layer 3[/red]")
            except Exception as e:
                console.print(f"[red]Failed to load Layer 3 findings:[/red] {e}")
            return

        # Try Tetragon/eBPF first (when kubectl available and not paused)
        _rotate_file_if_needed(layer3_jsonl, max_log_size_bytes, max_log_backups)
        try:
            with open(layer3_jsonl, "w") as f:
                pass  # truncate so Tetragon writes fresh
        except OSError:
            pass

        tetragon_ok = False
        tetragon_findings: list = []
        if shutil.which("kubectl") is not None and not (daemon and pause_layer3_logging[0]):
            try:
                run_monitor_k8s(
                    namespace="kube-system",
                    duration=duration,
                    output_file=layer3_jsonl,
                    output_format="jsonl",
                    verbose=verbose,
                )
                tetragon_findings = CorrelationEngine.load_layer3_findings(layer3_jsonl)
                if tetragon_findings:
                    tetragon_ok = True
            except FileNotFoundError:
                pass
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]Tetragon error: {e}[/yellow]")

        if tetragon_ok:
            new_findings = tetragon_findings
            console.print("[bold green]Layer 3+: eBPF/Tetragon active (deep network visibility)[/bold green]")
        else:
            if verbose:
                console.print("[yellow]Layer 3: Tetragon unavailable, falling back to Kubernetes API discovery[/yellow]")
                console.print("[bold green]Layer 3: Kubernetes API discovery (install Tetragon for deeper visibility)[/bold green]")
            api_findings: list = []
            try:
                api_monitor = K8sAPIMonitor()
                api_findings = api_monitor.discover_agents()
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]Kubernetes API discovery failed: {e}[/yellow]")
            try:
                with open(layer3_jsonl, "w") as f:
                    for finding in api_findings:
                        f.write(json.dumps(finding) + "\n")
            except OSError as e:
                if verbose:
                    console.print(f"[red]Failed to write Layer 3 findings: {e}[/red]")
            new_findings = CorrelationEngine.load_layer3_findings(layer3_jsonl)

        if not daemon:
            with findings_lock:
                layer3_findings = new_findings
        if new_findings:
            console.print("[cyan]   Runtime data loaded[/cyan]")
        console.print("")

    def run_layer4_once() -> None:
        nonlocal layer4_findings
        if is_skipped(4):
            console.print("[yellow]Skipping Layer 4 (endpoint discovery) per configuration[/yellow]")
            return
        console.print("[bold green]💻 Scanning endpoints...[/bold green]")
        try:
            subprocess.run(
                ["osqueryi", "--version"],
                capture_output=True,
                timeout=5,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            console.print("[yellow]   Endpoint agent not installed — skipping[/yellow]")
            return

        try:
            from agent_discover_scanner.layer4.osquery_executor import OsqueryExecutor

            executor = OsqueryExecutor()
            raw_results = executor.discover_all()

            flat_rows = []
            for rows in raw_results.values():
                if isinstance(rows, list):
                    flat_rows.extend(rows)

            layer4_json.write_text(json.dumps({"data": flat_rows}, indent=2))
            new_findings = CorrelationEngine.load_layer4_findings(layer4_json)
            if not daemon:
                with findings_lock:
                    layer4_findings = new_findings
        except Exception as e:
            console.print(f"[red]Layer 4 endpoint scan failed:[/red] {e}")

    def run_correlation_once() -> dict:
        if daemon:
            # Load from files each cycle to avoid accumulating findings in memory
            cf = CorrelationEngine.load_code_findings(layer1_sarif) if layer1_sarif.exists() else []
            nf = CorrelationEngine.load_network_findings(layer2_json)
            l3 = CorrelationEngine.load_layer3_findings(layer3_jsonl) if layer3_jsonl.exists() else []
            l4 = CorrelationEngine.load_layer4_findings(layer4_json) if layer4_json.exists() else []
        else:
            with findings_lock:
                cf = list(code_findings)
                nf = list(network_findings)
                l3 = list(layer3_findings)
                l4 = list(layer4_findings)
        # Merge layer2 findings + connections so correlate gets full network data
        try:
            if layer2_json.exists():
                layer2_data = json.loads(layer2_json.read_text())
                nf = (layer2_data.get("findings") or []) + (
                    layer2_data.get("connections") or []
                )
        except Exception:
            pass
        console.print("[bold cyan]🔗 Correlating findings...[/bold cyan]\n")
        inventory = CorrelationEngine.correlate(
            code_findings=cf,
            network_findings=nf,
            layer4_findings=l4,
            layer3_findings=l3,
            known_apps=known_apps,
        )
        console.print("[dim]✓ Correlation complete[/dim]\n")
        # Daemon: preserve first-seen (discovered_at) from previous inventory
        previous_discovered_at = None
        if daemon and inventory_path.exists():
            try:
                prev = json.loads(inventory_path.read_text())
                previous_discovered_at = {}
                gen = prev.get("generated_at") or ""
                for items in (prev.get("inventory") or {}).values():
                    for item in items:
                        aid = item.get("agent_id")
                        if aid:
                            previous_discovered_at[aid] = item.get("discovered_at") or gen
            except (json.JSONDecodeError, OSError):
                pass
        report = CorrelationEngine.generate_report(
            inventory, inventory_path, previous_discovered_at=previous_discovered_at
        )
        # Daemon: append one-line summary to history timeline
        if daemon:
            history_path = inventory_path.parent / "agent_inventory_history.jsonl"
            try:
                    with open(history_path, "a") as f:
                        f.write(
                            json.dumps(
                                {
                                    "timestamp": report["generated_at"],
                                    "confirmed": report["summary"]["confirmed"],
                                    "ghost": report["summary"]["ghost"],
                                    "unknown": report["summary"]["unknown"],
                                    "zombie": report["summary"].get("zombie", 0),
                                    "shadow_ai_usage": report["summary"].get("shadow_ai_usage", 0),
                                }
                            )
                            + "\n"
                        )
            except OSError:
                pass
        return report

    # Non-daemon: run once with layers in parallel
    hra_result: dict = {}
    if not daemon:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            # Fast tasks: Layer 1 + 4
            futures.append(executor.submit(run_layer1_once))
            futures.append(executor.submit(run_layer4_once))
            # Long-running tasks: Layer 2 + 3
            futures.append(executor.submit(run_layer2_once))
            futures.append(executor.submit(run_layer3_once))
            wait(futures)

        from agent_discover_scanner.high_risk_agents import detect_all_high_risk_agents

        try:
            hra_result = detect_all_high_risk_agents(
                layer4_findings=layer4_findings,
                network_findings=network_findings,
            )
            if hra_result.get("is_high_risk"):
                for finding in hra_result.get("findings", []):
                    confidence = finding.get("confidence", "medium")
                    if confidence == "confirmed":
                        console.print(
                            f"\n[bold red]🚨 HIGH-RISK AGENT CONFIRMED: "
                            f"{finding['display_name']}[/bold red]"
                        )
                        console.print(f"[red]   {finding['description']}[/red]")
                        console.print(
                            f"[red]   Capabilities: "
                            f"{', '.join(finding.get('capabilities', []))}[/red]\n"
                        )
                    elif confidence == "high":
                        console.print(
                            f"\n[yellow]⚠ HIGH-RISK AGENT DETECTED (high confidence): "
                            f"{finding['display_name']}[/yellow]"
                        )
                        console.print(
                            f"[yellow]   {finding['description']}[/yellow]\n"
                        )
        except Exception:
            hra_result = {}

        from agent_discover_scanner.mcp_detector import detect_mcp_servers

        try:
            mcp_result = detect_mcp_servers(
                scan_dir=str(scan_root),
                network_findings=network_findings,
                layer4_findings=layer4_findings,
            )
            if mcp_result.get("servers"):
                if mcp_result.get("has_local_scripts"):
                    console.print(
                        "[bold red]⚠ Local MCP script detected — "
                        "unknown code with tool access[/bold red]"
                    )
                unverified = [
                    s
                    for s in mcp_result.get("servers", [])
                    if not s.get("publisher_verified") and not s.get("is_local_script")
                ]
                for s in unverified[:3]:
                    console.print(
                        f"[yellow]⚠ Unverified MCP server: "
                        f"{s.get('server_name', '?')} "
                        f"({s.get('vendor', 'unknown vendor')}) — "
                        f"not from a verified publisher[/yellow]"
                    )
                if mcp_result.get("network_detected"):
                    console.print(
                        "[dim]  ℹ MCP connections detected via network — "
                        "likely configured via AI client UI "
                        "(no local config file)[/dim]"
                    )
        except Exception:
            mcp_result = {}

        report = run_correlation_once()
        if platform:
            try:
                network_for_upload = network_findings or []
                try:
                    if layer2_json.exists():
                        data = json.loads(layer2_json.read_text())
                        network_for_upload = (data.get("findings") or []) + (
                            data.get("connections") or []
                        )
                except Exception:
                    pass
                upload_scan_results(
                    report,
                    hostname=socket.gethostname(),
                    api_key=api_key,
                    tenant_token=tenant_token,
                    wawsdb_url=wawsdb_url,
                    network_findings=network_for_upload,
                    layer4_findings=layer4_findings,
                    high_risk_agent=hra_result,
                    mcp_result=mcp_result,
                    scan_dir=str(scan_root),
                )
            except Exception:
                logger.warning("DefendAI platform upload failed unexpectedly", exc_info=True)
    else:
        # Daemon mode: run layers continuously and update correlation
        console.print("[bold yellow]Daemon mode enabled: running continuous monitoring[/bold yellow]\n")
        if platform:
            interval_sec = max(1, platform_interval) * 30
            console.print(
                f"[dim]Platform sync every {interval_sec}s "
                f"({max(1, platform_interval)} correlation cycles)[/dim]\n"
            )

        def signal_handler(signum, frame):
            console.print(f"\n[yellow]Received signal {signum}, shutting down daemon...[/yellow]")
            stop_event.set()

        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        except ValueError:
            # Signal handling may not be available in some environments (e.g. Windows)
            pass

        # Daemon log rotation: all daemon output to a rotating file (20MB, 3 backups)
        daemon_log_path = output_dir / "daemon.log"
        daemon_log_handler = RotatingFileHandler(
            daemon_log_path,
            maxBytes=_DAEMON_LOG_MAX_BYTES,
            backupCount=_DAEMON_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        daemon_log_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        logger.addHandler(daemon_log_handler)
        logger.setLevel(logging.INFO)

        def _check_disk_and_maybe_pause() -> None:
            try:
                free = shutil.disk_usage(output_dir).free
                if free < _DAEMON_DISK_CRITICAL_BYTES:
                    pause_layer3_logging[0] = True
                    logger.warning(
                        "Low disk space: %.0fMB remaining; pausing Layer 3 logging",
                        free / 1024 / 1024,
                    )
                elif free < _DAEMON_DISK_WARN_BYTES:
                    logger.warning(
                        "Low disk space: %.0fMB remaining",
                        free / 1024 / 1024,
                    )
                elif free > _DAEMON_DISK_RESUME_BYTES:
                    pause_layer3_logging[0] = False
            except Exception as e:
                logger.exception("Disk check failed: %s", e)

        _check_disk_and_maybe_pause()  # at startup

        def disk_check_daemon() -> None:
            while not stop_event.is_set():
                if stop_event.wait(3600):  # wait 1 hour or until stop
                    break
                _check_disk_and_maybe_pause()

        disk_check_thread = threading.Thread(
            target=disk_check_daemon, name="disk-check-daemon", daemon=True
        )
        disk_check_thread.start()

        def layer1_daemon():
            backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
            try:
                while not stop_event.is_set():
                    try:
                        # Try to use watchdog if available for faster updates, otherwise poll every 5 minutes
                        try:
                            from watchdog.events import FileSystemEventHandler
                            from watchdog.observers import Observer

                            class ChangeHandler(FileSystemEventHandler):
                                def on_any_event(self, event):
                                    if stop_event.is_set():
                                        return
                                    run_layer1_once()

                            observer = Observer()
                            handler = ChangeHandler()
                            observer.schedule(handler, str(scan_root), recursive=True)
                            observer.start()
                            try:
                                while not stop_event.is_set():
                                    time.sleep(1)
                            finally:
                                observer.stop()
                                observer.join()
                        except ImportError:
                            # Fallback: periodic rescan every 5 minutes
                            while not stop_event.is_set():
                                run_layer1_once()
                                if stop_event.wait(300):
                                    break
                        backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
                    except Exception as e:
                        logger.exception(
                            "Layer 1 daemon error (will retry in %ss): %s",
                            backoff_sec,
                            e,
                            exc_info=True,
                        )
                        if stop_event.wait(backoff_sec):
                            break
                        backoff_sec = min(backoff_sec * 2, _DAEMON_BACKOFF_MAX_SEC)
            except Exception as e:
                logger.exception("Layer 1 daemon crashed: %s", e, exc_info=True)

        def layer2_daemon():
            backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
            try:
                while not stop_event.is_set():
                    try:
                        run_layer2_once()
                        backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
                    except Exception as e:
                        logger.exception(
                            "Layer 2 daemon error (will retry in %ss): %s",
                            backoff_sec,
                            e,
                            exc_info=True,
                        )
                        if stop_event.wait(backoff_sec):
                            break
                        backoff_sec = min(backoff_sec * 2, _DAEMON_BACKOFF_MAX_SEC)
                        continue
                    if stop_event.wait(duration):
                        break
            except Exception as e:
                logger.exception("Layer 2 daemon crashed: %s", e, exc_info=True)

        def layer3_daemon():
            backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
            try:
                while not stop_event.is_set():
                    try:
                        run_layer3_once()
                        backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
                    except Exception as e:
                        logger.exception(
                            "Layer 3 daemon error (will retry in %ss): %s",
                            backoff_sec,
                            e,
                            exc_info=True,
                        )
                        if stop_event.wait(backoff_sec):
                            break
                        backoff_sec = min(backoff_sec * 2, _DAEMON_BACKOFF_MAX_SEC)
                        continue
                    if stop_event.wait(duration):
                        break
            except Exception as e:
                logger.exception("Layer 3 daemon crashed: %s", e, exc_info=True)

        def layer4_daemon():
            backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
            try:
                while not stop_event.is_set():
                    try:
                        run_layer4_once()
                        backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
                    except Exception as e:
                        logger.exception(
                            "Layer 4 daemon error (will retry in %ss): %s",
                            backoff_sec,
                            e,
                            exc_info=True,
                        )
                        if stop_event.wait(backoff_sec):
                            break
                        backoff_sec = min(backoff_sec * 2, _DAEMON_BACKOFF_MAX_SEC)
                        continue
                    if stop_event.wait(60):
                        break
            except Exception as e:
                logger.exception("Layer 4 daemon crashed: %s", e, exc_info=True)

        def correlation_daemon():
            last_report_json = None
            last_uploaded_hash = ""
            backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
            cycle_count = 0
            upload_interval = max(1, platform_interval)
            try:
                while not stop_event.is_set():
                    try:
                        report_local = run_correlation_once()
                        cycle_count += 1

                        # Upload every N cycles if platform enabled (only when inventory changed)
                        if platform and cycle_count % upload_interval == 0:
                            current_hash = _inventory_hash(report_local)
                            if current_hash and current_hash == last_uploaded_hash:
                                logger.info(
                                    "Inventory unchanged — skipping upload (cycle %d)",
                                    cycle_count,
                                )
                                console.print(
                                    f"[dim]↩ No changes detected — platform sync skipped "
                                    f"(cycle {cycle_count})[/dim]"
                                )
                            else:
                                try:
                                    network_for_upload = []
                                    try:
                                        if layer2_json.exists():
                                            data = json.loads(layer2_json.read_text())
                                            network_for_upload = (data.get("findings") or []) + (
                                                data.get("connections") or []
                                            )
                                    except Exception:
                                        pass
                                    l4 = (
                                        CorrelationEngine.load_layer4_findings(layer4_json)
                                        if layer4_json.exists()
                                        else []
                                    )
                                    try:
                                        from agent_discover_scanner.high_risk_agents import (
                                            detect_all_high_risk_agents,
                                        )
                                        hra_upload = detect_all_high_risk_agents(
                                            layer4_findings=l4,
                                            network_findings=network_for_upload,
                                        )
                                    except Exception:
                                        hra_upload = {}
                                    try:
                                        from agent_discover_scanner.mcp_detector import (
                                            detect_mcp_servers,
                                        )
                                        mcp_upload = detect_mcp_servers(
                                            scan_dir=str(scan_root),
                                            network_findings=network_for_upload,
                                            layer4_findings=l4,
                                        )
                                    except Exception:
                                        mcp_upload = {}
                                    upload_scan_results(
                                        report_local,
                                        hostname=socket.gethostname(),
                                        api_key=api_key,
                                        tenant_token=tenant_token,
                                        wawsdb_url=wawsdb_url,
                                        network_findings=network_for_upload,
                                        layer4_findings=l4,
                                        high_risk_agent=hra_upload,
                                        mcp_result=mcp_upload,
                                        scan_dir=str(scan_root),
                                    )
                                    last_uploaded_hash = current_hash
                                    logger.info(
                                        "Platform upload completed (cycle %d)",
                                        cycle_count,
                                    )
                                except Exception as e:
                                    logger.warning(
                                        "Platform upload failed (cycle %d): %s",
                                        cycle_count,
                                        e,
                                    )
                                    # Don't update last_uploaded_hash on failure so next cycle retries

                        if scan_output_format == "json":
                            current_json = json.dumps(report_local, sort_keys=True)
                        else:
                            current_json = None

                        # Only print full JSON if user requested; file is always written by run_correlation_once
                        if scan_output_format == "json" and current_json != last_report_json:
                            console.print(current_json)
                            last_report_json = current_json

                        backoff_sec = _DAEMON_BACKOFF_INITIAL_SEC
                    except Exception as e:
                        logger.exception(
                            "Correlation daemon error (will retry in %ss): %s",
                            backoff_sec,
                            e,
                            exc_info=True,
                        )
                        if stop_event.wait(backoff_sec):
                            break
                        backoff_sec = min(backoff_sec * 2, _DAEMON_BACKOFF_MAX_SEC)
                        continue
                    if stop_event.wait(30):
                        break
            except Exception as e:
                logger.exception("Correlation daemon crashed: %s", e, exc_info=True)

        threads = [
            threading.Thread(target=layer1_daemon, name="layer1-daemon", daemon=True),
            threading.Thread(target=layer2_daemon, name="layer2-daemon", daemon=True),
            threading.Thread(target=layer3_daemon, name="layer3-daemon", daemon=True),
            threading.Thread(target=layer4_daemon, name="layer4-daemon", daemon=True),
            threading.Thread(target=correlation_daemon, name="correlator-daemon", daemon=True),
        ]

        for t in threads:
            t.start()

        try:
            # Wait until stop_event is set
            while not stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()
        finally:
            # Give threads a moment to shut down gracefully
            time.sleep(2)
            if daemon_log_handler:
                logger.removeHandler(daemon_log_handler)
                daemon_log_handler.close()
        # After daemon shutdown, print one final summary and optionally attempt upload once
        report = run_correlation_once()
        if platform:
            try:
                upload_scan_results(
                    report,
                    hostname=socket.gethostname(),
                    api_key=api_key,
                    tenant_token=tenant_token,
                    wawsdb_url=wawsdb_url,
                    high_risk_agent=None,
                    mcp_result=None,
                    scan_dir=str(scan_root),
                )
            except Exception:
                logger.warning("DefendAI platform upload failed unexpectedly", exc_info=True)

    # Final summary table
    console.print("\n[bold cyan]🤖 Autonomous Agent Inventory[/bold cyan]\n")

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Classification", style="cyan")
    summary_table.add_column("Count", style="green")
    summary_table.add_column("Description", style="dim")

    summary_table.add_row(
        "CONFIRMED",
        str(report["summary"]["confirmed"]),
        "Active — detected in code and observed at runtime",
    )
    summary_table.add_row(
        "UNKNOWN",
        str(report["summary"]["unknown"]),
        "Code found — not yet observed at runtime",
    )
    summary_table.add_row(
        "SHADOW AI",
        str(report["summary"].get("shadow_ai_usage", 0)),
        "Known app using AI — review for governance",
    )
    summary_table.add_row(
        "ZOMBIE",
        str(report["summary"].get("zombie", 0)),
        "Inactive — code exists but no recent runtime activity",
    )
    summary_table.add_row(
        "GHOST",
        f"[red]{report['summary']['ghost']}[/red]",
        "[red]⚠ Critical — runtime activity with no source code (ungoverned)[/red]",
    )

    console.print(summary_table)

    # Risk breakdown
    console.print("\n[bold]Risk Breakdown:[/bold]")
    rb = report["risk_breakdown"]
    console.print(f"  [red]●[/red] Critical: {rb.get('critical', 0)}")
    console.print(f"  [yellow]●[/yellow] High: {rb.get('high', 0)}")
    console.print(f"  [blue]●[/blue] Medium: {rb.get('medium', 0)}")
    console.print(f"  [green]●[/green] Low: {rb.get('low', 0)}")

    # Detection coverage by layer combination
    coverage = report["summary"].get("detection_coverage", {})
    if coverage:
        console.print("\n[bold]Detection Coverage by Layer Combination:[/bold]")
        cov_table = Table(show_header=True, header_style="bold magenta")
        cov_table.add_column("Layers", style="cyan")
        cov_table.add_column("Agents", style="green")

        for layers, count in sorted(coverage.items(), key=lambda x: (-x[1], x[0])):
            cov_table.add_row(layers or "none", str(count))

        console.print(cov_table)

    console.print(f"\n[green]✅ Scan complete — results saved to {output_dir}[/green]\n")

    if scan_output_format == "json":
        console.print(json.dumps(report, indent=2))


    return report
