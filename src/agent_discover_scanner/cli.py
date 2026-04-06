import ast
import json
import logging
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agent_discover_scanner.errors import (
    ValidationError,
    show_no_findings_help,
    show_setup_help,
    validate_directory_exists,
    validate_file_exists,
)
from agent_discover_scanner.js_signatures import JavaScriptAgentDetector
from agent_discover_scanner.sarif_output import SARIFGenerator
from agent_discover_scanner.sbom_analyzer import (
    analyze_package_json,
    analyze_requirements_txt,
)
from agent_discover_scanner.scanner import Scanner
from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
from agent_discover_scanner.visitor import ContextAwareVisitor
from agent_discover_scanner.platform import upload_scan_results

#layer4 imports
from agent_discover_scanner.layer4.osquery_executor import OsqueryExecutor
from agent_discover_scanner.layer4.result_parser import OsqueryResultParser
from agent_discover_scanner.reports.layer4_report import Layer4Report
from agent_discover_scanner.monitors.k8s_monitor import K8sAPIMonitor
import socket

__version__ = _pkg_version("agent-discover-scanner")
logger = logging.getLogger(__name__)

app = typer.Typer(help="AgentDiscover Scanner: Detect Autonomous AI Agents and Shadow AI")
console = Console()


def version_callback(value: Optional[bool]) -> None:
    """
    Global --version / -v option callback.
    """
    if not value:
        return
    console.print(f"AgentDiscover Scanner v{__version__}")
    raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        is_eager=True,
        help="Show version and exit",
        callback=version_callback,
    ),
) -> None:
    # Main app callback (no-op; used only for global options like --version)
    return


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the repository to scan"),
    output: str = typer.Option("results.sarif", help="Output SARIF file path"),
    format: str = typer.Option(
        "table",
        help="Output format: sarif, table, text (alias for table), or both",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
):
    """
    Scan source code for AI agents and Shadow AI patterns.
    """
    console.print(f"[bold green]📂 Analyzing source code at {path}[/bold green]\n")

    # Validate input
    try:
        scan_root = validate_directory_exists(path, "Scan directory")
    except ValidationError:
        raise typer.Exit(code=1)

    scan_fmt = format.strip().lower()
    if scan_fmt == "text":
        scan_fmt = "table"
    if scan_fmt not in ("sarif", "table", "both"):
        console.print("[red]Invalid --format; use sarif, table, text, or both[/red]")
        raise typer.Exit(code=1)

    # Initialize scanner
    scanner = Scanner(scan_root)

    # Track statistics
    files_scanned = 0
    total_findings = 0
    all_findings = []
    all_imports = set()

    # Findings by severity and language
    findings_by_severity = {"error": 0, "warning": 0, "note": 0}
    files_by_language = {"python": 0, "javascript": 0}

    try:
        # Scan all files
        for file_path in scanner.scan():
            files_scanned += 1

            if verbose:
                console.print(f"[dim]Scanning: {file_path}[/dim]")

            try:
                source_code = file_path.read_text(encoding="utf-8")

                # Determine file type and use appropriate scanner
                if file_path.suffix == ".py":
                    files_by_language["python"] += 1
                    # Python AST analysis
                    tree = ast.parse(source_code, filename=str(file_path))
                    visitor = ContextAwareVisitor(file_path, signature_registry=SIGNATURE_REGISTRY)
                    visitor.visit(tree)

                    total_findings += len(visitor.findings)
                    all_findings.extend(visitor.findings)
                    all_imports.update(visitor.imports)

                    # Count by severity
                    for finding in visitor.findings:
                        findings_by_severity[finding.severity] += 1

                    # Show findings
                    if visitor.findings and scan_fmt in ["table", "both"]:
                        for finding in visitor.findings:
                            severity_color = {
                                "error": "red",
                                "warning": "yellow",
                                "note": "blue",
                            }.get(finding.severity, "white")

                            console.print(f"  [{severity_color}]●[/{severity_color}] {finding}")

                elif file_path.suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs"}:
                    files_by_language["javascript"] += 1
                    # JavaScript/TypeScript analysis
                    js_detector = JavaScriptAgentDetector(file_path)
                    findings = js_detector.scan_file(source_code)

                    total_findings += len(findings)
                    all_findings.extend(findings)
                    all_imports.update(js_detector.imports)

                    # Count by severity
                    for finding in findings:
                        findings_by_severity[finding.severity] += 1

                    # Show findings
                    if findings and scan_fmt in ["table", "both"]:
                        for finding in findings:
                            severity_color = {
                                "error": "red",
                                "warning": "yellow",
                                "note": "blue",
                            }.get(finding.severity, "white")

                            console.print(f"  [{severity_color}]●[/{severity_color}] {finding}")

            except SyntaxError as e:
                if verbose:
                    console.print(f"[red]Syntax error in {file_path}: {e}[/red]")
            except Exception as e:
                if verbose:
                    console.print(f"[red]Error processing {file_path}: {e}[/red]")

        # Check if we scanned any files
        if files_scanned == 0:
            console.print("[yellow]⚠️  No Python or JavaScript files found[/yellow]")
            console.print("[dim]Supported extensions: .py, .js, .ts, .jsx, .tsx, .mjs[/dim]")
            raise typer.Exit(code=0)

        # Generate SARIF output if requested
        if scan_fmt in ["sarif", "both"]:
            output_path = Path(output)
            SARIFGenerator.write_sarif(all_findings, scan_root, output_path)

        # Display summary table if requested
        if scan_fmt in ["table", "both"]:
            console.print("\n[bold cyan]Scan Complete![/bold cyan]")

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Files Scanned", str(files_scanned))
            table.add_row("  • Python", str(files_by_language["python"]))
            table.add_row("  • JavaScript/TypeScript", str(files_by_language["javascript"]))
            table.add_row("Total Findings", str(total_findings))
            table.add_row("  • Errors", f"[red]{findings_by_severity['error']}[/red]")
            table.add_row("  • Warnings", f"[yellow]{findings_by_severity['warning']}[/yellow]")
            table.add_row("  • Notes", f"[blue]{findings_by_severity['note']}[/blue]")
            table.add_row("Unique Imports", str(len(all_imports)))

            console.print(table)

            # Show summary of findings by rule
            if all_findings:
                console.print("\n[bold]Findings by Rule:[/bold]")
                findings_by_rule = {}
                for finding in all_findings:
                    if finding.rule_id not in findings_by_rule:
                        findings_by_rule[finding.rule_id] = []
                    findings_by_rule[finding.rule_id].append(finding)

                for rule_id, findings in sorted(findings_by_rule.items()):
                    console.print(f"  {rule_id}: {len(findings)} finding(s)")
            else:
                show_no_findings_help("agents")

            # Show unique imports if verbose
            if verbose and all_imports:
                console.print("\n[bold]Discovered Imports:[/bold]")
                for imp in sorted(all_imports)[:20]:
                    console.print(f"  • {imp}")
                if len(all_imports) > 20:
                    console.print(f"  ... and {len(all_imports) - 20} more")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=130)

    except typer.Exit:
        # Re-raise typer exits (not actual errors)
        raise
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if verbose:
            import traceback

            console.print(traceback.format_exc())
        show_setup_help()
        raise typer.Exit(code=1)


@app.command()
def deps(
    path: str = typer.Argument(..., help="Path to scan for dependencies"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
):
    """
    Scan dependencies (requirements.txt, package.json) for AI/ML frameworks.
    """
    console.print(f"[bold green]Scanning dependencies in: {path}[/bold green]\n")

    # Validate input
    try:
        scan_path = validate_directory_exists(path, "Scan directory")
    except ValidationError:
        raise typer.Exit(code=1)

    all_findings = []

    # Scan requirements.txt
    req_file = scan_path / "requirements.txt"
    if req_file.exists():
        console.print("[cyan]Analyzing requirements.txt...[/cyan]")
        findings = analyze_requirements_txt(req_file)
        all_findings.extend(findings)

        if verbose:
            for finding in findings:
                risk_color = "red" if finding.risk_level == "high" else "yellow"
                console.print(
                    f"  [{risk_color}]●[/{risk_color}] {finding.package_name} ({finding.version}) - {finding.reason}"
                )

    # Scan package.json
    pkg_file = scan_path / "package.json"
    if pkg_file.exists():
        console.print("[cyan]Analyzing package.json...[/cyan]")
        findings = analyze_package_json(pkg_file)
        all_findings.extend(findings)

        if verbose:
            for finding in findings:
                risk_color = "red" if finding.risk_level == "high" else "yellow"
                console.print(
                    f"  [{risk_color}]●[/{risk_color}] {finding.package_name} ({finding.version}) - {finding.reason}"
                )

    # Check if we found any dependency files
    if not req_file.exists() and not pkg_file.exists():
        console.print("[yellow]⚠️  No dependency files found[/yellow]")
        console.print("[dim]Looked for: requirements.txt, package.json[/dim]")
        show_no_findings_help("dependencies")
        raise typer.Exit(code=0)

    # Summary
    console.print("\n[bold cyan]Dependency Scan Complete![/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    high_risk = sum(1 for f in all_findings if f.risk_level == "high")
    medium_risk = sum(1 for f in all_findings if f.risk_level == "medium")

    table.add_row("Total Risky Dependencies", str(len(all_findings)))
    table.add_row("  • High Risk (Agent Frameworks)", f"[red]{high_risk}[/red]")
    table.add_row("  • Medium Risk (LLM Clients)", f"[yellow]{medium_risk}[/yellow]")

    console.print(table)

    if all_findings:
        console.print("\n[bold]Detected Frameworks:[/bold]")
        for finding in all_findings:
            risk_color = "red" if finding.risk_level == "high" else "yellow"
            console.print(
                f"  [{risk_color}]●[/{risk_color}] {finding.package_name} - {finding.reason}"
            )
    else:
        show_no_findings_help("dependencies")


@app.command()
def monitor(
    duration: int = typer.Option(60, help="Duration to monitor in seconds"),
    output: str = typer.Option("network-findings.json", help="Output JSON file"),
):
    """
    Monitor network traffic for active AI agent connections.

    Uses psutil to detect active connections to AI services and vector databases.
    Detects RAG patterns when both AI services and vector DBs are used together.
    """
    from agent_discover_scanner.network_monitor import NetworkMonitor

    console.print("[bold green]🌐 Monitoring live network connections...[/bold green]\n")
    console.print(f"[cyan]   Observing runtime behavior ({duration}s)...[/cyan]\n")
    console.print("[cyan]Detecting connections to:[/cyan]")
    console.print("  • AI Services (OpenAI, Anthropic, Google AI, etc.)")
    console.print("  • Vector Databases (Pinecone, Weaviate, Qdrant, etc.)")
    console.print("  • RAG Patterns (AI + Vector DB combinations)\n")

    try:
        monitor = NetworkMonitor()
        summary = monitor.monitor(duration_seconds=duration)
        
        # Save report
        monitor.save_report(summary, Path(output))
        
    except ImportError:
        console.print("[red]❌ Error: psutil not installed[/red]")
        console.print("\n[yellow]💡 Install psutil:[/yellow]")
        console.print("  [cyan]pip install psutil[/cyan]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]❌ Monitoring error:[/red] {e}")
        if "AccessDenied" in str(e) or "permission" in str(e).lower():
            console.print("\n[yellow]💡 Tip: You may need elevated permissions to monitor network connections[/yellow]")
        raise typer.Exit(code=1)

    # Display results with Rich formatting
    console.print("\n[bold cyan]Network Monitoring Complete![/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Scan Duration", f"{summary['scan_duration']}s")
    table.add_row("Total Connections", str(summary["total_connections"]))
    table.add_row(
        "Unique Services",
        ", ".join(summary["unique_services"]) if summary["unique_services"] else "None",
    )
    table.add_row("RAG Patterns Detected", f"[red]{len(summary['rag_patterns'])}[/red]")

    console.print(table)

    if summary["services"]:
        console.print("\n[bold]Connections by Service:[/bold]")
        for service, count in sorted(summary["services"].items(), key=lambda x: x[1], reverse=True):
            console.print(f"  [yellow]●[/yellow] {service}: {count}")

    if summary["processes"]:
        console.print("\n[bold]Connections by Process:[/bold]")
        for process, count in sorted(summary["processes"].items(), key=lambda x: x[1], reverse=True):
            console.print(f"  [cyan]●[/cyan] {process}: {count}")

    if summary["rag_patterns"]:
        console.print("\n[bold red]🚨 RAG Patterns Detected![/bold red]")
        console.print("[red]Processes using both AI services and vector databases:[/red]")
        for pattern in summary["rag_patterns"]:
            console.print(f"\n  [yellow]Process:[/yellow] {pattern['process']} (PID: {pattern['pid']})")
            console.print(f"  [yellow]AI Services:[/yellow] {', '.join(pattern['ai_services'])}")
            console.print(f"  [yellow]Vector DBs:[/yellow] {', '.join(pattern['vector_dbs'])}")
            console.print(f"  [yellow]Confidence:[/yellow] {pattern['confidence']}")

    console.print(f"\n[green]✓ Results saved to: {output}[/green]")


@app.command()
def correlate(
    code_scan: str = typer.Option(..., help="Path to code scan SARIF file"),
    network_scan: str = typer.Option("network-findings.json", help="Path to network findings JSON"),
    output: str = typer.Option("agent-inventory.json", help="Output inventory JSON file"),
):
    """
    Correlate code and network findings to create unified agent inventory.

    Detects:
    - CONFIRMED: Agents found in code AND running
    - UNKNOWN: Agents in code but not yet active
    - GHOST: Active agents with NO code found (CRITICAL)
    """
    from agent_discover_scanner.correlator import CorrelationEngine
    from agent_discover_scanner.known_apps import build_known_apps

    console.print("[bold green]Correlating findings...[/bold green]\n")

    # Validate inputs
    try:
        code_scan_path = validate_file_exists(code_scan, "Code scan SARIF file")
        network_scan_path = validate_file_exists(network_scan, "Network scan JSON file")
    except ValidationError:
        raise typer.Exit(code=1)

    # Load findings
    code_findings = CorrelationEngine.load_code_findings(code_scan_path)
    network_findings = CorrelationEngine.load_network_findings(network_scan_path)

    console.print("[cyan]Loaded:[/cyan]")
    console.print(f"  • Code findings: {len(code_findings)}")
    console.print(f"  • Network findings: {len(network_findings)}\n")

    # Correlate
    known_apps = build_known_apps()
    inventory = CorrelationEngine.correlate(
        code_findings, network_findings, known_apps=known_apps
    )

    # Behavioral analysis
    if network_findings:
        console.print("[bold cyan]Analyzing Behavioral Patterns...[/bold cyan]")
        behavioral = CorrelationEngine.analyze_behaviors(network_findings)

        if behavioral["summary"]["total_patterns"] > 0:
            console.print("\n[bold]Detected Behavioral Patterns:[/bold]")
            console.print(f"  • ReAct Loops: {behavioral['summary']['react_loops']}")
            console.print(f"  • RAG Patterns: {behavioral['summary']['rag_patterns']}")
            console.print(f"  • Multi-turn Conversations: {behavioral['summary']['multi_turn']}")

            # Show details
            for pattern_type, pattern_list in behavioral["patterns"].items():
                if pattern_list:
                    console.print(f"\n[yellow]{pattern_type.upper().replace('_', ' ')}:[/yellow]")
                    for pattern in pattern_list:
                        console.print(f"  [green]✓[/green] {pattern['description']}")
                        for indicator in pattern["indicators"]:
                            console.print(f"    - {indicator}")

    # Generate report
    report = CorrelationEngine.generate_report(inventory, Path(output))

    # Display results
    console.print("\n[bold cyan]Correlation Complete![/bold cyan]\n")

    # Summary table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Classification", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Description", style="dim")

    table.add_row("CONFIRMED", str(report["summary"]["confirmed"]), "Code + Network (Active)")
    table.add_row("UNKNOWN", str(report["summary"]["unknown"]), "Code Only (Not Yet Active)")
    table.add_row(
        "SHADOW AI",
        str(report["summary"].get("shadow_ai_usage", 0)),
        "Known app using AI — review for governance",
    )
    table.add_row("ZOMBIE", str(report["summary"]["zombie"]), "Code But No Traffic (Deprecated)")
    table.add_row(
        "GHOST",
        f"[red]{report['summary']['ghost']}[/red]",
        "[red]Traffic But No Code (CRITICAL)[/red]",
    )

    console.print(table)

    # Risk breakdown
    console.print("\n[bold]Risk Breakdown:[/bold]")
    console.print(f"  [red]●[/red] Critical: {report['risk_breakdown']['critical']}")
    console.print(f"  [yellow]●[/yellow] High: {report['risk_breakdown']['high']}")
    console.print(f"  [blue]●[/blue] Medium: {report['risk_breakdown']['medium']}")

    # Ghost agent warnings
    if inventory["ghost"]:
        console.print("\n[bold red]⚠️  GHOST AGENTS DETECTED![/bold red]")
        console.print("[red]Active agents with NO corresponding code found:[/red]")
        for ghost in inventory["ghost"]:
            console.print(f"  • Provider: {ghost.network_provider}")
            console.print(f"    Process: {ghost.process_name}")
            console.print(f"    Last Seen: {ghost.last_seen}\n")

    console.print(f"\n[green]✓ Inventory saved to: {output}[/green]")


@app.command("scan-all")
def scan_all(
    path: str = typer.Argument(..., help="Directory to scan"),
    duration: int = typer.Option(
        60,
        "--duration",
        "-d",
        help="Network and K8s monitor observation window in seconds",
    ),
    output: Path = typer.Option(
        Path("defendai-results"),
        "--output",
        "-o",
        help="Output directory for scan results",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Console summary: text (default) or json (print final inventory JSON). Layer 1 code output remains SARIF on disk.",
    ),
    layer3_file: Optional[Path] = typer.Option(
        None,
        "--layer3-file",
        help="Optional path to existing Tetragon JSONL output (skip live monitor-k8s if provided)",
    ),
    skip_layers: Optional[str] = typer.Option(
        None,
        "--skip-layers",
        help="Comma-separated layers to skip, e.g. '3' or '2,3'",
    ),
    daemon: bool = typer.Option(
        False,
        "--daemon",
        help="Run continuously, re-scanning every 30 seconds",
    ),
    max_log_size: int = typer.Option(
        50,
        "--max-log-size",
        help="Rotate layer2/layer3 output files when they exceed this size in MB",
    ),
    max_log_backups: int = typer.Option(
        5,
        "--max-log-backups",
        help="Number of rotated backup files to keep for layer2/layer3",
    ),
    platform: bool = typer.Option(
        False,
        "--platform",
        help="Upload results to DefendAI platform after scan",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="DefendAI platform API key",
    ),
    tenant_token: Optional[str] = typer.Option(
        None,
        "--tenant-token",
        help="DefendAI platform tenant token",
    ),
    wawsdb_url: str = typer.Option(
        "https://wauzeway.defendai.ai",
        "--wawsdb-url",
        help="DefendAI platform base URL",
    ),
    platform_interval: int = typer.Option(
        5,
        "--platform-interval",
        help="Upload to platform every N correlation cycles in daemon mode (default: 5)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including Layer 3/Kubernetes errors",
    ),
    layer: Optional[str] = typer.Option(
        None,
        "--layer",
        help="Run a single facet only: code, network, k8s, endpoint, or mcp (not with --daemon)",
    ),
):
    """
    Run a full 4-layer AI agent scan, correlate all findings,
    and optionally upload results to the DefendAI platform.
    """
    from agent_discover_scanner.scan_runner import execute_scan_all

    execute_scan_all(
        path=path,
        output=output,
        duration=duration,
        layer3_file=layer3_file,
        skip_layers=skip_layers,
        daemon=daemon,
        max_log_size=max_log_size,
        max_log_backups=max_log_backups,
        platform=platform,
        api_key=api_key,
        tenant_token=tenant_token,
        wawsdb_url=wawsdb_url,
        platform_interval=platform_interval,
        verbose=verbose,
        scan_output_format=format,
        layer=layer,
    )


@app.command()
def audit(
    path: str = typer.Argument(..., help="Directory to scan"),
    output: Path = typer.Option(
        Path("defendai-audit"),
        "--output",
        "-o",
        help="Audit bundle root directory (scan artifacts under raw/)",
    ),
    duration: int = typer.Option(
        60,
        "--duration",
        "-d",
        help="Network and K8s monitor observation window in seconds",
    ),
    layer3_file: Optional[Path] = typer.Option(
        None,
        "--layer3-file",
        help="Optional path to existing Tetragon JSONL output (skip live monitor-k8s if provided)",
    ),
    skip_layers: Optional[str] = typer.Option(
        None,
        "--skip-layers",
        help="Comma-separated layers to skip, e.g. '3' or '2,3'",
    ),
    max_log_size: int = typer.Option(
        50,
        "--max-log-size",
        help="Rotate layer2/layer3 output files when they exceed this size in MB",
    ),
    max_log_backups: int = typer.Option(
        5,
        "--max-log-backups",
        help="Number of rotated backup files to keep for layer2/layer3",
    ),
    platform: bool = typer.Option(
        False,
        "--platform",
        help="Upload results to DefendAI platform after scan",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="DefendAI platform API key",
    ),
    tenant_token: Optional[str] = typer.Option(
        None,
        "--tenant-token",
        help="DefendAI platform tenant token",
    ),
    wawsdb_url: str = typer.Option(
        "https://wauzeway.defendai.ai",
        "--wawsdb-url",
        help="DefendAI platform base URL",
    ),
    platform_interval: int = typer.Option(
        5,
        "--platform-interval",
        help="Upload to platform every N correlation cycles in daemon mode (default: 5)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including Layer 3/Kubernetes errors",
    ),
):
    """
    Run the full scan-all pipeline into output/raw/, then write AIBOM JSON and Markdown reports
    (ghost-agents.md, mcp-report.md, summary.md) beside raw/.
    """
    from agent_discover_scanner.aibom import generate_aibom
    from agent_discover_scanner.audit_reports import (
        write_audit_summary,
        write_ghost_agents_markdown,
        write_mcp_markdown,
    )
    from agent_discover_scanner.correlator import CorrelationEngine
    from agent_discover_scanner.mcp_detector import detect_mcp_servers
    from agent_discover_scanner.scan_runner import execute_scan_all

    output.mkdir(parents=True, exist_ok=True)
    raw_dir = output / "raw"
    report = execute_scan_all(
        path=path,
        output=raw_dir,
        duration=duration,
        layer3_file=layer3_file,
        skip_layers=skip_layers,
        daemon=False,
        max_log_size=max_log_size,
        max_log_backups=max_log_backups,
        platform=platform,
        api_key=api_key,
        tenant_token=tenant_token,
        wawsdb_url=wawsdb_url,
        platform_interval=platform_interval,
        verbose=verbose,
        scan_output_format="text",
        layer=None,
    )
    if report is None:
        console.print("[red]Audit did not produce a correlation report.[/red]")
        raise typer.Exit(code=1)

    inv_path = raw_dir / "agent_inventory.json"
    if not inv_path.is_file():
        console.print(f"[red]Missing inventory file: {inv_path}[/red]")
        raise typer.Exit(code=1)

    generate_aibom(inv_path, output / "aibom.json")
    write_ghost_agents_markdown(inv_path, output / "ghost-agents.md")
    write_audit_summary(report, output / "summary.md", raw_dir)

    nf: list = []
    l4: list = []
    layer2_json = raw_dir / "layer2_network.json"
    layer4_json = raw_dir / "layer4_endpoint.json"
    try:
        if layer2_json.is_file():
            data = json.loads(layer2_json.read_text(encoding="utf-8"))
            nf = (data.get("findings") or []) + (data.get("connections") or [])
    except (json.JSONDecodeError, OSError):
        pass
    try:
        if layer4_json.is_file():
            l4 = CorrelationEngine.load_layer4_findings(layer4_json)
    except Exception:
        pass
    try:
        mcp_result = detect_mcp_servers(
            scan_dir=path,
            network_findings=nf,
            layer4_findings=l4,
        )
    except Exception:
        mcp_result = {}
    write_mcp_markdown(mcp_result, output / "mcp-report.md")

    console.print(f"\n[green]✅ Audit bundle written to {output.resolve()}[/green]\n")


@app.command()
def monitor_k8s(
    namespace: str = typer.Option(
        "kube-system",
        "--namespace",
        "-n",
        help="Kubernetes namespace where Tetragon is deployed",
    ),
    duration: Optional[int] = typer.Option(
        None,
        "--duration",
        "-d",
        help="Monitoring duration in seconds (default: run until Ctrl+C)",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (for json/jsonl formats)",
    ),
    output_format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format: console, json, or jsonl",
    ),
    tetragon_export_file: Optional[Path] = typer.Option(
        None,
        "--tetragon-export-file",
        help="Read from Tetragon export file instead of kubectl (e.g. /var/run/cilium/tetragon/tetragon.log). Lower API server overhead.",
    ),
):
    """
    Monitor Kubernetes cluster for AI agent activity using Tetragon.
    
    Requires:
    - Cilium Tetragon installed in the cluster
    - kubectl configured and authenticated (unless --tetragon-export-file is used)
    - TracingPolicy deployed (see docs/TETRAGON_SETUP.md)
    
    Examples:
        # Monitor with console output
        agent-discover-scanner monitor-k8s
        
        # Production: read from local Tetragon export file (no kubectl/API load)
        agent-discover-scanner monitor-k8s --tetragon-export-file /var/run/cilium/tetragon/tetragon.log
        
        # Save detections to JSONL file
        agent-discover-scanner monitor-k8s --output detections.jsonl --format jsonl
        
        # Monitor for 60 seconds and save as JSON
        agent-discover-scanner monitor-k8s --duration 60 --output report.json --format json
        
        # Monitor Tetragon in custom namespace
        agent-discover-scanner monitor-k8s --namespace monitoring
    """
    from pathlib import Path
    from agent_discover_scanner.monitors import monitor_k8s as run_monitor
    
    output_path = Path(output_file) if output_file else None
    
    try:
        run_monitor(
            namespace=namespace,
            duration=duration,
            output_file=output_path,
            output_format=output_format,
            tetragon_export_file=tetragon_export_file,
        )
    except FileNotFoundError as e:
        if tetragon_export_file and "Tetragon export file" in str(e):
            console.print(f"[red]Error: {e}[/red]")
        else:
            console.print(
                "[red]Error: kubectl not found. Please install kubectl and configure cluster access.[/red]"
            )
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


#@app.command()
@app.command()
def endpoint(
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (JSON or Markdown)"
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: json or markdown"
    ),
):
    """
    Endpoint Discovery: Scan local endpoint for Shadow AI using osquery.
    
    Discovers AI usage on this machine:
    - Desktop AI applications (ChatGPT, Claude, Cursor)
    - AI packages (pip, npm: openai, langchain, etc.)
    - Active connections to AI services
    - Browser-based AI usage
    
    Requires osquery to be installed:
      macOS:   brew install osquery
      Windows: choco install osquery
      Linux:   See https://osquery.io/downloads
    """
    from rich.console import Console
    from rich.table import Table
    import subprocess
    import json
    
    console = Console()
    
    # Check if osquery is installed
    try:
        subprocess.run(
            ["osqueryi", "--version"],
            capture_output=True,
            timeout=5,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("\n[red]✗ Error: osquery not installed[/red]\n")
        console.print("[yellow]Install osquery:[/yellow]")
        console.print("  macOS:   [cyan]brew install osquery[/cyan]")
        console.print("  Windows: [cyan]choco install osquery[/cyan]")
        console.print("  Linux:   [cyan]https://osquery.io/downloads[/cyan]")
        console.print("\n[yellow]Full setup guide:[/yellow]")
        console.print("  https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/blob/main/docs/layer4-setup.md")
        raise typer.Exit(1)
    
    console.print("\n[bold blue]Endpoint Discovery: Endpoint Discovery (Shadow AI)[/bold blue]\n")
    
    # Execute osquery
    with console.status("[bold yellow]Running osquery scans...", spinner="dots"):
        executor = OsqueryExecutor()
        raw_results = executor.discover_all()
    
    # Convert to model
    hostname = socket.gethostname()
    endpoint = OsqueryResultParser.create_endpoint_discovery(
        hostname=hostname,
        osquery_results=raw_results
    )
    
    # Generate report
    report = Layer4Report([endpoint])
    summary = report.generate_summary()
    
    # Display summary
    console.print("\n[bold green]✓ Scan Complete[/bold green]\n")
    
    summary_table = Table(show_header=False, box=None)
    summary_table.add_row("[cyan]Hostname:", f"[white]{endpoint.hostname}")
    summary_table.add_row("[cyan]OS:", f"[white]{endpoint.os_type} {endpoint.os_version}")
    summary_table.add_row("[cyan]Total AI Instances:", f"[white]{endpoint.total_ai_instances}")
    summary_table.add_row("[cyan]Risk Score:", f"[white]{endpoint.risk_score}/100")
    console.print(summary_table)
    
    # Show findings
    if endpoint.applications:
        console.print(f"\n[yellow]Desktop Applications ({len(endpoint.applications)}):[/yellow]")
        for app in endpoint.applications[:5]:
            console.print(f"  • {app.name} [dim]v{app.version}[/dim]")
    
    if endpoint.packages:
        console.print(f"\n[yellow]AI Packages ({len(endpoint.packages)}):[/yellow]")
        for pkg in endpoint.packages[:5]:
            console.print(f"  • {pkg.name} [dim]v{pkg.version} ({pkg.package_manager})[/dim]")
    
    if endpoint.connections:
        console.print(f"\n[yellow]Active AI Connections ({len(endpoint.connections)}):[/yellow]")
        for conn in endpoint.connections[:5]:
            console.print(f"  • {conn.process_name} → {conn.remote_hostname}:{conn.remote_port}")
    
    # Save report
    if output:
        output_path = output
    else:
        output_path = Path("layer4_report.md" if output_format == "markdown" else "layer4_report.json")
    
    if output_format == "markdown":
        report_content = report.generate_markdown_report()
        output_path.write_text(report_content)
    else:
        # JSON format
        json_data = {
            "scan_timestamp": endpoint.scan_timestamp.isoformat(),
            "hostname": endpoint.hostname,
            "os_type": endpoint.os_type,
            "os_version": endpoint.os_version,
            "username": endpoint.username,
            "risk_score": endpoint.risk_score,
            "total_ai_instances": endpoint.total_ai_instances,
            "applications": [
                {
                    "name": app.name,
                    "version": app.version,
                    "vendor": app.vendor,
                    "install_path": app.install_path
                }
                for app in endpoint.applications
            ],
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "package_manager": pkg.package_manager
                }
                for pkg in endpoint.packages
            ],
            "connections": [
                {
                    "process_name": conn.process_name,
                    "remote_hostname": conn.remote_hostname,
                    "remote_port": conn.remote_port
                }
                for conn in endpoint.connections
            ]
        }
        output_path.write_text(json.dumps(json_data, indent=2))
    
    console.print(f"\n[green]✓ Report saved to:[/green] [cyan]{output_path}[/cyan]\n")


if __name__ == "__main__":
    app()
