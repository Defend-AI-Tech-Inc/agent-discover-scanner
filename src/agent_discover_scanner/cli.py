import ast
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

#layer4 imports
from agent_discover_scanner.layer4.osquery_executor import OsqueryExecutor
from agent_discover_scanner.layer4.result_parser import OsqueryResultParser
from agent_discover_scanner.reports.layer4_report import Layer4Report
import socket

app = typer.Typer(help="AgentDiscover Scanner: Detect Autonomous AI Agents and Shadow AI")
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the repository to scan"),
    output: str = typer.Option("results.sarif", help="Output SARIF file path"),
    format: str = typer.Option("table", help="Output format (sarif, table, both)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
):
    """
    Scan source code for AI agents and Shadow AI patterns.
    """
    console.print(f"[bold green]Starting scan on: {path}[/bold green]\n")

    # Validate input
    try:
        scan_root = validate_directory_exists(path, "Scan directory")
    except ValidationError:
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
                    if visitor.findings and format in ["table", "both"]:
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
                    if findings and format in ["table", "both"]:
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
        if format in ["sarif", "both"]:
            output_path = Path(output)
            SARIFGenerator.write_sarif(all_findings, scan_root, output_path)
            console.print(f"\n[bold green]✓[/bold green] SARIF report written to: {output_path}")

        # Display summary table if requested
        if format in ["table", "both"]:
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

    console.print(
        f"[bold green]Starting network monitoring for {duration} seconds...[/bold green]\n"
    )
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
    inventory = CorrelationEngine.correlate(code_findings, network_findings)

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
):
    """
    Monitor Kubernetes cluster for AI agent activity using Tetragon.
    
    Requires:
    - Cilium Tetragon installed in the cluster
    - kubectl configured and authenticated
    - TracingPolicy deployed (see docs/TETRAGON_SETUP.md)
    
    Examples:
        # Monitor with console output
        agent-discover-scanner monitor-k8s
        
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
        )
    except FileNotFoundError:
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
