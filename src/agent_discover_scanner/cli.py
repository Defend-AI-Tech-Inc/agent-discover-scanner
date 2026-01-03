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

    ⚠️  EXPERIMENTAL: Requires lsof (Mac/Linux only)
    """
    from agent_discover_scanner.network_monitor import monitor_network

    console.print("[yellow]⚠️  EXPERIMENTAL FEATURE[/yellow]")
    console.print("[dim]Network monitoring requires 'lsof' command (Mac/Linux only)[/dim]\n")

    console.print(
        f"[bold green]Starting network monitoring for {duration} seconds...[/bold green]\n"
    )
    console.print("[cyan]Detecting connections to:[/cyan]")
    console.print("  • OpenAI API")
    console.print("  • Anthropic API")
    console.print("  • Google AI")
    console.print("  • Vector Databases (Pinecone, Weaviate, etc.)\n")

    try:
        summary = monitor_network(duration, Path(output))
    except FileNotFoundError:
        console.print("[red]❌ Error: 'lsof' command not found[/red]")
        console.print("\n[yellow]💡 This feature requires:[/yellow]")
        console.print("  • Mac or Linux operating system")
        console.print("  • lsof utility (usually pre-installed)")
        console.print("\n[dim]Windows users: Network monitoring not supported yet[/dim]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]❌ Monitoring error:[/red] {e}")
        raise typer.Exit(code=1)

    # Display results
    console.print("\n[bold cyan]Network Monitoring Complete![/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Scan Duration", f"{summary['scan_duration']}s")
    table.add_row("Total Connections", str(summary["total_connections"]))
    table.add_row(
        "Unique Providers",
        ", ".join(summary["unique_providers"]) if summary["unique_providers"] else "None",
    )
    table.add_row("RAG Patterns", str(len(summary["rag_patterns"])))

    console.print(table)

    if summary["unique_providers"]:
        console.print("\n[bold]Active LLM Providers:[/bold]")
        for provider in summary["unique_providers"]:
            console.print(f"  [yellow]●[/yellow] {provider}")

    if summary["rag_patterns"]:
        console.print("\n[bold red]RAG Pattern Detected![/bold red]")
        for pattern in summary["rag_patterns"]:
            console.print(f"  • LLM: {pattern['llm_provider']} + Vector DB: {pattern['vector_db']}")

    console.print(f"\n[green]Results saved to: {output}[/green]")


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
):
    """
    Monitor Kubernetes cluster for AI agent activity using Tetragon.
    
    Requires:
    - Cilium Tetragon installed in the cluster
    - kubectl configured and authenticated
    - TracingPolicy deployed (see docs/TETRAGON_SETUP.md)
    
    Examples:
        # Monitor indefinitely
        agent-discover-scanner monitor-k8s
        
        # Monitor for 60 seconds
        agent-discover-scanner monitor-k8s --duration 60
        
        # Monitor Tetragon in custom namespace
        agent-discover-scanner monitor-k8s --namespace monitoring
    """
    from .monitors import monitor_k8s as run_monitor
    
    try:
        run_monitor(namespace=namespace, duration=duration)
    except FileNotFoundError:
        console.print(
            "[red]Error: kubectl not found. Please install kubectl and configure cluster access.[/red]"
        )
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
