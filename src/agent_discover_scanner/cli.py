import ast
import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table

from agent_discover_scanner.scanner import Scanner
from agent_discover_scanner.visitor import ContextAwareVisitor
from agent_discover_scanner.signatures import SIGNATURE_REGISTRY
from agent_discover_scanner.sarif_output import SARIFGenerator
from agent_discover_scanner.js_signatures import JavaScriptAgentDetector
from agent_discover_scanner.sbom_analyzer import (
    analyze_requirements_txt,
    analyze_package_json,
)

app = typer.Typer(help="AgentDiscover Scanner: Detect Autonomous AI Agents and Shadow AI")
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the repository to scan"),
    output: str = typer.Option("results.sarif", help="Output SARIF file path"),
    format: str = typer.Option("table", help="Output format (sarif, table, both)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output")
):
    """
    Scan source code for AI agents and Shadow AI patterns.
    """
    console.print(f"[bold green]Starting scan on: {path}[/bold green]\n")
    
    # Initialize scanner
    scan_root = Path(path).resolve()
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
                source_code = file_path.read_text(encoding='utf-8')
                
                # Determine file type and use appropriate scanner
                if file_path.suffix == '.py':
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
                                "note": "blue"
                            }.get(finding.severity, "white")
                            
                            console.print(f"  [{severity_color}]●[/{severity_color}] {finding}")
                
                elif file_path.suffix in {'.js', '.ts', '.jsx', '.tsx', '.mjs'}:
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
                                "note": "blue"
                            }.get(finding.severity, "white")
                            
                            console.print(f"  [{severity_color}]●[/{severity_color}] {finding}")
                
            except SyntaxError as e:
                if verbose:
                    console.print(f"[red]Syntax error in {file_path}: {e}[/red]")
            except Exception as e:
                if verbose:
                    console.print(f"[red]Error processing {file_path}: {e}[/red]")
        
        # Generate SARIF output if requested
        if format in ["sarif", "both"]:
            output_path = Path(output)
            SARIFGenerator.write_sarif(all_findings, scan_root, output_path)
            console.print(f"\n[bold green]✓[/bold green] SARIF report written to: {output_path}")
        
        # Display summary table if requested
        if format in ["table", "both"]:
            console.print(f"\n[bold cyan]Scan Complete![/bold cyan]")
            
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
                console.print(f"\n[bold]Findings by Rule:[/bold]")
                findings_by_rule = {}
                for finding in all_findings:
                    if finding.rule_id not in findings_by_rule:
                        findings_by_rule[finding.rule_id] = []
                    findings_by_rule[finding.rule_id].append(finding)
                
                for rule_id, findings in sorted(findings_by_rule.items()):
                    console.print(f"  {rule_id}: {len(findings)} finding(s)")
            
            # Show unique imports if verbose
            if verbose and all_imports:
                console.print(f"\n[bold]Discovered Imports:[/bold]")
                for imp in sorted(all_imports)[:20]:
                    console.print(f"  • {imp}")
                if len(all_imports) > 20:
                    console.print(f"  ... and {len(all_imports) - 20} more")
        
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def deps(
    path: str = typer.Argument(..., help="Path to scan for dependencies"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output")
):
    """
    Scan dependencies (requirements.txt, package.json) for AI/ML frameworks.
    """
    console.print(f"[bold green]Scanning dependencies in: {path}[/bold green]\n")
    
    scan_path = Path(path)
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
                console.print(f"  [{risk_color}]●[/{risk_color}] {finding.package_name} ({finding.version}) - {finding.reason}")
    
    # Scan package.json
    pkg_file = scan_path / "package.json"
    if pkg_file.exists():
        console.print("[cyan]Analyzing package.json...[/cyan]")
        findings = analyze_package_json(pkg_file)
        all_findings.extend(findings)
        
        if verbose:
            for finding in findings:
                risk_color = "red" if finding.risk_level == "high" else "yellow"
                console.print(f"  [{risk_color}]●[/{risk_color}] {finding.package_name} ({finding.version}) - {finding.reason}")
    
    # Summary
    console.print(f"\n[bold cyan]Dependency Scan Complete![/bold cyan]")
    
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
        console.print(f"\n[bold]Detected Frameworks:[/bold]")
        for finding in all_findings:
            risk_color = "red" if finding.risk_level == "high" else "yellow"
            console.print(f"  [{risk_color}]●[/{risk_color}] {finding.package_name} - {finding.reason}")


@app.command()
def monitor(
    duration: int = typer.Option(60, help="Duration to monitor in seconds"),
    output: str = typer.Option("network-findings.json", help="Output JSON file"),
):
    """
    Monitor network traffic for active AI agent connections.
    """
    from agent_discover_scanner.network_monitor import monitor_network
    
    console.print(f"[bold green]Starting network monitoring for {duration} seconds...[/bold green]\n")
    console.print("[cyan]Detecting connections to:[/cyan]")
    console.print("  • OpenAI API")
    console.print("  • Anthropic API")
    console.print("  • Google AI")
    console.print("  • Vector Databases (Pinecone, Weaviate, etc.)\n")
    
    summary = monitor_network(duration, Path(output))
    
    # Display results
    console.print(f"\n[bold cyan]Network Monitoring Complete![/bold cyan]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Scan Duration", f"{summary['scan_duration']}s")
    table.add_row("Total Connections", str(summary['total_connections']))
    table.add_row("Unique Providers", ", ".join(summary['unique_providers']) if summary['unique_providers'] else "None")
    table.add_row("RAG Patterns", str(len(summary['rag_patterns'])))
    
    console.print(table)
    
    if summary['unique_providers']:
        console.print(f"\n[bold]Active LLM Providers:[/bold]")
        for provider in summary['unique_providers']:
            console.print(f"  [yellow]●[/yellow] {provider}")
    
    if summary['rag_patterns']:
        console.print(f"\n[bold red]RAG Pattern Detected![/bold red]")
        for pattern in summary['rag_patterns']:
            console.print(f"  • LLM: {pattern['llm_provider']} + Vector DB: {pattern['vector_db']}")
    
    console.print(f"\n[green]Results saved to: {output}[/green]")


if __name__ == "__main__":
    app()
