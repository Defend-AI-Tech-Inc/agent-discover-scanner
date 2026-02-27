"""Tetragon event monitor for Kubernetes."""

import json
import os
import select
import subprocess
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Union

from rich.console import Console
from rich.table import Table

from .tetragon_events import parse_tetragon_event, TetragonEvent
from .vendor_mapping import identify_vendor
from .json_output import JSONLogger


console = Console()


class TetragonMonitor:
    """Monitor Tetragon events for AI agent detection."""
    
    def __init__(self, namespace: str = "kube-system"):
        """
        Initialize Tetragon monitor.
        
        Args:
            namespace: Kubernetes namespace where Tetragon is deployed
        """
        self.namespace = namespace
        self.detections = defaultdict(list)
    
    def stream_events(
        self,
        follow: bool = True,
        duration: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        tetragon_export_file: Optional[Union[str, Path]] = None,
    ) -> Iterator[TetragonEvent]:
        """
        Stream Tetragon events from kubectl logs or from a local export file.
        
        Args:
            follow: If True, follow logs in real-time (like tail -f)
            duration: If set, stop after this many seconds
            stop_event: If set, stop when this event is set
            tetragon_export_file: If set, read from this file instead of kubectl
                (e.g. /var/run/cilium/tetragon/tetragon.log). Production-recommended.
        
        Yields:
            Parsed TetragonEvent objects
        """
        start_time = datetime.now()
        process: Optional[subprocess.Popen] = None
        file_handle = None

        if tetragon_export_file:
            # Production path: tail Tetragon export file directly (no API server load)
            path = Path(tetragon_export_file)
            if not path.exists():
                console.print(f"[red]Error: Tetragon export file not found: {path}[/red]")
                raise FileNotFoundError(f"Tetragon export file not found: {path}")
            try:
                file_handle = open(path, "r")
                file_handle.seek(0, os.SEEK_END)
            except OSError as e:
                console.print(f"[red]Error: Cannot open Tetragon export file: {e}[/red]")
                raise
            try:
                while True:
                    if stop_event and stop_event.is_set():
                        break
                    ready, _, _ = select.select([file_handle], [], [], 1.0)
                    if ready:
                        line = file_handle.readline()
                        if not line:
                            continue
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw_event = json.loads(line)
                            event = parse_tetragon_event(raw_event)
                            if event and event.sock_arg:
                                yield event
                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            console.print(f"[yellow]Warning: Failed to parse event: {e}[/yellow]")
                            continue
                    if duration is not None:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        if elapsed >= duration:
                            break
            finally:
                if file_handle is not None:
                    try:
                        file_handle.close()
                    except Exception:
                        pass
            return

        # Default: stream via kubectl logs
        get_pod_cmd = [
            "kubectl", "get", "pods",
            "-n", self.namespace,
            "-l", "app.kubernetes.io/name=tetragon",
            "-o", "jsonpath={.items[0].metadata.name}",
        ]
        
        try:
            pod_name = subprocess.check_output(get_pod_cmd, text=True).strip()
        except subprocess.CalledProcessError:
            console.print("[red]Error: Could not find Tetragon pods. Is Tetragon installed?[/red]")
            raise
        
        cmd = [
            "kubectl", "logs",
            "-n", self.namespace,
            pod_name,
            "-c", "export-stdout",
        ]
        
        if follow:
            cmd.append("-f")
        else:
            cmd.extend(["--tail", "100"])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            while True:
                if stop_event and stop_event.is_set():
                    break

                ready, _, _ = select.select([process.stdout], [], [], 1.0)
                if ready:
                    line = process.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        raw_event = json.loads(line)
                        event = parse_tetragon_event(raw_event)

                        if event and event.sock_arg:
                            yield event

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        console.print(f"[yellow]Warning: Failed to parse event: {e}[/yellow]")
                        continue

                if duration is not None:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed >= duration:
                        break

        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped by user[/yellow]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error running kubectl: {e}[/red]")
            raise
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
    
    def detect_llm_connections(self, event: TetragonEvent) -> Optional[dict]:
        """
        Detect if event represents connection to LLM/Vector DB.
        
        Args:
            event: Parsed Tetragon event
            
        Returns:
            Detection info dict if LLM connection detected, None otherwise
        """
        if not event.sock_arg:
            return None
        
        vendor = identify_vendor(event.sock_arg.daddr, event.sock_arg.dport)
        
        if vendor:
            detection = {
                "timestamp": event.timestamp,
                "vendor": vendor,
                "dest_ip": event.sock_arg.daddr,
                "dest_port": event.sock_arg.dport,
                "pod_namespace": event.process.pod.namespace if event.process.pod else "unknown",
                "pod_name": event.process.pod.name if event.process.pod else "unknown",
                "workload": event.process.pod.workload if event.process.pod else "unknown",
                "workload_kind": event.process.pod.workload_kind if event.process.pod else "unknown",
                "binary": event.process.binary,
                "node": event.node_name,
            }
            
            # Track detection
            pod_key = f"{detection['pod_namespace']}/{detection['pod_name']}"
            self.detections[pod_key].append(detection)
            
            return detection
        
        return None
    
    def display_detection(self, detection: dict):
        """Display a detection in real-time."""
        console.print(
            f"[bold red]🚨 AI Agent Detected![/bold red] "
            f"[cyan]{detection['pod_namespace']}/{detection['pod_name']}[/cyan] "
            f"-> [yellow]{detection['vendor']}[/yellow] "
            f"({detection['dest_ip']}:{detection['dest_port']})"
        )
    
    def display_summary(self):
        """Display summary of all detections."""
        if not self.detections:
            console.print("[green]No AI agent activity detected[/green]")
            return
        
        table = Table(title="AI Agent Detection Summary")
        table.add_column("Pod", style="cyan")
        table.add_column("Workload", style="blue")
        table.add_column("Vendor", style="yellow")
        table.add_column("Connections", justify="right", style="green")
        table.add_column("Binary", style="magenta")
        
        for pod_key, detections in self.detections.items():
            # Aggregate by vendor
            vendor_counts = defaultdict(int)
            workload = None
            binary = None
            
            for d in detections:
                vendor_counts[d["vendor"]] += 1
                workload = f"{d['workload_kind']}/{d['workload']}"
                binary = d["binary"]
            
            vendors_str = ", ".join(f"{v} ({c})" for v, c in vendor_counts.items())
            
            table.add_row(
                pod_key,
                workload,
                vendors_str,
                str(len(detections)),
                binary,
            )
        
        console.print(table)


def monitor_k8s(
    namespace: str = "kube-system",
    duration: Optional[int] = None,
    output_file: Optional[Path] = None,
    output_format: str = "console",
    stop_event: Optional[threading.Event] = None,
    tetragon_export_file: Optional[Union[str, Path]] = None,
):
    """
    Monitor Kubernetes cluster for AI agent activity.
    
    Args:
        namespace: Tetragon namespace
        duration: Monitoring duration in seconds (None = infinite)
        output_file: Path to output file (for json/jsonl formats)
        output_format: Output format: "console", "json", or "jsonl"
        stop_event: Optional event to signal stop (e.g. daemon mode)
        tetragon_export_file: If set, read from this file instead of kubectl logs
            (e.g. /var/run/cilium/tetragon/tetragon.log). Lower API server overhead.
    """
    monitor = TetragonMonitor(namespace=namespace)
    
    # Setup JSON logger if needed
    json_logger = None
    if output_format in ["json", "jsonl"]:
        json_logger = JSONLogger(output_file=output_file, format=output_format)
    
    if output_format == "console":
        console.print("[bold green]🔍 Monitoring Kubernetes cluster for AI agents...[/bold green]")
        if tetragon_export_file:
            console.print(f"[dim]Reading from: {tetragon_export_file}[/dim]")
        else:
            console.print(f"Tetragon namespace: {namespace}")
        console.print("Press Ctrl+C to stop\n")
    
    try:
        for event in monitor.stream_events(
            follow=True,
            duration=duration,
            stop_event=stop_event,
            tetragon_export_file=tetragon_export_file,
        ):
            detection = monitor.detect_llm_connections(event)

            if detection:
                # Console output
                if output_format == "console":
                    monitor.display_detection(detection)

                # JSON output
                if json_logger:
                    json_logger.log_detection(detection)

            if stop_event and stop_event.is_set():
                break

    except KeyboardInterrupt:
        pass
    finally:
        if json_logger:
            json_logger.close()
        
        if output_format == "console":
            console.print("\n" + "="*60)
            monitor.display_summary()
        elif output_file:
            console.print(f"[green]✅ Detections saved to {output_file}[/green]")
