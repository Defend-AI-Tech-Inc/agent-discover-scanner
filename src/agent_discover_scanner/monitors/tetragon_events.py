"""Tetragon event data models and parser."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SockArg(BaseModel):
    """Socket argument from tcp_connect kprobe."""
    family: str
    type: str
    protocol: str
    saddr: str  # Source IP
    daddr: str  # Destination IP
    sport: int  # Source port
    dport: int  # Destination port
    state: str


class PodInfo(BaseModel):
    """Kubernetes pod information."""
    namespace: str
    name: str
    uid: str
    workload: str
    workload_kind: str


class ProcessInfo(BaseModel):
    """Process execution information."""
    binary: str
    arguments: str
    pid: int
    pod: Optional[PodInfo] = None


class TetragonEvent(BaseModel):
    """Parsed Tetragon process_kprobe event."""
    event_type: str = "process_kprobe"
    timestamp: datetime
    node_name: str
    
    # Process info
    process: ProcessInfo
    
    # Network info (if tcp_connect)
    function_name: Optional[str] = None
    sock_arg: Optional[SockArg] = None
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


def parse_tetragon_event(raw_event: dict) -> Optional[TetragonEvent]:
    """
    Parse raw Tetragon JSON event into structured model.
    
    Args:
        raw_event: Raw JSON dict from Tetragon logs
        
    Returns:
        TetragonEvent if valid process_kprobe event, None otherwise
    """
    # Only handle process_kprobe events with tcp_connect
    if "process_kprobe" not in raw_event:
        return None
        
    kprobe = raw_event["process_kprobe"]
    
    # Extract process info
    proc = kprobe["process"]
    pod_data = proc.get("pod")
    
    pod_info = None
    if pod_data:
        pod_info = PodInfo(
            namespace=pod_data["namespace"],
            name=pod_data["name"],
            uid=pod_data["uid"],
            workload=pod_data.get("workload", "unknown"),
            workload_kind=pod_data.get("workload_kind", "unknown"),
        )
    
    process = ProcessInfo(
        binary=proc["binary"],
        arguments=proc["arguments"],
        pid=proc["pid"],
        pod=pod_info,
    )
    
    # Extract network info
    sock_arg = None
    function_name = kprobe.get("function_name")
    
    if function_name == "tcp_connect" and kprobe.get("args"):
        sock_data = kprobe["args"][0].get("sock_arg")
        if sock_data:
            sock_arg = SockArg(**sock_data)
    
    return TetragonEvent(
        timestamp=datetime.fromisoformat(raw_event["time"].replace("Z", "+00:00")),
        node_name=raw_event["node_name"],
        process=process,
        function_name=function_name,
        sock_arg=sock_arg,
    )
