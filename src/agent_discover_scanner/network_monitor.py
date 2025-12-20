"""
Network traffic analyzer for detecting active AI agents.
"""
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class NetworkFinding:
    """Represents a detected network connection to LLM APIs."""
    timestamp: str
    destination: str
    provider: str  # "openai", "anthropic", "google", etc.
    process_name: Optional[str] = None
    local_port: Optional[int] = None
    connection_type: str = "https"  # "https", "wss"
    
    def to_dict(self) -> dict:
        return asdict(self)


class NetworkMonitor:
    """Monitor network traffic for LLM API connections."""
    
    # Known LLM provider endpoints
    LLM_ENDPOINTS = {
        "api.openai.com": "openai",
        "api.anthropic.com": "anthropic",
        "generativelanguage.googleapis.com": "google",
        "api.cohere.ai": "cohere",
        "bedrock-runtime": "aws-bedrock",
        "azure.openai.com": "azure-openai",
        "openrouter.ai": "openrouter",
        "together.xyz": "together-ai",
    }
    
    # Vector database endpoints
    VECTOR_DB_ENDPOINTS = {
        "pinecone.io": "pinecone",
        "api.pinecone.io": "pinecone",
        "weaviate.cloud": "weaviate",
        "qdrant.tech": "qdrant",
        "chroma.io": "chromadb",
    }
    
    @classmethod
    def analyze_dns_logs(cls, log_file: Path) -> List[NetworkFinding]:
        """
        Analyze DNS query logs for LLM provider lookups.
        
        Args:
            log_file: Path to DNS log file
        
        Returns:
            List of network findings
        """
        findings = []
        
        if not log_file.exists():
            return findings
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse DNS log line (format varies by system)
                    for endpoint, provider in cls.LLM_ENDPOINTS.items():
                        if endpoint in line:
                            finding = NetworkFinding(
                                timestamp=datetime.now().isoformat(),
                                destination=endpoint,
                                provider=provider
                            )
                            findings.append(finding)
                            break
        except Exception:
            pass
        
        return findings
    
    @classmethod
    def get_active_connections(cls) -> List[NetworkFinding]:
        """
        Get currently active connections to LLM providers.
        Uses netstat/lsof to find active connections.
        
        Returns:
            List of active LLM connections
        """
        findings = []
        
        try:
            # Use lsof on macOS/Linux to find network connections
            # This shows what processes are connecting where
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Check if any LLM endpoint is in the connection
                    for endpoint, provider in {**cls.LLM_ENDPOINTS, **cls.VECTOR_DB_ENDPOINTS}.items():
                        if endpoint in line:
                            # Parse process name and port
                            parts = line.split()
                            if len(parts) > 1:
                                process_name = parts[0]
                                
                                finding = NetworkFinding(
                                    timestamp=datetime.now().isoformat(),
                                    destination=endpoint,
                                    provider=provider,
                                    process_name=process_name
                                )
                                findings.append(finding)
                                break
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # lsof not available or timed out
            pass
        
        return findings
    
    @classmethod
    def detect_rag_pattern(cls, findings: List[NetworkFinding]) -> List[Dict]:
        """
        Detect RAG (Retrieval-Augmented Generation) patterns.
        
        RAG = Simultaneous connections to LLM + Vector DB
        
        Returns:
            List of detected RAG patterns with confidence scores
        """
        rag_patterns = []
        
        # Group by timestamp (within 60 seconds)
        llm_connections = [f for f in findings if f.provider in cls.LLM_ENDPOINTS.values()]
        vector_connections = [f for f in findings if f.provider in cls.VECTOR_DB_ENDPOINTS.values()]
        
        # If we see both in the same analysis window, likely RAG
        if llm_connections and vector_connections:
            rag_patterns.append({
                "pattern": "RAG_DETECTED",
                "confidence": "high",
                "llm_provider": llm_connections[0].provider,
                "vector_db": vector_connections[0].provider,
                "timestamp": datetime.now().isoformat()
            })
        
        return rag_patterns


def monitor_network(duration_seconds: int = 60, output_file: Optional[Path] = None) -> Dict:
    """
    Monitor network for specified duration and report LLM activity.
    
    Args:
        duration_seconds: How long to monitor
        output_file: Optional JSON output file
    
    Returns:
        Summary of findings
    """
    import time
    
    print(f"Monitoring network for {duration_seconds} seconds...")
    
    all_findings = []
    start_time = time.time()
    
    while time.time() - start_time < duration_seconds:
        # Check for active connections every 5 seconds
        findings = NetworkMonitor.get_active_connections()
        all_findings.extend(findings)
        
        if findings:
            for finding in findings:
                print(f"  [DETECT] {finding.provider} connection from {finding.process_name}")
        
        time.sleep(5)
    
    # Detect patterns
    rag_patterns = NetworkMonitor.detect_rag_pattern(all_findings)
    
    # Create summary
    summary = {
        "scan_duration": duration_seconds,
        "total_connections": len(all_findings),
        "unique_providers": list(set(f.provider for f in all_findings)),
        "rag_patterns": rag_patterns,
        "findings": [f.to_dict() for f in all_findings]
    }
    
    # Save to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
    
    return summary
