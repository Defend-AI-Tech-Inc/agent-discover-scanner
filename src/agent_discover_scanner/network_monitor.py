"""
Network Monitor V2 - Improved AI connection detection using psutil

Fixes WebSocket detection issue by monitoring ALL established connections,
not just new ones.
"""

import psutil
import socket
import time
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json

@dataclass
class AIConnection:
    """Detected AI service connection"""
    timestamp: datetime
    process_name: str
    pid: int
    process_path: str
    remote_host: str
    remote_ip: str
    remote_port: int
    local_port: int
    ai_service: str  # 'OpenAI', 'Anthropic', etc.
    connection_type: str  # 'tcp', 'udp'

class NetworkMonitor:
    """Improved network monitor using psutil for better WebSocket detection"""
    
    # AI service domains and their classifications
    AI_SERVICES = {
        # OpenAI
        'openai.com': 'OpenAI',
        'api.openai.com': 'OpenAI API',
        'chatgpt.com': 'ChatGPT',
        
        # Anthropic
        'anthropic.com': 'Anthropic',
        'api.anthropic.com': 'Anthropic API',
        'claude.ai': 'Claude',
        'console.anthropic.com': 'Anthropic Console',
        'claude-api.anthropic.com': 'Claude API',
        
        # Google
        'googleapis.com': 'Google AI',
        'generativelanguage.googleapis.com': 'Gemini API',
        'bard.google.com': 'Bard',
        
        # Other AI services
        'cohere.ai': 'Cohere',
        'api.cohere.ai': 'Cohere API',
        'replicate.com': 'Replicate',
        'huggingface.co': 'HuggingFace',
        'perplexity.ai': 'Perplexity',
        
        # Development tools
        'github.com/features/copilot': 'GitHub Copilot',
        'api.cursor.sh': 'Cursor',
        'codeium.com': 'Codeium',
    }
        
    # ADD: Vector database domains
    VECTOR_DBS = {
        'pinecone.io': 'Pinecone',
        'api.pinecone.io': 'Pinecone',
        'weaviate.io': 'Weaviate',
        'qdrant.io': 'Qdrant',
        'milvus.io': 'Milvus',
        'chromadb.io': 'ChromaDB',
    }
    
    def detect_rag_patterns(self, connections: List[AIConnection]) -> List[Dict]:
        """
        Detect RAG (Retrieval-Augmented Generation) patterns.
        
        RAG indicator: AI service + Vector DB in same process or timeframe
        """
        rag_patterns = []
        
        # Group connections by process
        by_process = {}
        for conn in connections:
            if conn.pid not in by_process:
                by_process[conn.pid] = {
                    'process_name': conn.process_name,
                    'ai_services': set(),
                    'vector_dbs': set(),
                }
            
            # Check if it's vector DB
            if self._is_vector_db(conn.remote_host):
                by_process[conn.pid]['vector_dbs'].add(conn.ai_service)
            else:
                by_process[conn.pid]['ai_services'].add(conn.ai_service)
        
        # Find processes with both AI + VectorDB
        for pid, data in by_process.items():
            if data['ai_services'] and data['vector_dbs']:
                rag_patterns.append({
                    'process': data['process_name'],
                    'pid': pid,
                    'ai_services': list(data['ai_services']),
                    'vector_dbs': list(data['vector_dbs']),
                    'confidence': 'HIGH'
                })
        
        return rag_patterns
    
    def _is_vector_db(self, hostname: str) -> bool:
        """Check if hostname is a vector database"""
        hostname_lower = hostname.lower()
        return any(db in hostname_lower for db in self.VECTOR_DBS.keys())
    
    def _classify_ai_service(self, hostname: str) -> Optional[str]:
        """Classify hostname as AI service or vector DB"""
        hostname_lower = hostname.lower()
        
        # Check AI services first
        for domain, service_name in self.AI_SERVICES.items():
            if domain in hostname_lower:
                return service_name
        
        # Check vector DBs
        for domain, service_name in self.VECTOR_DBS.items():
            if domain in hostname_lower:
                return service_name
        
        # Handle generic AWS/cloud hostnames that might be Anthropic
        # e.g., "ec2-52-85-xxx.compute-1.amazonaws.com"
        if "amazonaws.com" in hostname_lower or "compute-1.amazonaws.com" in hostname_lower:
            # Extract IP-like patterns from hostname
            ip_match = re.search(r'(\d+)-(\d+)-(\d+)', hostname_lower)
            if ip_match:
                first_octet = ip_match.group(1)
                second_octet = ip_match.group(2)
                # Check if it matches Anthropic IP patterns
                if first_octet == "52" and second_octet == "85":
                    return "Anthropic API"
                elif first_octet == "54" and second_octet in ["240", "241", "242", "243"]:
                    return "Anthropic API"
        
        return None
    
    def _classify_ai_service_by_ip(self, ip: str) -> Optional[str]:
        """
        Classify IP address directly as AI service.
        Used when reverse DNS fails or returns generic hostnames.
        """
        detected_hostname = self._detect_service_by_ip(ip)
        if detected_hostname:
            # Map detected hostname to service name
            return self._classify_ai_service(detected_hostname)
        return None
    
    def __init__(self):
        self._dns_cache = {}  # Cache DNS lookups
    
    def _generate_summary(self, connections: List[AIConnection], duration: int) -> Dict:
        """Generate summary report"""
        
        # Count by service
        services = {}
        for conn in connections:
            services[conn.ai_service] = services.get(conn.ai_service, 0) + 1
        
        # Count by process
        processes = {}
        for conn in connections:
            processes[conn.process_name] = processes.get(conn.process_name, 0) + 1
        
        # RAG pattern detection
        rag_patterns = self.detect_rag_patterns(connections)
        
        summary = {
            'scan_duration': duration,
            'total_connections': len(connections),
            'unique_services': list(services.keys()),
            'services': services,
            'processes': processes,
            'rag_patterns': rag_patterns,
            'connections': [
                {
                    'timestamp': conn.timestamp.isoformat(),
                    'process': conn.process_name,
                    'pid': conn.pid,
                    'service': conn.ai_service,
                    'remote_host': conn.remote_host,
                    'remote_port': conn.remote_port,
                }
                for conn in connections
            ]
        }
        
        return summary
    
    def get_active_ai_connections(self) -> List[AIConnection]:
        """
        Get all currently active AI connections across all processes.
        This catches WebSocket connections that lsof misses.
        """
        connections = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # Get process info early to avoid issues if process terminates
                try:
                    proc_pid = proc.pid
                    proc_name = proc.name()
                    proc_exe = proc.exe() or 'unknown'
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                
                # Get all network connections for this process
                for conn in proc.connections(kind='inet'):
                    # Only interested in established connections
                    if conn.status != 'ESTABLISHED':
                        continue
                    
                    # Must have remote address
                    if not conn.raddr:
                        continue
                    
                    # Must have local address
                    if not conn.laddr:
                        continue
                    
                    # Resolve hostname (with IP-based detection fallback)
                    hostname = self._resolve_hostname(conn.raddr.ip)
                    
                    # Check if it's an AI service (check both hostname and IP)
                    ai_service = self._classify_ai_service(hostname) or self._classify_ai_service_by_ip(conn.raddr.ip)
                    if ai_service:
                        connections.append(AIConnection(
                            timestamp=datetime.now(),
                            process_name=proc_name,
                            pid=proc_pid,
                            process_path=proc_exe,
                            remote_host=hostname,
                            remote_ip=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            local_port=conn.laddr.port,
                            ai_service=ai_service,
                            connection_type='tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                        ))
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process ended or we don't have permission
                continue
            except Exception as e:
                # Log but don't crash
                try:
                    proc_id = proc.pid
                except:
                    proc_id = "unknown"
                print(f"Warning: Error processing process {proc_id}: {e}")
                continue
        
        return connections
    
    def monitor(self, duration_seconds: int = 60, interval_seconds: int = 5) -> Dict:
        """
        Monitor AI connections for a specified duration.
        
        Args:
            duration_seconds: How long to monitor
            interval_seconds: How often to check (default: 5 seconds)
        
        Returns:
            Summary dict with all detected connections
        """
        print(f"Monitoring AI connections for {duration_seconds} seconds...")
        print(f"Checking every {interval_seconds} seconds\n")
        
        all_connections = []
        unique_connections = set()  # Track (process, service) pairs
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            connections = self.get_active_ai_connections()
            
            for conn in connections:
                # Create unique key
                conn_key = (conn.process_name, conn.ai_service, conn.remote_host)
                
                if conn_key not in unique_connections:
                    unique_connections.add(conn_key)
                    all_connections.append(conn)
                    
                    # Print detection
                    print(f"[DETECT] {conn.ai_service} connection from {conn.process_name} "
                          f"(PID: {conn.pid}) → {conn.remote_host}:{conn.remote_port}")
            
            # Wait before next check
            time.sleep(interval_seconds)
        
        # Generate summary
        summary = self._generate_summary(all_connections, duration_seconds)
        return summary
    
    def _resolve_hostname(self, ip: str) -> str:
        """
        Resolve IP to hostname with IP-based detection fallback.
        Uses reverse DNS first, then IP pattern matching for known AI services.
        """
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        
        # First, try IP-based detection (works even when reverse DNS fails)
        ip_based_hostname = self._detect_service_by_ip(ip)
        if ip_based_hostname:
            self._dns_cache[ip] = ip_based_hostname
            return ip_based_hostname
        
        # Fallback to reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            # If DNS fails, return IP (will be checked by IP-based detection)
            self._dns_cache[ip] = ip
            return ip
    
    def _detect_service_by_ip(self, ip: str) -> Optional[str]:
        """
        Detect AI service by IP address patterns.
        This is crucial because reverse DNS often fails for cloud/CDN IPs.
        """
        # Claude.ai uses Cloudflare (104.18.*, 104.26.*)
        # Check this first as it's most specific
        if ip.startswith("104.18.") or ip.startswith("104.26."):
            return "claude.ai"
        
        # Anthropic API uses AWS - specific known ranges
        # Anthropic API typically uses: 52.85.*, 54.240.*, 54.241.*, 54.242.*
        if (ip.startswith("52.85.") or 
            ip.startswith("54.240.") or ip.startswith("54.241.") or 
            ip.startswith("54.242.") or ip.startswith("54.243.")):
            return "api.anthropic.com"
        
        # OpenAI IP ranges (Azure)
        # OpenAI uses: 13.107.*, 20.*, and some 52.84.* ranges
        if ip.startswith("13.107.") or ip.startswith("20."):
            return "api.openai.com"
        # Some OpenAI regions use 52.84.* but we need to be careful
        # Only match if it's not already matched as Anthropic
        if ip.startswith("52.84."):
            # OpenAI uses 52.84.42.*, 52.84.43.*, etc. in some regions
            # But to avoid false positives, we'll be conservative
            # If reverse DNS fails, we'll check the hostname instead
            pass
        
        # Google AI (various ranges)
        if (ip.startswith("142.250.") or ip.startswith("172.217.") or 
            ip.startswith("216.58.") or ip.startswith("172.253.")):
            return "generativelanguage.googleapis.com"
        
        return None
    
    def save_report(self, summary: Dict, output_file: Path):
        """Save summary to JSON file"""
        output_file.write_text(json.dumps(summary, indent=2))
        print(f"\n✓ Report saved to: {output_file}")


# CLI integration
def monitor_network(duration: int = 60, output_file: Optional[Path] = None):
    """
    CLI function for network monitoring
    """
    monitor = NetworkMonitor()
    summary = monitor.monitor(duration_seconds=duration)
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    print(f"Duration: {summary['scan_duration']}s")
    print(f"Total AI Connections: {summary['total_connections']}")
    print(f"\nUnique AI Services: {', '.join(summary['unique_services']) if summary['unique_services'] else 'None'}")
    
    if summary['services']:
        print("\nConnections by Service:")
        for service, count in summary['services'].items():
            print(f"  • {service}: {count}")
    
    if summary['processes']:
        print("\nConnections by Process:")
        for process, count in summary['processes'].items():
            print(f"  • {process}: {count}")
    
    if summary.get('rag_patterns'):
        print("\n🚨 RAG Patterns Detected:")
        for rag in summary['rag_patterns']:
            print(f"  • Process: {rag['process']} (PID: {rag['pid']})")
            print(f"    AI Services: {', '.join(rag['ai_services'])}")
            print(f"    Vector DBs: {', '.join(rag['vector_dbs'])}")
            print(f"    Confidence: {rag['confidence']}")
    
    # Save if requested
    if output_file:
        monitor.save_report(summary, output_file)
    
    return summary
