"""
Network Monitor V2 - Improved AI connection detection using psutil

Fixes WebSocket detection issue by monitoring ALL established connections,
not just new ones.
"""

import psutil
import socket
import threading
import time
import re
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json

import httpx

_logger = logging.getLogger(__name__)

# Compiled IPv4 pattern — used to distinguish raw IPs from resolved hostnames.
_IPv4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# ── Forward-DNS correlation ────────────────────────────────────────────────────

# AWS regions where Bedrock runtime endpoints exist. These are pre-resolved at
# startup so that rotating Bedrock IPs can be matched without reverse-DNS.
_BEDROCK_REGIONS: tuple[str, ...] = (
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ap-southeast-2",
    "ap-south-1", "sa-east-1", "ca-central-1",
    "us-gov-west-1", "ap-east-1", "me-south-1", "il-central-1",
)

# Hostnames that are forward-resolved at NetworkMonitor startup and on every
# TTL refresh.  The Bedrock regional variants are the primary motivation —
# bedrock-runtime.{region}.amazonaws.com rotates across dozens of generic
# EC2 IPs whose reverse-DNS gives ec2-X-X-X.compute-1.amazonaws.com, not the
# service name.  Proactive forward resolution maps every live IP back to the
# service hostname before psutil even sees the connection.
_LLM_SEED_HOSTNAMES: list[str] = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.together.xyz",
    "api.x.ai",
    "api.cohere.ai",
    "api.perplexity.ai",
    *[f"bedrock-runtime.{r}.amazonaws.com" for r in _BEDROCK_REGIONS],
    *[f"bedrock-agent-runtime.{r}.amazonaws.com" for r in _BEDROCK_REGIONS],
]

# External LLM APIs exclusively use HTTPS.  Connections to these providers on
# any other port are almost certainly email (993 IMAPS), database (5432), or
# some other protocol sharing IP space with the AI provider's CDN.
# Private/loopback IPs (Ollama, local inference) are exempt from this check.
_EXTERNAL_LLM_PORTS: frozenset[int] = frozenset({443, 8443})


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is loopback, link-local, or RFC-1918 / RFC-6598 private space."""
    if not ip or ip in ("0.0.0.0", "::1", "::"):
        return True
    if ip.startswith("127.") or ip.startswith("169.254."):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    # IPv6 ULA (fc00::/7)
    if ip.lower().startswith(("fc", "fd", "fe80")):
        return True
    # RFC-1918: 172.16.0.0/12  (172.16–172.31)
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return True
    except (ValueError, IndexError):
        pass
    return False


class ForwardDNSCache:
    """
    Short-TTL forward-DNS correlation cache: IP → hostname.

    Seeded by proactively resolving all known LLM service hostnames via
    ``socket.getaddrinfo`` (the OS resolver, which honours /etc/hosts and
    the system DNS cache).  Every resolved IP is stored with a TTL so that
    rotating Bedrock / CDN IPs are refreshed automatically.

    Also populated bidirectionally from successful reverse-DNS lookups in
    ``_resolve_hostname`` so that *any* forward mapping the OS has performed
    is captured without a separate seeding pass.

    Thread-safe: a single ``threading.Lock`` guards all cache mutations.
    """

    DEFAULT_TTL: float = 60.0   # seconds; matches typical DNS TTLs for AWS endpoints

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        # ip → (hostname, expires_at_monotonic)
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    # ── write ─────────────────────────────────────────────────────────────────

    def observe(self, hostname: str, ip: str) -> None:
        """Record that *hostname* forward-resolved to *ip*.  Thread-safe."""
        expires = time.monotonic() + self._ttl
        with self._lock:
            self._cache[ip] = (hostname, expires)

    def seed(self, hostnames: list[str]) -> None:
        """
        Resolve each hostname via ``socket.getaddrinfo`` and cache all
        returned IPs.  Silently skips any hostname that fails to resolve
        (network unavailable, NXDOMAIN, etc.).

        Designed to be called in a background daemon thread so it never
        blocks the monitor's main loop.
        """
        for hostname in hostnames:
            try:
                infos = socket.getaddrinfo(
                    hostname, None,
                    type=socket.SOCK_STREAM,
                    flags=socket.AI_ADDRCONFIG,
                )
                for info in infos:
                    ip = info[4][0]
                    if ip:
                        self.observe(hostname, ip)
            except (socket.gaierror, OSError):
                pass

    # ── read ──────────────────────────────────────────────────────────────────

    def lookup(self, ip: str) -> str | None:
        """
        Return the hostname associated with *ip* if it is cached and not
        expired.  Evicts expired entries on read.  Thread-safe.
        """
        with self._lock:
            entry = self._cache.get(ip)
        if entry is None:
            return None
        hostname, expires = entry
        if time.monotonic() > expires:
            with self._lock:
                self._cache.pop(ip, None)
            return None
        return hostname

    def size(self) -> int:
        """Return the number of cached entries (for testing / metrics)."""
        with self._lock:
            return len(self._cache)

_BEDROCK_RANGES_URL = "https://ranges.defendai.ai/bedrock.json"
_BEDROCK_FALLBACK_PATH = Path(__file__).parent / "data" / "bedrock_ips_fallback.json"

# Module-level cache — None means "not yet fetched"; populated on first call.
_bedrock_ip_cache: set[str] | None = None


def fetch_bedrock_ip_ranges() -> set[str]:
    """Return the set of Bedrock endpoint IPs to use for classification.

    Fetch order:
    1. Module-level cache (populated after the first successful call).
    2. Live feed at ``_BEDROCK_RANGES_URL`` (3-second timeout).
    3. Bundled fallback at ``data/bedrock_ips_fallback.json``.

    Returns an empty set if every source fails so callers degrade gracefully.
    """
    global _bedrock_ip_cache
    if _bedrock_ip_cache is not None:
        return _bedrock_ip_cache

    # -- Live feed -------------------------------------------------------
    try:
        resp = httpx.get(_BEDROCK_RANGES_URL, timeout=3.0)
        resp.raise_for_status()
        ips: set[str] = set(resp.json().get("flat_ips", []))
        if ips:
            _bedrock_ip_cache = ips
            _logger.debug("Bedrock IP ranges loaded from live feed (%d IPs).", len(ips))
            return _bedrock_ip_cache
        _logger.debug("Live Bedrock IP feed returned an empty flat_ips list; trying fallback.")
    except Exception as exc:  # network errors, JSON decode, non-2xx, …
        _logger.debug("Bedrock IP ranges feed unavailable (%s); using bundled fallback.", exc)

    # -- Bundled fallback ------------------------------------------------
    try:
        data = json.loads(_BEDROCK_FALLBACK_PATH.read_text(encoding="utf-8"))
        ips = set(data.get("flat_ips", []))
        _bedrock_ip_cache = ips
        _logger.debug("Bedrock IP ranges loaded from fallback file (%d IPs).", len(ips))
    except Exception as exc:
        _logger.warning("Could not load Bedrock IP fallback file: %s", exc)
        _bedrock_ip_cache = set()

    return _bedrock_ip_cache

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
    # Populated by process introspection (L1 rules run against the entry script)
    entry_script: str | None = None         # resolved abs path to the Python entry script
    framework: str | None = None            # e.g. "LangChain/LangGraph"; None if not detected
    framework_confidence: str | None = None # "high" = entry script direct, "medium" = project scan

class NetworkMonitor:
    """Improved network monitor using psutil for better WebSocket detection"""
    
    # AI service domains and their classifications
    AI_SERVICES = {
        # OpenAI
        'openai.com': 'OpenAI',
        'api.openai.com': 'OpenAI API',
        'chatgpt.com': 'ChatGPT',
        'chat.openai.com': 'ChatGPT',
        
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
        'gemini.google.com': 'Gemini',
        
        # AWS Bedrock — region-scoped dynamic hostnames; matched by substring
        'bedrock-runtime': 'AWS Bedrock',
        'bedrock-agent-runtime': 'AWS Bedrock Agent',

        # xAI / Grok
        'x.ai': 'xAI',
        'api.x.ai': 'Grok API',

        # Groq (inference platform)
        'groq.com': 'Groq',
        'api.groq.com': 'Groq API',

        # Mistral AI
        'mistral.ai': 'Mistral',
        'api.mistral.ai': 'Mistral API',

        # DeepSeek
        'deepseek.com': 'DeepSeek',
        'api.deepseek.com': 'DeepSeek API',

        # Together AI
        'together.ai': 'Together AI',
        'api.together.xyz': 'Together AI API',

        # Azure OpenAI (tenant-scoped; matched by substring in _is_ai_service)
        'openai.azure.com': 'Azure OpenAI',

        # Other AI services
        'cohere.ai': 'Cohere',
        'api.cohere.ai': 'Cohere API',
        'replicate.com': 'Replicate',
        'huggingface.co': 'HuggingFace',
        'perplexity.ai': 'Perplexity',
        'api.perplexity.ai': 'Perplexity API',
        
        # Development tools
        'github.com': 'GitHub Copilot',  # Note: matches all GitHub connections, not just Copilot
        'api.github.com': 'GitHub Copilot',  # GitHub API (used by Copilot)
        'copilot.microsoft.com': 'Microsoft Copilot',
        'api.cursor.sh': 'Cursor',
        'codeium.com': 'Codeium',
    }
        
    # Vector database domains (includes both old and new domains for compatibility)
    VECTOR_DBS = {
        'pinecone.io': 'Pinecone',
        'api.pinecone.io': 'Pinecone',
        'weaviate.io': 'Weaviate',
        'weaviate.cloud': 'Weaviate',  # Hosted/cloud version
        'qdrant.io': 'Qdrant',
        'qdrant.tech': 'Qdrant',  # Legacy domain
        'milvus.io': 'Milvus',
        'chromadb.io': 'ChromaDB',
        'chroma.io': 'ChromaDB',  # Legacy domain
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
        """Classify hostname as AI service or vector DB.

        The lookup order is:
        1. Bedrock IP set — checked first when *hostname* is a bare IPv4 address
           (i.e. reverse-DNS resolution failed or returned the raw IP).
        2. AI service domain substrings.
        3. Vector-DB domain substrings.
        4. Encoded-IP heuristics for amazonaws.com reverse-DNS names.
        """
        # -- 1. Bedrock IP set (raw IPv4 only) ---------------------------
        if _IPv4_RE.match(hostname):
            if hostname in fetch_bedrock_ip_ranges():
                return "AWS Bedrock"

        hostname_lower = hostname.lower()

        # -- 2. AI service domain substrings ----------------------------
        for domain, service_name in self.AI_SERVICES.items():
            if domain in hostname_lower:
                return service_name

        # -- 3. Vector DB domain substrings -----------------------------
        for domain, service_name in self.VECTOR_DBS.items():
            if domain in hostname_lower:
                return service_name

        # -- 4. Encoded-IP heuristics for amazonaws.com names -----------
        # e.g. "ec2-52-85-xxx.compute-1.amazonaws.com"
        if "amazonaws.com" in hostname_lower or "compute-1.amazonaws.com" in hostname_lower:
            ip_match = re.search(r'(\d+)-(\d+)-(\d+)', hostname_lower)
            if ip_match:
                first_octet = ip_match.group(1)
                second_octet = ip_match.group(2)
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
    
    def __init__(self) -> None:
        self._dns_cache: dict[str, str] = {}   # ip → hostname (reverse-DNS cache, no TTL)
        self._fwd_dns = ForwardDNSCache()       # ip → hostname (forward-DNS, short TTL)
        # Seed the forward-DNS cache in a background daemon thread so __init__ is
        # non-blocking.  The seed resolves all LLM service hostnames (including every
        # regional Bedrock variant) and populates the ip→hostname map before the first
        # scan cycle finishes.
        threading.Thread(
            target=self._fwd_dns.seed,
            args=(_LLM_SEED_HOSTNAMES,),
            daemon=True,
            name="fwd-dns-seed",
        ).start()
    
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
                    # Process introspection fields (None when not detected)
                    'framework': conn.framework,
                    'framework_confidence': conn.framework_confidence,
                    'entry_script': conn.entry_script,
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

                    # Port filter: external LLM APIs only ever use HTTPS (443 / 8443).
                    # Skip any external connection on a non-HTTPS port to prevent
                    # false-positives like :993 IMAP where Google/CDN IP ranges
                    # overlap with AI provider address space.
                    # Private IPs (Ollama, local inference, internal proxies) are exempt.
                    if (
                        not _is_private_ip(conn.raddr.ip)
                        and conn.raddr.port not in _EXTERNAL_LLM_PORTS
                    ):
                        continue

                    # Resolve hostname (with IP-based detection fallback)
                    hostname = self._resolve_hostname(conn.raddr.ip)
                    
                    # Check if it's an AI service (check both hostname and IP)
                    ai_service = self._classify_ai_service(hostname) or self._classify_ai_service_by_ip(conn.raddr.ip)
                    if ai_service:
                        ai_conn = AIConnection(
                            timestamp=datetime.now(),
                            process_name=proc_name,
                            pid=proc_pid,
                            process_path=proc_exe,
                            remote_host=hostname,
                            remote_ip=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            local_port=conn.laddr.port,
                            ai_service=ai_service,
                            connection_type='tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                        )
                        # ── Layer 2 process introspection ──────────────────
                        # Run L1 framework-detection rules (DAI001–007) against
                        # the process's entry script so the connection carries
                        # framework evidence for the correlator.
                        try:
                            from agent_discover_scanner.process_introspection import introspect_process
                            intr = introspect_process(proc_pid)
                            ai_conn.entry_script = intr.entry_script
                            ai_conn.framework = intr.framework
                            ai_conn.framework_confidence = intr.framework_confidence
                        except Exception:
                            pass  # introspection is best-effort; never block detection
                        connections.append(ai_conn)
            
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
        print(f"   Observing runtime behavior ({duration_seconds}s)...")

        all_connections = []
        unique_connections = set()  # Track (process, service) pairs
        start_time = time.time()
        last_tick_at = start_time
        tick_interval = 15  # print a progress line every 15s if nothing detected

        while time.time() - start_time < duration_seconds:
            connections = self.get_active_ai_connections()
            detected_this_round = False

            for conn in connections:
                conn_key = (conn.process_name, conn.ai_service, conn.remote_host)
                if conn_key not in unique_connections:
                    unique_connections.add(conn_key)
                    all_connections.append(conn)
                    detected_this_round = True
                    print(f"[DETECT] {conn.ai_service} connection from {conn.process_name} "
                          f"(PID: {conn.pid}) → {conn.remote_host}:{conn.remote_port}")

            now = time.time()
            elapsed = int(now - start_time)
            remaining = max(0, duration_seconds - elapsed)
            if not detected_this_round and now - last_tick_at >= tick_interval and remaining > 5:
                print(f"   [{elapsed}s] Watching for AI connections... ({remaining}s remaining)")
                last_tick_at = now

            time.sleep(interval_seconds)
        
        # Generate summary
        summary = self._generate_summary(all_connections, duration_seconds)
        return summary
    
    def _resolve_hostname(self, ip: str) -> str:
        """
        Resolve an IP address to a service hostname.

        Resolution order
        ----------------
        1. **Forward-DNS correlation cache** (``_fwd_dns``) — highest priority.
           Populated at startup by resolving all known LLM hostnames and refreshed
           every TTL seconds.  This recovers service names like
           ``bedrock-runtime.us-east-1.amazonaws.com`` from rotating IPs whose
           reverse-DNS would only return a generic EC2 hostname.
        2. **Reverse-DNS cache** (``_dns_cache``) — previously resolved via
           ``socket.gethostbyaddr``.
        3. **Live reverse-DNS** (``socket.gethostbyaddr``) — result is stored in
           both caches so the forward-DNS map stays warm for the next lookup.
        4. **IP-pattern heuristics** (``_detect_service_by_ip``) — last resort
           when all DNS paths fail.
        """
        # ── 1. Forward-DNS correlation (authoritative, short-TTL) ─────────────
        fwd = self._fwd_dns.lookup(ip)
        if fwd:
            self._dns_cache[ip] = fwd   # keep reverse cache warm too
            return fwd

        # ── 2. Reverse-DNS cache hit ───────────────────────────────────────────
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        # ── 3. Live reverse-DNS lookup ─────────────────────────────────────────
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            hostname_l = (hostname or "").lower()
            # Cloudflare generic reverse-DNS is not actionable; try IP heuristics instead.
            if hostname_l and ("cloudflare" in hostname_l or hostname_l.endswith(".cdn.cloudflare.net")):
                ip_based_hostname = self._detect_service_by_ip(ip)
                if ip_based_hostname:
                    self._dns_cache[ip] = ip_based_hostname
                    return ip_based_hostname
            result = hostname or ip
            self._dns_cache[ip] = result
            # Populate forward-DNS cache bidirectionally so subsequent lookups
            # of the same hostname's other IPs benefit from this resolution.
            if hostname:
                self._fwd_dns.observe(hostname, ip)
            return result
        except (socket.herror, socket.gaierror, socket.timeout):
            pass

        # ── 4. IP-pattern heuristics ───────────────────────────────────────────
        ip_based_hostname = self._detect_service_by_ip(ip)
        if ip_based_hostname:
            self._dns_cache[ip] = ip_based_hostname
            return ip_based_hostname
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
