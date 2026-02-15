from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class EndpointAIApplication:
    """Discovered AI application on endpoint"""
    name: str  # "ChatGPT Desktop", "Cursor", "GitHub Copilot"
    version: str
    install_path: str
    install_date: datetime
    last_used: Optional[datetime]
    vendor: str  # "OpenAI", "Anthropic", "GitHub"

@dataclass
class EndpointAIPackage:
    """Discovered AI package (pip, npm, etc.)"""
    name: str  # "openai", "langchain", "anthropic"
    version: str
    package_manager: str  # "pip", "npm", "go"
    install_path: str
    last_modified: datetime

@dataclass
class EndpointAIConnection:
    """Active connection to AI service"""
    process_name: str
    process_id: int
    remote_address: str  # "104.18.7.192" (api.openai.com)
    remote_port: int
    remote_hostname: str  # "api.openai.com"
    connection_state: str  # "ESTABLISHED", "CLOSE_WAIT"
    bytes_sent: int
    bytes_received: int
    timestamp: datetime

@dataclass
class EndpointBrowserActivity:
    """Browser-based AI usage"""
    url: str  # "https://chatgpt.com"
    title: str
    browser: str  # "Chrome", "Firefox", "Safari"
    visit_count: int
    last_visit: datetime
    total_time_seconds: int

@dataclass
class EndpointDiscovery:
    """Complete endpoint discovery result"""
    hostname: str
    os_type: str  # "Windows", "macOS", "Linux"
    os_version: str
    username: str
    ip_address: str
    scan_timestamp: datetime
    
    applications: List[EndpointAIApplication]
    packages: List[EndpointAIPackage]
    connections: List[EndpointAIConnection]
    browser_activity: List[EndpointBrowserActivity]
    
    @property
    def total_ai_instances(self) -> int:
        return (len(self.applications) + 
                len(self.packages) + 
                len(set(c.remote_hostname for c in self.connections)) +
                len(self.browser_activity))
    
    @property
    def risk_score(self) -> int:
        """Calculate risk score 0-100"""
        score = 0
        
        # Unapproved apps
        score += len(self.applications) * 10
        
        # Active connections to AI
        score += len(self.connections) * 5
        
        # Browser activity (lower risk)
        score += len(self.browser_activity) * 2
        
        # Packages (development usage)
        score += len(self.packages) * 3
        
        return min(score, 100)
