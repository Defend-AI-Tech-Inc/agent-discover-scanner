import os
import platform
import socket
from datetime import datetime
from typing import List, Dict
from agent_discover_scanner.models.endpoint_discovery import (
    EndpointDiscovery, EndpointAIApplication, EndpointAIPackage,
    EndpointAIConnection, EndpointBrowserActivity
)

class OsqueryResultParser:
    """Convert raw osquery results to EndpointDiscovery model"""
    
    @staticmethod
    def parse_applications(raw_results: List[Dict]) -> List[EndpointAIApplication]:
        """Parse desktop applications from osquery"""
        apps = []
        
        for row in raw_results:
            apps.append(EndpointAIApplication(
                name=row.get("name", "Unknown"),
                version=row.get("version", "unknown"),
                install_path=row.get("path", ""),
                install_date=datetime.now(),  # osquery doesn't always have this
                last_used=None,
                vendor=OsqueryResultParser._infer_vendor(row.get("name", ""))
            ))
        
        return apps
    
    @staticmethod
    def parse_packages(raw_results: List[Dict], package_type: str) -> List[EndpointAIPackage]:
        """Parse Python/NPM packages from osquery"""
        packages = []
        
        for row in raw_results:
            packages.append(EndpointAIPackage(
                name=row.get("name", "unknown"),
                version=row.get("version", "unknown"),
                package_manager=package_type,  # "pip" or "npm"
                install_path=row.get("install_path", row.get("directory", "")),
                last_modified=datetime.now()
            ))
        
        return packages
    
    @staticmethod
    def parse_connections(raw_results: List[Dict]) -> List[EndpointAIConnection]:
        """Parse active network connections from osquery"""
        connections = []
        parser = OsqueryResultParser()
        
        for row in raw_results:
            connections.append(EndpointAIConnection(
                process_name=row.get("process_name", "unknown"),
                process_id=int(row.get("pid", 0)),
                remote_address=row.get("remote_address", ""),
                remote_port=int(row.get("remote_port", 0)),
                remote_hostname=parser._resolve_hostname(row.get("remote_address", "")),
                connection_state=row.get("state", "UNKNOWN"),
                bytes_sent=0,  # osquery doesn't track this easily
                bytes_received=0,
                timestamp=datetime.now()
            ))
        
        return connections
    
    @staticmethod
    def parse_browser_history(raw_results: List[Dict]) -> List[EndpointBrowserActivity]:
        """Parse browser history from osquery"""
        activities = []
        
        for row in raw_results:
            # Parse last_visit timestamp if present
            try:
                last_visit = datetime.fromisoformat(row.get("last_visit_time", ""))
            except:
                last_visit = datetime.now()
            
            activities.append(EndpointBrowserActivity(
                url=row.get("url", ""),
                title=row.get("title", ""),
                browser="Chrome",  # We only query Chrome for now
                visit_count=int(row.get("visit_count", 0)),
                last_visit=last_visit,
                total_time_seconds=0  # Not tracked by osquery
            ))
        
        return activities
    
    @staticmethod
    def _infer_vendor(app_name: str) -> str:
        """Infer vendor from application name"""
        name_lower = app_name.lower()
        
        if "chatgpt" in name_lower or "openai" in name_lower:
            return "OpenAI"
        elif "claude" in name_lower or "anthropic" in name_lower:
            return "Anthropic"
        elif "cursor" in name_lower:
            return "Cursor Inc"
        elif "copilot" in name_lower:
            return "GitHub"
        elif "tabnine" in name_lower:
            return "Tabnine"
        else:
            return "Unknown"
    
    def _resolve_hostname(self, ip_address: str) -> str:
        """Resolve IP to probable AI service hostname"""
        # More precise IP matching
        if ip_address.startswith("13.107.") or ip_address.startswith("52.84."):
            return "api.openai.com"
        elif ip_address.startswith("52.") or ip_address.startswith("54."):
            # AWS - could be Anthropic but not certain
            return "api.anthropic.com (AWS)"
        elif ip_address.startswith("104.18.") or ip_address.startswith("104.26."):
            return "claude.ai"
        else:
            return ip_address
    
    @staticmethod
    def create_endpoint_discovery(
        hostname: str,
        osquery_results: Dict[str, List[Dict]]
    ) -> EndpointDiscovery:
        """
        Convert raw osquery results to EndpointDiscovery model
        
        Args:
            hostname: Machine hostname
            osquery_results: Dict from OsqueryExecutor.discover_all()
        
        Returns:
            EndpointDiscovery object
        """
        import platform
        import socket
        
        # Parse each category
        applications = OsqueryResultParser.parse_applications(
            osquery_results.get("desktop_apps", [])
        )
        
        python_packages = OsqueryResultParser.parse_packages(
            osquery_results.get("python_packages", []),
            package_type="pip"
        )
        
        npm_packages = OsqueryResultParser.parse_packages(
            osquery_results.get("npm_packages", []),
            package_type="npm"
        )
        
        packages = python_packages + npm_packages
        
        connections = OsqueryResultParser.parse_connections(
            osquery_results.get("ai_connections", [])
        )
        
        browser_activity = OsqueryResultParser.parse_browser_history(
            osquery_results.get("chrome_history", [])
        )
        
        # Get system info
        os_type = platform.system()
        os_version = platform.release()
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        
        # Try to get IP address
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
        except:
            ip_address = "127.0.0.1"
        
        return EndpointDiscovery(
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            username=username,
            ip_address=ip_address,
            scan_timestamp=datetime.now(),
            applications=applications,
            packages=packages,
            connections=connections,
            browser_activity=browser_activity
        )
