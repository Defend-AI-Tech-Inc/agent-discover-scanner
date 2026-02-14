from typing import List
from collections import Counter
from agent_discover_scanner.models.endpoint_discovery import EndpointDiscovery

class Layer4Report:
    """Generate Layer 4 endpoint discovery report"""
    
    def __init__(self, endpoints: List[EndpointDiscovery]):
        self.endpoints = endpoints
    
    @property
    def total_endpoints_scanned(self) -> int:
        return len(self.endpoints)
    
    @property
    def endpoints_with_shadow_ai(self) -> int:
        return sum(1 for e in self.endpoints if e.total_ai_instances > 0)
    
    @property
    def shadow_ai_percentage(self) -> float:
        if not self.endpoints:
            return 0.0
        return (self.endpoints_with_shadow_ai / self.total_endpoints_scanned) * 100
    
    @property
    def total_ai_instances_found(self) -> int:
        return sum(e.total_ai_instances for e in self.endpoints)
    
    @property
    def most_common_apps(self) -> List[tuple]:
        """Returns [(app_name, count), ...]"""
        app_counter = Counter()
        for endpoint in self.endpoints:
            for app in endpoint.applications:
                app_counter[app.name] += 1
        return app_counter.most_common(10)
    
    @property
    def most_common_packages(self) -> List[tuple]:
        """Returns [(package_name, count), ...]"""
        pkg_counter = Counter()
        for endpoint in self.endpoints:
            for pkg in endpoint.packages:
                pkg_counter[f"{pkg.name} ({pkg.package_manager})"] += 1
        return pkg_counter.most_common(10)
    
    @property
    def top_ai_services_connected(self) -> List[tuple]:
        """Returns [(service, count), ...]"""
        service_counter = Counter()
        for endpoint in self.endpoints:
            for conn in endpoint.connections:
                service_counter[conn.remote_hostname] += 1
        return service_counter.most_common(10)
    
    @property
    def high_risk_endpoints(self) -> List[EndpointDiscovery]:
        """Endpoints with risk score >= 50"""
        return sorted(
            [e for e in self.endpoints if e.risk_score >= 50],
            key=lambda e: e.risk_score,
            reverse=True
        )
    
    def generate_summary(self) -> dict:
        """Generate summary statistics"""
        return {
            "total_endpoints": self.total_endpoints_scanned,
            "shadow_ai_endpoints": self.endpoints_with_shadow_ai,
            "shadow_ai_percentage": round(self.shadow_ai_percentage, 1),
            "total_ai_instances": self.total_ai_instances_found,
            "high_risk_endpoints": len(self.high_risk_endpoints),
            "top_apps": dict(self.most_common_apps[:5]),
            "top_packages": dict(self.most_common_packages[:5]),
            "top_services": dict(self.top_ai_services_connected[:5])
        }
    
    def generate_markdown_report(self) -> str:
        """Generate markdown report for demo"""
        summary = self.generate_summary()
        
        report = f"""# Layer 4: Endpoint Discovery Report

## Summary

**Total Endpoints Scanned:** {summary['total_endpoints']}
**Endpoints with Shadow AI:** {summary['shadow_ai_endpoints']} ({summary['shadow_ai_percentage']}%)
**Total AI Instances Found:** {summary['total_ai_instances']}
**High-Risk Endpoints:** {summary['high_risk_endpoints']}

---

## Top AI Applications Discovered

"""
        for app, count in self.most_common_apps[:10]:
            report += f"- **{app}**: {count} endpoints\n"
        
        report += "\n---\n\n## Top AI Packages Discovered\n\n"
        
        for pkg, count in self.most_common_packages[:10]:
            report += f"- **{pkg}**: {count} endpoints\n"
        
        report += "\n---\n\n## Most Accessed AI Services\n\n"
        
        for service, count in self.top_ai_services_connected[:10]:
            report += f"- **{service}**: {count} active connections\n"
        
        report += "\n---\n\n## High-Risk Endpoints (Risk Score >= 50)\n\n"
        
        for endpoint in self.high_risk_endpoints[:10]:
            report += f"### {endpoint.hostname} (Risk Score: {endpoint.risk_score})\n\n"
            report += f"- **User:** {endpoint.username}\n"
            report += f"- **OS:** {endpoint.os_type}\n"
            report += f"- **AI Instances:** {endpoint.total_ai_instances}\n"
            
            if endpoint.applications:
                report += f"- **Applications:** {', '.join(a.name for a in endpoint.applications)}\n"
            if endpoint.packages:
                report += f"- **Packages:** {', '.join(p.name for p in endpoint.packages[:5])}\n"
            if endpoint.connections:
                report += f"- **Active Connections:** {', '.join(c.remote_hostname for c in endpoint.connections)}\n"
            
            report += "\n"
        
        return report
