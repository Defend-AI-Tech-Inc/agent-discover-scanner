import subprocess
import json
import platform
from typing import List, Dict
from agent_discover_scanner.layer4.osquery_queries import AIDiscoveryQueries

class OsqueryExecutor:
    """
    Execute osquery queries directly via osqueryi
    
    This is the simplest approach - no fleet manager needed.
    Perfect for demos and small-scale assessments.
    """
    
    def __init__(self):
        self.platform = self._detect_platform()
        self.queries = AIDiscoveryQueries.get_all_queries(self.platform)
    
    def _detect_platform(self) -> str:
        """Detect OS platform"""
        system = platform.system().lower()
        if system == "darwin":
            return "darwin"
        elif system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        else:
            raise Exception(f"Unsupported platform: {system}")
    
    def execute_query(self, query: str) -> List[Dict]:
        """
        Execute a single osquery query
        
        Returns:
            List of result rows as dicts
        """
        # Add this validation:
        # Only block shell injection characters, not SQL newlines
        dangerous_patterns = [
            '&&',   # Shell command chaining
            '||',   # Shell command chaining  
            '`',    # Command substitution
            '$(',   # Command substitution
            ';rm',  # Command injection
            ';curl', # Command injection
        ]
        
        query_lower = query.lower()
        if any(pattern in query_lower for pattern in dangerous_patterns):
            raise ValueError("Query contains potentially dangerous patterns")
        
        try:
            # Run osqueryi with JSON output
            result = subprocess.run(
                ["osqueryi", "--json", query],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Query failed: {result.stderr}")
                return []
            
            # Parse JSON output
            results = json.loads(result.stdout)
            return results
            
        except subprocess.TimeoutExpired:
            print(f"Query timed out after 30 seconds")
            return []
        except json.JSONDecodeError:
            print(f"Failed to parse osquery output: {result.stdout}")
            return []
        except FileNotFoundError:
            print("osqueryi not found. Is osquery installed?")
            return []
    
    def discover_all(self) -> Dict[str, List[Dict]]:
        """
        Run all AI discovery queries
        
        Returns:
            Dict of {query_name: results}
        """
        all_results = {}
        
        for query_name, query_sql in self.queries.items():
            print(f"[Layer 4] Running query: {query_name}...")
            results = self.execute_query(query_sql)
            all_results[query_name] = results
            print(f"[Layer 4] Found {len(results)} results")
        
        return all_results
    
    def get_summary_stats(self, results: Dict[str, List[Dict]]) -> Dict:
        """Generate summary statistics"""
        
        total_findings = sum(len(r) for r in results.values())
        
        return {
            "platform": self.platform,
            "total_findings": total_findings,
            "desktop_apps": len(results.get("desktop_apps", [])),
            "python_packages": len(results.get("python_packages", [])),
            "npm_packages": len(results.get("npm_packages", [])),
            "active_connections": len(results.get("ai_connections", [])),
            "chrome_history": len(results.get("chrome_history", [])),
            "vscode_extensions": len(results.get("vscode_extensions", []))
        }
