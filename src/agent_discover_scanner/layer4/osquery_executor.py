import json
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

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
                timeout=30,
            )

            if result.returncode != 0:
                print(f"[Layer 4] Query failed: {result.stderr.strip()}")
                return []

            # Parse JSON output
            results = json.loads(result.stdout)
            return results

        except subprocess.TimeoutExpired:
            print("[Layer 4] Query timed out after 30 seconds")
            return []
        except json.JSONDecodeError:
            print(f"[Layer 4] Failed to parse osquery output: {result.stdout}")
            return []
        except FileNotFoundError:
            print("[Layer 4] osqueryi not found. Is osquery installed?")
            return []
        except Exception as e:
            # Catch-all: never let a single query abort discovery
            print(f"[Layer 4] Unexpected osquery error: {e}")
            return []
    
    def discover_all(self) -> Dict[str, List[Dict]]:
        """
        Run all AI discovery queries
        
        Returns:
            Dict of {query_name: results}
        """
        all_results: Dict[str, List[Dict]] = {}

        for query_name, query_sql in self.queries.items():
            print(f"[Layer 4] Running query: {query_name}...")
            try:
                results = self.execute_query(query_sql)
            except Exception as e:
                # Extra safety: per-query guard so one failure never stops others
                print(f"[Layer 4] Warning: query '{query_name}' failed: {e}")
                results = []
            all_results[query_name] = results
            print(f"[Layer 4] Found {len(results)} results for {query_name}")

        # Add browser history findings via direct SQLite reads
        browser_history = self.scan_browser_history()
        if browser_history:
            all_results["browser_history"] = browser_history
            print(f"[Layer 4] Browser history findings: {len(browser_history)}")

        return all_results

    def _get_browser_db_candidates(self) -> List[Tuple[str, str, Path]]:
        """
        Return (browser_name, kind, path) tuples where kind is one of:
        'chrome', 'safari', 'firefox'.
        """
        system = platform.system().lower()
        home = Path.home()
        candidates: List[Tuple[str, str, Path]] = []

        if system == "darwin":
            candidates.append(
                (
                    "chrome",
                    "chrome",
                    home / "Library/Application Support/Google/Chrome/Default/History",
                )
            )
            candidates.append(
                (
                    "edge",
                    "chrome",
                    home / "Library/Application Support/Microsoft Edge/Default/History",
                )
            )
            candidates.append(("safari", "safari", home / "Library/Safari/History.db"))
            ff_root = home / "Library/Application Support/Firefox/Profiles"
            if ff_root.exists():
                for profile in ff_root.glob("*.default*"):
                    candidates.append(("firefox", "firefox", profile / "places.sqlite"))

        elif system == "windows":
            local = os.environ.get("LOCALAPPDATA")
            appdata = os.environ.get("APPDATA")
            if local:
                candidates.append(
                    (
                        "chrome",
                        "chrome",
                        Path(local) / "Google" / "Chrome" / "User Data" / "Default" / "History",
                    )
                )
                candidates.append(
                    (
                        "edge",
                        "chrome",
                        Path(local) / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
                    )
                )
            if appdata:
                ff_root = Path(appdata) / "Mozilla" / "Firefox" / "Profiles"
                if ff_root.exists():
                    for profile in ff_root.glob("*.default*"):
                        candidates.append(("firefox", "firefox", profile / "places.sqlite"))

        else:  # linux and others
            candidates.append(
                (
                    "chrome",
                    "chrome",
                    home / ".config" / "google-chrome" / "Default" / "History",
                )
            )
            candidates.append(
                (
                    "chrome",
                    "chrome",
                    home / ".config" / "chromium" / "Default" / "History",
                )
            )
            ff_root = home / ".mozilla" / "firefox"
            if ff_root.exists():
                for profile in ff_root.glob("*.default*"):
                    candidates.append(("firefox", "firefox", profile / "places.sqlite"))

        return candidates

    def scan_browser_history(self) -> List[Dict]:
        """
        Read browser history databases directly via SQLite.

        Returns rows compatible with Layer 4 findings format, marked with
        source: "browser_history".
        """
        candidates = self._get_browser_db_candidates()
        findings: List[Dict] = []

        if not candidates:
            return findings

        # Common URL filter across browsers
        url_filter = """
        url LIKE '%openai%' OR
        url LIKE '%anthropic%' OR
        url LIKE '%claude.ai%' OR
        url LIKE '%gemini%' OR
        url LIKE '%perplexity%' OR
        url LIKE '%huggingface%' OR
        url LIKE '%copilot.microsoft%' OR
        url LIKE '%poe.com%' OR
        url LIKE '%character.ai%'
        """

        for browser, kind, db_path in candidates:
            if not db_path.exists():
                continue

            tmp = Path(tempfile.mktemp(suffix=".db"))
            conn = None
            try:
                shutil.copy2(db_path, tmp)
                conn = sqlite3.connect(tmp)
                cursor = conn.cursor()

                if kind == "chrome":
                    sql = f"""
                    SELECT url, title, last_visit_time
                    FROM urls
                    WHERE {url_filter}
                    ORDER BY last_visit_time DESC
                    LIMIT 100
                    """
                    rows = cursor.execute(sql).fetchall()
                    for url, title, last_visit in rows:
                        findings.append(
                            {
                                "process_name": browser,
                                "pid": None,
                                "url": url,
                                "title": title,
                                "last_visit_time": last_visit,
                                "source": "browser_history",
                            }
                        )

                elif kind == "safari":
                    # Safari: history_visits JOIN history_items (no title column in Safari schema)
                    sql = f"""
                    SELECT history_items.url, history_visits.visit_time
                    FROM history_visits
                    JOIN history_items
                      ON history_visits.history_item = history_items.id
                    WHERE {url_filter}
                    ORDER BY history_visits.visit_time DESC
                    LIMIT 100
                    """
                    rows = cursor.execute(sql).fetchall()
                    for url, visit_time in rows:
                        findings.append(
                            {
                                "process_name": browser,
                                "pid": None,
                                "url": url,
                                "title": None,
                                "last_visit_time": visit_time,
                                "source": "browser_history",
                            }
                        )

                elif kind == "firefox":
                    # Firefox: moz_places table
                    sql = f"""
                    SELECT url, title, last_visit_date
                    FROM moz_places
                    WHERE {url_filter}
                    ORDER BY last_visit_date DESC
                    LIMIT 100
                    """
                    rows = cursor.execute(sql).fetchall()
                    for url, title, last_visit in rows:
                        findings.append(
                            {
                                "process_name": browser,
                                "pid": None,
                                "url": url,
                                "title": title,
                                "last_visit_time": last_visit,
                                "source": "browser_history",
                            }
                        )

            except Exception as e:
                print(f"[Layer 4] Warning: failed to read browser history from {db_path}: {e}")
            finally:
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass
                try:
                    if tmp.exists():
                        tmp.unlink()
                except Exception:
                    pass

        return findings
    
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
