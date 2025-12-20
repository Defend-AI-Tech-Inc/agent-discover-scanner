"""
Correlation Engine: Match code findings with network activity.

Creates unified agent inventory and detects Ghost Agents.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class AgentInventoryItem:
    """Unified agent inventory entry."""
    agent_id: str
    classification: str  # "confirmed", "zombie", "ghost", "unknown"
    risk_level: str  # "critical", "high", "medium", "low"
    
    # Code-based attributes
    code_file: Optional[str] = None
    framework: Optional[str] = None
    rule_id: Optional[str] = None
    has_code_execution: bool = False
    
    # Network-based attributes
    network_provider: Optional[str] = None
    last_seen: Optional[str] = None
    process_name: Optional[str] = None
    
    # Metadata
    discovered_at: str = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        return asdict(self)


class CorrelationEngine:
    """
    Correlates code findings with network findings to create unified inventory.
    
    Classification Logic:
    - CONFIRMED: Found in code AND active network traffic
    - ZOMBIE: Found in code but NO network traffic (deprecated/unused)
    - GHOST: Network traffic but NOT found in code (CRITICAL - unmanaged)
    - UNKNOWN: Found in code, not yet seen in network (not deployed yet)
    """
    
    @classmethod
    def load_code_findings(cls, sarif_path: Path) -> List[Dict]:
        """Load code scan findings from SARIF file."""
        if not sarif_path.exists():
            return []
        
        try:
            with open(sarif_path, 'r') as f:
                sarif = json.load(f)
            
            findings = []
            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    findings.append({
                        'rule_id': result.get('ruleId'),
                        'file_path': result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                        'line': result['locations'][0]['physicalLocation']['region']['startLine'],
                        'message': result['message']['text'],
                        'level': result.get('level', 'warning')
                    })
            
            return findings
        except (json.JSONDecodeError, KeyError):
            return []
    
    @classmethod
    def load_network_findings(cls, network_path: Path) -> List[Dict]:
        """Load network monitoring findings from JSON file."""
        if not network_path.exists():
            return []
        
        try:
            with open(network_path, 'r') as f:
                data = json.load(f)
            
            return data.get('findings', [])
        except (json.JSONDecodeError, KeyError):
            return []
    
    @classmethod
    def extract_framework_from_rule(cls, rule_id: str) -> str:
        """Map rule ID to framework name."""
        mapping = {
            'DAI001': 'AutoGen',
            'DAI002': 'CrewAI',
            'DAI003': 'LangChain/LangGraph',
            'DAI004': 'Shadow AI'
        }
        return mapping.get(rule_id, 'Unknown')
    
    @classmethod
    def correlate(
        cls,
        code_findings: List[Dict],
        network_findings: List[Dict]
    ) -> Dict[str, List[AgentInventoryItem]]:
        """
        Correlate code and network findings.
        
        Returns:
            Dictionary with classifications: {
                'confirmed': [...],
                'zombie': [...],
                'ghost': [...],
                'unknown': [...]
            }
        """
        inventory = {
            'confirmed': [],
            'zombie': [],
            'ghost': [],
            'unknown': []
        }
        
        # Track which code files have network activity
        active_files = set()
        
        # Process network findings to identify active providers
        active_providers = {}
        for nf in network_findings:
            provider = nf.get('provider', 'unknown')
            process = nf.get('process_name', 'unknown')
            active_providers[provider] = {
                'process': process,
                'timestamp': nf.get('timestamp')
            }
        
        # Process code findings
        for cf in code_findings:
            agent_id = f"{cf['file_path']}:{cf['line']}"
            framework = cls.extract_framework_from_rule(cf['rule_id'])
            
            # Check if this is a high-risk configuration
            has_code_exec = 'CODE EXECUTION' in cf['message'] or 'HIGH RISK' in cf['message']
            is_shadow_ai = cf['rule_id'] == 'DAI004'
            
            # Determine risk level
            if has_code_exec or is_shadow_ai:
                risk = 'critical' if is_shadow_ai else 'high'
            else:
                risk = 'medium'
            
            # Try to correlate with network activity
            # Simple heuristic: if framework matches provider, it's likely the same agent
            network_match = None
            if 'openai' in framework.lower() and 'openai' in active_providers:
                network_match = 'openai'
            elif 'anthropic' in framework.lower() and 'anthropic' in active_providers:
                network_match = 'anthropic'
            elif 'Shadow AI' in framework:
                # Shadow AI findings are code-based detection of direct clients
                # Check if corresponding provider is active
                if 'OpenAI' in cf['message'] and 'openai' in active_providers:
                    network_match = 'openai'
                elif 'Anthropic' in cf['message'] and 'anthropic' in active_providers:
                    network_match = 'anthropic'
            
            # Classify the agent
            if network_match:
                # CONFIRMED: Code + Network
                classification = 'confirmed'
                active_files.add(cf['file_path'])
                provider_info = active_providers[network_match]
                
                item = AgentInventoryItem(
                    agent_id=agent_id,
                    classification=classification,
                    risk_level=risk,
                    code_file=cf['file_path'],
                    framework=framework,
                    rule_id=cf['rule_id'],
                    has_code_execution=has_code_exec,
                    network_provider=network_match,
                    last_seen=provider_info['timestamp'],
                    process_name=provider_info['process']
                )
            else:
                # UNKNOWN: Code only, no network traffic yet
                # (or ZOMBIE if we had historical data showing it used to be active)
                classification = 'unknown'
                
                item = AgentInventoryItem(
                    agent_id=agent_id,
                    classification=classification,
                    risk_level=risk,
                    code_file=cf['file_path'],
                    framework=framework,
                    rule_id=cf['rule_id'],
                    has_code_execution=has_code_exec
                )
            
            inventory[classification].append(item)
        
        # Identify GHOST AGENTS: Network traffic but no code found
        for provider, info in active_providers.items():
            # Check if this provider is accounted for in code findings
            has_code = any(
                provider in item.network_provider for item in inventory['confirmed']
                if item.network_provider
            )
            
            if not has_code:
                # GHOST: Network activity with no corresponding code
                ghost_id = f"ghost:{provider}:{info['process']}"
                
                item = AgentInventoryItem(
                    agent_id=ghost_id,
                    classification='ghost',
                    risk_level='critical',  # Ghosts are always critical
                    network_provider=provider,
                    last_seen=info['timestamp'],
                    process_name=info['process']
                )
                
                inventory['ghost'].append(item)
        
        return inventory
    
    @classmethod
    def generate_report(
        cls,
        inventory: Dict[str, List[AgentInventoryItem]],
        output_path: Optional[Path] = None
    ) -> Dict:
        """
        Generate correlation report with statistics.
        
        Returns:
            Report dictionary with metrics and inventory
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_agents': sum(len(items) for items in inventory.values()),
                'confirmed': len(inventory['confirmed']),
                'unknown': len(inventory['unknown']),
                'zombie': len(inventory['zombie']),
                'ghost': len(inventory['ghost']),
            },
            'risk_breakdown': {
                'critical': sum(
                    1 for items in inventory.values() 
                    for item in items 
                    if item.risk_level == 'critical'
                ),
                'high': sum(
                    1 for items in inventory.values() 
                    for item in items 
                    if item.risk_level == 'high'
                ),
                'medium': sum(
                    1 for items in inventory.values() 
                    for item in items 
                    if item.risk_level == 'medium'
                ),
            },
            'inventory': {
                classification: [item.to_dict() for item in items]
                for classification, items in inventory.items()
            }
        }
        
        # Save to file if requested
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report


    @classmethod
    def analyze_behaviors(
        cls,
        network_findings: List[Dict]
    ) -> Dict:
        """
        Analyze network findings for behavioral patterns.
        
        Returns:
            Dictionary with detected behavioral patterns
        """
        from agent_discover_scanner.behavioral_patterns import BehavioralAnalyzer
        
        patterns = BehavioralAnalyzer.analyze_all_patterns(network_findings)
        
        # Count patterns
        summary = {
            'total_patterns': sum(len(p) for p in patterns.values()),
            'react_loops': len(patterns['react_loops']),
            'rag_patterns': len(patterns['rag_patterns']),
            'multi_turn': len(patterns['multi_turn']),
            'token_bursts': len(patterns['token_bursts'])
        }
        
        return {
            'summary': summary,
            'patterns': {
                pattern_type: [
                    {
                        'type': p.pattern_type,
                        'confidence': p.confidence,
                        'description': p.description,
                        'indicators': p.indicators,
                        'timestamp': p.timestamp,
                        'metadata': p.metadata
                    }
                    for p in pattern_list
                ]
                for pattern_type, pattern_list in patterns.items()
            }
        }
