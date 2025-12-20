"""
Behavioral pattern detection for identifying agentic activity.

Detects:
- ReAct loops (Reasoning + Acting cycles)
- Token burst patterns (streaming responses)
- Multi-turn conversations
- RAG patterns (LLM + Vector DB)
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class BehavioralPattern:
    """Represents a detected behavioral pattern."""
    pattern_type: str  # "react_loop", "token_burst", "multi_turn", "rag"
    confidence: str  # "high", "medium", "low"
    description: str
    indicators: List[str]
    timestamp: str
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BehavioralAnalyzer:
    """
    Analyzes network findings for behavioral patterns that indicate agentic activity.
    """
    
    # Time windows for pattern detection
    REACT_WINDOW_SECONDS = 30  # ReAct loop typically completes in 30s
    BURST_WINDOW_SECONDS = 5   # Token bursts happen quickly
    MULTI_TURN_WINDOW_SECONDS = 300  # 5 minute conversation window
    
    @classmethod
    def detect_react_pattern(cls, findings: List[Dict]) -> List[BehavioralPattern]:
        """
        Detect ReAct (Reasoning + Acting) loops.
        
        Pattern: LLM call → short pause → LLM call → short pause (3+ times)
        
        This indicates:
        - Agent is "thinking" (LLM call)
        - Agent is "acting" (tool execution - not visible in our network scan)
        - Agent is "observing" (next LLM call with results)
        """
        patterns = []
        
        if len(findings) < 3:
            return patterns
        
        # Group findings by provider and look for rapid succession
        llm_findings = [f for f in findings if cls._is_llm_provider(f.get('provider'))]
        
        if len(llm_findings) < 3:
            return patterns
        
        # Check for rapid successive calls (< 30 seconds apart)
        consecutive_calls = 0
        for i in range(len(llm_findings) - 1):
            time_diff = cls._time_difference(
                llm_findings[i].get('timestamp'),
                llm_findings[i + 1].get('timestamp')
            )
            
            if time_diff and time_diff < cls.REACT_WINDOW_SECONDS:
                consecutive_calls += 1
            else:
                consecutive_calls = 0
            
            # If we see 3+ rapid calls, likely a ReAct loop
            if consecutive_calls >= 2:
                pattern = BehavioralPattern(
                    pattern_type="react_loop",
                    confidence="high",
                    description="ReAct agent loop detected: Multiple rapid LLM calls indicating reasoning-action cycles",
                    indicators=[
                        f"{consecutive_calls + 1} consecutive LLM calls within {cls.REACT_WINDOW_SECONDS}s",
                        f"Provider: {llm_findings[i].get('provider')}",
                        f"Process: {llm_findings[i].get('process_name', 'unknown')}"
                    ],
                    timestamp=llm_findings[i].get('timestamp'),
                    metadata={
                        'call_count': consecutive_calls + 1,
                        'provider': llm_findings[i].get('provider'),
                        'process': llm_findings[i].get('process_name')
                    }
                )
                patterns.append(pattern)
                break  # Found one, that's enough
        
        return patterns
    
    @classmethod
    def detect_rag_pattern(cls, findings: List[Dict]) -> List[BehavioralPattern]:
        """
        Detect RAG (Retrieval-Augmented Generation) patterns.
        
        Pattern: Vector DB query → LLM call (within seconds)
        
        Indicates agent is:
        1. Querying vector database for relevant context
        2. Passing context to LLM for generation
        """
        patterns = []
        
        llm_findings = [f for f in findings if cls._is_llm_provider(f.get('provider'))]
        vector_findings = [f for f in findings if cls._is_vector_db(f.get('provider'))]
        
        if not (llm_findings and vector_findings):
            return patterns
        
        # Check for temporal correlation
        for vf in vector_findings:
            for lf in llm_findings:
                time_diff = cls._time_difference(
                    vf.get('timestamp'),
                    lf.get('timestamp')
                )
                
                if time_diff and 0 < time_diff < 60:  # Within 1 minute
                    pattern = BehavioralPattern(
                        pattern_type="rag",
                        confidence="high",
                        description="RAG pattern detected: Vector DB query followed by LLM call",
                        indicators=[
                            f"Vector DB: {vf.get('provider')}",
                            f"LLM: {lf.get('provider')}",
                            f"Time gap: {time_diff}s"
                        ],
                        timestamp=vf.get('timestamp'),
                        metadata={
                            'vector_db': vf.get('provider'),
                            'llm': lf.get('provider'),
                            'time_gap': time_diff
                        }
                    )
                    patterns.append(pattern)
                    return patterns  # Found one, that's enough
        
        return patterns
    
    @classmethod
    def detect_multi_turn_conversation(cls, findings: List[Dict]) -> List[BehavioralPattern]:
        """
        Detect multi-turn conversations (sustained agent activity).
        
        Pattern: Multiple LLM calls over extended period (5+ calls in 5 minutes)
        
        Indicates:
        - Interactive agent
        - Conversational workflow
        - Complex multi-step task
        """
        patterns = []
        
        llm_findings = [f for f in findings if cls._is_llm_provider(f.get('provider'))]
        
        if len(llm_findings) < 5:
            return patterns
        
        # Check if 5+ calls within 5 minute window
        first_call = llm_findings[0].get('timestamp')
        last_call = llm_findings[-1].get('timestamp')
        
        time_span = cls._time_difference(first_call, last_call)
        
        if time_span and time_span < cls.MULTI_TURN_WINDOW_SECONDS:
            pattern = BehavioralPattern(
                pattern_type="multi_turn",
                confidence="medium",
                description=f"Multi-turn conversation detected: {len(llm_findings)} LLM calls in {time_span}s",
                indicators=[
                    f"{len(llm_findings)} LLM API calls",
                    f"Conversation span: {time_span}s",
                    f"Provider: {llm_findings[0].get('provider')}"
                ],
                timestamp=first_call,
                metadata={
                    'call_count': len(llm_findings),
                    'duration_seconds': time_span,
                    'provider': llm_findings[0].get('provider')
                }
            )
            patterns.append(pattern)
        
        return patterns
    
    @classmethod
    def detect_token_burst(cls, findings: List[Dict]) -> List[BehavioralPattern]:
        """
        Detect token burst patterns (streaming responses).
        
        Pattern: High-frequency data transfer (indicates streaming)
        
        Note: This is a placeholder - actual implementation would need
        byte count data from network monitor.
        """
        # This would require enhanced network monitoring with packet size data
        # For now, return empty as we don't have that data
        return []
    
    @classmethod
    def analyze_all_patterns(cls, findings: List[Dict]) -> Dict[str, List[BehavioralPattern]]:
        """
        Run all pattern detectors and return results.
        
        Returns:
            Dictionary with pattern types as keys and detected patterns as values
        """
        results = {
            'react_loops': cls.detect_react_pattern(findings),
            'rag_patterns': cls.detect_rag_pattern(findings),
            'multi_turn': cls.detect_multi_turn_conversation(findings),
            'token_bursts': cls.detect_token_burst(findings)
        }
        
        return results
    
    @staticmethod
    def _is_llm_provider(provider: str) -> bool:
        """Check if provider is an LLM provider."""
        if not provider:
            return False
        
        llm_providers = ['openai', 'anthropic', 'google', 'cohere', 'bedrock', 'azure-openai']
        return any(p in provider.lower() for p in llm_providers)
    
    @staticmethod
    def _is_vector_db(provider: str) -> bool:
        """Check if provider is a vector database."""
        if not provider:
            return False
        
        vector_dbs = ['pinecone', 'weaviate', 'qdrant', 'chroma']
        return any(db in provider.lower() for db in vector_dbs)
    
    @staticmethod
    def _time_difference(timestamp1: str, timestamp2: str) -> Optional[float]:
        """Calculate time difference in seconds between two ISO timestamps."""
        if not (timestamp1 and timestamp2):
            return None
        
        try:
            t1 = datetime.fromisoformat(timestamp1.replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(timestamp2.replace('Z', '+00:00'))
            return abs((t2 - t1).total_seconds())
        except (ValueError, AttributeError):
            return None
