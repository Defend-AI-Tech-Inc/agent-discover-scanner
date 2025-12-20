"""
Tests for behavioral pattern detection.
"""
from datetime import datetime, timedelta
from agent_discover_scanner.behavioral_patterns import BehavioralAnalyzer, BehavioralPattern


def test_is_llm_provider():
    """Test LLM provider detection."""
    assert BehavioralAnalyzer._is_llm_provider("openai") == True
    assert BehavioralAnalyzer._is_llm_provider("anthropic") == True
    assert BehavioralAnalyzer._is_llm_provider("google") == True
    assert BehavioralAnalyzer._is_llm_provider("api.openai.com") == True
    assert BehavioralAnalyzer._is_llm_provider("pinecone") == False
    assert BehavioralAnalyzer._is_llm_provider("") == False
    assert BehavioralAnalyzer._is_llm_provider(None) == False


def test_is_vector_db():
    """Test vector database detection."""
    assert BehavioralAnalyzer._is_vector_db("pinecone") == True
    assert BehavioralAnalyzer._is_vector_db("weaviate") == True
    assert BehavioralAnalyzer._is_vector_db("qdrant") == True
    assert BehavioralAnalyzer._is_vector_db("chroma") == True
    assert BehavioralAnalyzer._is_vector_db("openai") == False
    assert BehavioralAnalyzer._is_vector_db("") == False


def test_time_difference():
    """Test time difference calculation."""
    t1 = "2025-12-20T12:00:00Z"
    t2 = "2025-12-20T12:00:05Z"
    
    diff = BehavioralAnalyzer._time_difference(t1, t2)
    assert diff == 5.0
    
    # Should handle None
    assert BehavioralAnalyzer._time_difference(None, t2) is None
    assert BehavioralAnalyzer._time_difference(t1, None) is None


def test_detect_react_pattern_with_rapid_calls():
    """Test ReAct pattern detection with rapid successive LLM calls."""
    base_time = datetime.now()
    
    findings = [
        {
            'timestamp': base_time.isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=5)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=10)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        }
    ]
    
    patterns = BehavioralAnalyzer.detect_react_pattern(findings)
    
    assert len(patterns) == 1
    assert patterns[0].pattern_type == "react_loop"
    assert patterns[0].confidence == "high"
    # FIX: Check the actual text in description
    assert "multiple rapid" in patterns[0].description.lower()


def test_detect_react_pattern_no_pattern():
    """Test ReAct detection with insufficient data."""
    findings = [
        {
            'timestamp': datetime.now().isoformat(),
            'provider': 'openai',
            'process_name': 'test.py'
        }
    ]
    
    # Only 1 finding, need 3+ for ReAct
    patterns = BehavioralAnalyzer.detect_react_pattern(findings)
    assert len(patterns) == 0


def test_detect_rag_pattern():
    """Test RAG pattern detection (Vector DB + LLM)."""
    base_time = datetime.now()
    
    findings = [
        {
            'timestamp': base_time.isoformat(),
            'provider': 'pinecone',
            'process_name': 'rag_agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=2)).isoformat(),
            'provider': 'openai',
            'process_name': 'rag_agent.py'
        }
    ]
    
    patterns = BehavioralAnalyzer.detect_rag_pattern(findings)
    
    assert len(patterns) == 1
    assert patterns[0].pattern_type == "rag"
    assert patterns[0].confidence == "high"
    assert "Vector DB" in patterns[0].description
    assert patterns[0].metadata['vector_db'] == 'pinecone'
    assert patterns[0].metadata['llm'] == 'openai'


def test_detect_rag_pattern_missing_components():
    """Test RAG detection when missing LLM or Vector DB."""
    findings = [
        {
            'timestamp': datetime.now().isoformat(),
            'provider': 'openai',
            'process_name': 'test.py'
        }
    ]
    
    # Only LLM, no vector DB
    patterns = BehavioralAnalyzer.detect_rag_pattern(findings)
    assert len(patterns) == 0


def test_detect_multi_turn_conversation():
    """Test multi-turn conversation detection."""
    base_time = datetime.now()
    
    # 6 LLM calls within 60 seconds (need 5+)
    findings = [
        {
            'timestamp': (base_time + timedelta(seconds=i*10)).isoformat(),
            'provider': 'openai',
            'process_name': 'chatbot.py'
        }
        for i in range(6)  # FIX: Need 6 to ensure 5+ window
    ]
    
    patterns = BehavioralAnalyzer.detect_multi_turn_conversation(findings)
    
    assert len(patterns) == 1
    assert patterns[0].pattern_type == "multi_turn"
    assert patterns[0].metadata['call_count'] == 6


def test_detect_multi_turn_insufficient_calls():
    """Test multi-turn detection with too few calls."""
    findings = [
        {
            'timestamp': datetime.now().isoformat(),
            'provider': 'openai',
            'process_name': 'test.py'
        }
    ] * 3  # Only 3 calls, need 5+
    
    patterns = BehavioralAnalyzer.detect_multi_turn_conversation(findings)
    assert len(patterns) == 0


def test_analyze_all_patterns():
    """Test running all pattern detectors."""
    base_time = datetime.now()
    
    # FIX: Need 6 LLM calls total to trigger multi-turn (5+ requirement)
    findings = [
        # RAG pattern: Vector DB then LLM
        {
            'timestamp': base_time.isoformat(),
            'provider': 'pinecone',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=1)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        # More LLM calls for ReAct and multi-turn
        {
            'timestamp': (base_time + timedelta(seconds=5)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=10)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=15)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=20)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        },
        {
            'timestamp': (base_time + timedelta(seconds=25)).isoformat(),
            'provider': 'openai',
            'process_name': 'agent.py'
        }
    ]
    
    results = BehavioralAnalyzer.analyze_all_patterns(findings)
    
    # Should detect multiple patterns
    assert len(results['rag_patterns']) == 1
    assert len(results['react_loops']) == 1
    assert len(results['multi_turn']) == 1
    assert 'token_bursts' in results  # Even if empty


def test_behavioral_pattern_dataclass():
    """Test BehavioralPattern dataclass."""
    pattern = BehavioralPattern(
        pattern_type="test",
        confidence="high",
        description="Test pattern",
        indicators=["indicator1", "indicator2"],
        timestamp=datetime.now().isoformat(),
        metadata={'key': 'value'}
    )
    
    assert pattern.pattern_type == "test"
    assert pattern.confidence == "high"
    assert len(pattern.indicators) == 2
    assert pattern.metadata['key'] == 'value'
