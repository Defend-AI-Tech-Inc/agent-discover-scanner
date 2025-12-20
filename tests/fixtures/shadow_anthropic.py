"""
Test fixture: Direct Anthropic client usage (Shadow AI)
Should trigger: DAI004 - error
"""
from anthropic import Anthropic

# Direct Anthropic client - NO DefendAI Gateway
unmanaged_client = Anthropic(
    api_key="sk-ant-..."
)

# Using the client
response = unmanaged_client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)
