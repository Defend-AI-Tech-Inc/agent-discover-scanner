"""
Test fixture: Direct OpenAI client usage (Shadow AI)
Should trigger: DAI004 - error
"""

from openai import AsyncOpenAI, OpenAI

# Direct OpenAI client - NO DefendAI Gateway
unmanaged_client = OpenAI(api_key="sk-...")

# Async client - also unmanaged
async_client = AsyncOpenAI(api_key="sk-...")

# Using the client
response = unmanaged_client.chat.completions.create(
    model="gpt-4", messages=[{"role": "user", "content": "Hello"}]
)
