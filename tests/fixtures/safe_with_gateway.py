"""
Test fixture: OpenAI client using DefendAI Gateway (SAFE)
Should NOT trigger any findings
"""

from openai import OpenAI

# Safe - using DefendAI Gateway
managed_client = OpenAI(api_key="sk-...", base_url="https://gateway.defendai.com/v1")

response = managed_client.chat.completions.create(
    model="gpt-4", messages=[{"role": "user", "content": "Hello"}]
)
