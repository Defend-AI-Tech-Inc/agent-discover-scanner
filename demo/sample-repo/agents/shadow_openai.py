# DAI004 - Shadow AI (unmanaged OpenAI client)
from openai import OpenAI

client = OpenAI()  # No DefendAI Gateway base_url


def chat(prompt: str):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
