import httpx

# DAI005 - direct HTTP client
# DAI006 - LLM API endpoint string
OPENAI_URL = "https://api.openai.com/v1/chat/completions"


async def call_llm(prompt: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            OPENAI_URL,
            json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]}
        )
        return response.json()
