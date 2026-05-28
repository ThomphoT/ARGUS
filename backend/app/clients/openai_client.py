"""Optional OpenAI reasoning client with short timeouts for demo reliability."""

from typing import Any, Dict, List

import httpx

from backend.app.core.config import Settings


async def call_openai(prompt: str, settings: Settings) -> str:
    """Call OpenAI Chat Completions when OPENAI_API_KEY is configured."""

    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    payload: Dict[str, Any] = {
        "model": settings.openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
    data = response.json()
    choices: List[Dict[str, Any]] = data.get("choices", [])
    if not choices:
        raise RuntimeError("OpenAI returned no choices")
    return choices[0]["message"]["content"]
