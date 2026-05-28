"""OpenAI reasoning client for ARGUS."""

from openai import OpenAI

from backend.app.core.config import get_settings


def call_openai(prompt: str) -> str:
    """Core ARGUS LLM driver using OpenAI."""
    settings = get_settings()
    client = OpenAI(
        api_key=settings.openai_api_key,
        max_retries=0,
        timeout=5.0,
    )
    response = client.chat.completions.create(
        model=settings.openai_model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""
