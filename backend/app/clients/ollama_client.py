"""Ollama reasoning client for ARGUS."""

from ollama import Client

from backend.app.core.config import get_settings


def call_ollama(prompt: str) -> str:
    """Core ARGUS LLM driver using Ollama."""
    settings = get_settings()
    client = Client(host=settings.ollama_host, timeout=5)
    response = client.chat(
        model=settings.ollama_model,
        messages=[{"role": "user", "content": prompt}],
    )
    message = getattr(response, "message", None)
    if message is not None and hasattr(message, "content"):
        return message.content
    if isinstance(response, dict):
        return response.get("message", {}).get("content", "")
    return str(response)
