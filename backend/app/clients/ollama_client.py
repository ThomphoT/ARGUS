"""Ollama reasoning client for ARGUS."""

import os

from ollama import chat

from backend.app.core.config import get_settings


def call_ollama(prompt):
    """Core ARGUS LLM driver using chevalblanc/gpt-4o-mini through Ollama."""

    settings = get_settings()
    os.environ.setdefault("OLLAMA_HOST", settings.ollama_host)
    response = chat(
        model="chevalblanc/gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    message = getattr(response, "message", None)
    if message is not None and hasattr(message, "content"):
        return message.content
    if isinstance(response, dict):
        return response.get("message", {}).get("content", "")
    return str(response)
