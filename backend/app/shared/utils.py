"""Rate limiting and caching helpers for live Bright Data collection."""

import asyncio
import time
from collections import deque
from typing import Any, Hashable


class TTLCache:
    """Small in-memory TTL cache for repeated SERP and MCP queries."""

    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._items: dict[Hashable, tuple[float, Any]] = {}

    def get(self, key: Hashable) -> Any:
        item = self._items.get(key)
        if not item:
            return None
        expires_at, value = item
        if expires_at <= time.monotonic():
            self._items.pop(key, None)
            return None
        return value

    def set(self, key: Hashable, value: Any) -> None:
        self._items[key] = (time.monotonic() + self.ttl_seconds, value)


class AsyncRateLimiter:
    """Simple rolling-window rate limiter for external API calls."""

    def __init__(self, max_calls: int, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.window_seconds:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                wait_for = self.window_seconds - (now - self._calls[0])
                await asyncio.sleep(max(wait_for, 0))
            self._calls.append(time.monotonic())
