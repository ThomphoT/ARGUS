"""Persistent threat memory with optional Cognee integration."""

import inspect
import json
import logging
from pathlib import Path
from typing import Any

from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding

logger = logging.getLogger("argus")


class ThreatMemory:
    """Store structured findings in Cognee, falling back to local JSONL memory."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.local_path = Path(settings.local_memory_path)
        self.last_error = ""
        self.last_backend = "local_jsonl"

    async def store(self, finding: ClassifiedFinding) -> None:
        payload = finding.model_dump(mode="json")
        if self.settings.cognee_enabled:
            try:
                await self._store_cognee(payload)
                self.last_error = ""
                self.last_backend = "cognee"
                return
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.last_backend = "local_jsonl"
                logger.warning(
                    "Cognee storage failed; falling back to local JSONL: %s",
                    self.last_error,
                )

        self._store_local(payload)

    async def _store_cognee(self, payload: dict) -> None:
        import cognee  # type: ignore

        document = json.dumps(payload, sort_keys=True)
        await self._maybe_await(
            cognee.add([document], dataset_name=self.settings.cognee_dataset)
        )
        await self._maybe_await(cognee.cognify(datasets=[self.settings.cognee_dataset]))

    async def _maybe_await(self, value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    def _store_local(self, payload: dict) -> None:
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        with self.local_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
