"""Persistent threat memory with optional Cognee integration."""

import json
from pathlib import Path

from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding


class ThreatMemory:
    """Store structured findings in Cognee, falling back to local JSONL memory."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.local_path = Path(settings.local_memory_path)

    async def store(self, finding: ClassifiedFinding) -> None:
        payload = finding.model_dump(mode="json")
        if self.settings.cognee_enabled:
            try:
                import cognee  # type: ignore

                await cognee.add(
                    [json.dumps(payload)], dataset_name=self.settings.cognee_dataset
                )
                await cognee.cognify(datasets=[self.settings.cognee_dataset])
                return
            except Exception:
                pass

        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        with self.local_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
