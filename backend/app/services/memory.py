"""Persistent threat memory with optional Cognee integration."""

import json
from pathlib import Path
from typing import Any, Dict, List

from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding


class ThreatMemory:
    """Store structured findings in Cognee, falling back to local JSONL memory."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.local_path = Path(settings.local_memory_path)

    async def recall_domain(self, company_domain: str) -> List[Dict[str, Any]]:
        """Recall previous local investigations for diff intelligence."""

        findings: List[Dict[str, Any]] = []
        if not self.local_path.exists():
            return findings
        with self.local_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if payload.get("company_domain") == company_domain:
                    findings.append(payload)
        return findings[-50:]

    async def diff_intelligence(
        self, company_domain: str, finding: ClassifiedFinding
    ) -> Dict[str, Any]:
        """Compare the current finding with prior investigations for the domain."""

        previous = await self.recall_domain(company_domain)
        current_key = self._finding_key(finding.model_dump(mode="json"))
        prior_keys = {self._finding_key(item) for item in previous}
        is_new = current_key not in prior_keys
        prior_high = [
            item
            for item in previous
            if int(item.get("risk_score") or 0) >= 70
        ][-5:]

        return {
            "domain": company_domain,
            "is_new_vulnerability": is_new,
            "previous_investigation_count": len(previous),
            "threat_timeline": [
                {
                    "timestamp": item.get("timestamp"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "risk_score": item.get("risk_score"),
                }
                for item in prior_high
            ],
            "diff_summary": (
                "New vulnerability compared to stored ARGUS memory."
                if is_new
                else "Previously observed signal; compare recurrence and drift."
            ),
        }

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

    def _finding_key(self, payload: Dict[str, Any]) -> str:
        return "|".join(
            [
                str(payload.get("collector") or payload.get("type") or ""),
                str(payload.get("title") or "").strip().lower(),
                str(payload.get("url") or "").strip().lower(),
            ]
        )
