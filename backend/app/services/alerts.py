"""TriggerWare.ai webhook alert integration."""

import hmac
import json
from hashlib import sha256
from typing import Dict

import httpx

from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding, Severity


class TriggerWareAlerts:
    """Fire TriggerWare.ai webhook alerts for HIGH and CRITICAL threats."""

    def __init__(self, settings: Settings):
        self.settings = settings

    async def maybe_alert(self, finding: ClassifiedFinding) -> bool:
        if finding.severity not in {Severity.CRITICAL, Severity.HIGH}:
            return False
        if not self.settings.triggerware_webhook_url:
            return False

        payload = {
            "source": "ARGUS",
            "event": "threat_detected",
            "finding": finding.model_dump(mode="json"),
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.settings.triggerware_secret:
            headers["X-ARGUS-Signature"] = hmac.new(
                self.settings.triggerware_secret.encode("utf-8"),
                body,
                sha256,
            ).hexdigest()

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds
        ) as client:
            response = await client.post(
                self.settings.triggerware_webhook_url, content=body, headers=headers
            )
            response.raise_for_status()
        return True
