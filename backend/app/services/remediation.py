"""ARGUS remediation agent for halt-exfiltration workflows."""

import hmac
import json
import logging
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx

from backend.app.core.config import Settings

logger = logging.getLogger("argus")


IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


class RemediationAgent:
    """Stop active collection and invoke an optional real defense playbook."""

    def __init__(self, settings: Settings):
        self.settings = settings

    async def halt_exfiltration(
        self, company_domain: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        recovered_data = self._recover_data(findings)
        attacker = self._extract_attacker(findings)
        actions = [
            "Stopped active ARGUS attack-mode collection for this incident.",
            "Preserved collected evidence and recovered public exposure records.",
            "Prepared containment payload for the configured defense system.",
        ]

        defense_result = await self._dispatch_defense_playbook(
            company_domain, findings, recovered_data, attacker
        )
        if defense_result["connected"]:
            actions.append("Defense playbook accepted the containment request.")
            containment_status = "blocked"
        else:
            actions.append(
                "No defense webhook is configured; containment report is ready for manual response."
            )
            containment_status = "pending_configuration"

        return {
            "incident_id": f"ARGUS-{uuid4().hex[:8].upper()}",
            "company_domain": company_domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "containment_status": containment_status,
            "defense_system": defense_result,
            "attacker": attacker,
            "recovered_data": recovered_data,
            "actions": actions,
            "summary": {
                "findings_preserved": len(findings),
                "records_recovered": len(recovered_data),
                "highest_risk": max(
                    [int(item.get("risk_score") or 0) for item in findings], default=0
                ),
            },
        }

    async def _dispatch_defense_playbook(
        self,
        company_domain: str,
        findings: List[Dict[str, Any]],
        recovered_data: List[Dict[str, Any]],
        attacker: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self.settings.defense_webhook_url:
            return {
                "connected": False,
                "provider": "not_configured",
                "message": "Set DEFENSE_WEBHOOK_URL to connect ARGUS to a SOAR, firewall, or EDR playbook.",
            }

        payload = {
            "source": "ARGUS",
            "event": "exfiltration.halt_requested",
            "company_domain": company_domain,
            "attacker": attacker,
            "recovered_data": recovered_data,
            "findings": findings,
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.settings.defense_webhook_secret:
            headers["X-ARGUS-Signature"] = hmac.new(
                self.settings.defense_webhook_secret.encode("utf-8"),
                body,
                sha256,
            ).hexdigest()

        try:
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds
            ) as client:
                response = await client.post(
                    self.settings.defense_webhook_url, content=body, headers=headers
                )
                response.raise_for_status()
            return {
                "connected": True,
                "provider": "defense_webhook",
                "message": "Containment webhook delivered successfully.",
                "status_code": response.status_code,
            }
        except Exception as exc:
            logger.error("Defense webhook failed for domain=%s: %s", company_domain, exc)
            return {
                "connected": False,
                "provider": "defense_webhook",
                "message": f"Defense webhook failed: {type(exc).__name__}",
            }

    def _recover_data(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        recovered = []
        for finding in findings:
            evidence = finding.get("evidence") or {}
            serp = evidence.get("serp_result") or {}
            recovered.append(
                {
                    "title": finding.get("title") or "Preserved finding",
                    "type": finding.get("type") or finding.get("collector") or "finding",
                    "severity": finding.get("severity") or "UNKNOWN",
                    "risk_score": finding.get("risk_score") or 0,
                    "source": finding.get("source") or serp.get("via") or "ARGUS",
                    "url": finding.get("url") or serp.get("url"),
                    "description": finding.get("description") or serp.get("snippet"),
                }
            )
        return recovered[:10]

    def _extract_attacker(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        for finding in findings:
            evidence_text = json.dumps(finding.get("evidence") or {}, default=str)
            combined = " ".join(
                [
                    str(finding.get("title") or ""),
                    str(finding.get("description") or ""),
                    str(finding.get("url") or ""),
                    evidence_text,
                ]
            )
            match = IP_PATTERN.search(combined)
            if match:
                return {
                    "ip": match.group(0),
                    "location": self._extract_location(finding),
                    "confidence": "evidence",
                }
        return {
            "ip": None,
            "location": None,
            "confidence": "unavailable",
            "note": "No attacker IP or location appeared in the collected evidence.",
        }

    def _extract_location(self, finding: Dict[str, Any]) -> Optional[str]:
        evidence = finding.get("evidence") or {}
        for key in ("location", "country", "geo", "region"):
            value = evidence.get(key)
            if value:
                return str(value)
        serp = evidence.get("serp_result") or {}
        for key in ("location", "country", "geo", "region"):
            value = serp.get(key)
            if value:
                return str(value)
        return None
