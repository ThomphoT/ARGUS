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


def generate_remediation_payload(
    company_domain: str,
    findings: List[Dict[str, Any]],
    recovered_data: Optional[List[Dict[str, Any]]] = None,
    attacker: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a halt-exfiltration payload for SOAR, firewall, or EDR playbooks."""

    highest_risk = max([int(item.get("risk_score") or 0) for item in findings], default=0)
    critical_findings = [
        item
        for item in findings
        if int(item.get("risk_score") or 0) >= 70
        or str(item.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
    ]
    indicators = []
    playbook_steps = []
    for finding in critical_findings:
        evidence = finding.get("evidence") or {}
        recommendations = finding.get("recommendations") or []
        if isinstance(recommendations, str):
            recommendations = [recommendations]
        recommendation = (
            evidence.get("defense_recommendation")
            or (recommendations or [None])[0]
            or "Preserve evidence, restrict exposed assets, and validate ownership."
        )
        playbook_steps.extend(_steps_for_finding(finding, recommendation))
        indicators.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score"),
                "url": finding.get("url"),
                "query": evidence.get("query"),
                "collector": finding.get("collector") or finding.get("type"),
                "recommendation": recommendation,
                "containment_profile": _containment_profile(finding),
            }
        )

    return {
        "source": "ARGUS",
        "event": "halt_exfiltration",
        "authorization": {
            "mode": "human_in_the_loop",
            "required": True,
            "granted_by": "operator_click",
            "note": "ARGUS generated this payload only after a manual halt request.",
        },
        "playbook": "contain-open-web-exposure",
        "company_domain": company_domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "priority": "critical" if highest_risk >= 90 else "high" if highest_risk >= 70 else "review",
        "attacker": attacker or {},
        "actions": [
            "block_related_network_indicators",
            "isolate_exposed_assets",
            "revoke_or_rotate_exposed_credentials",
            "open_soar_incident",
            "preserve_evidence_snapshot",
        ],
        "playbook_steps": playbook_steps[:20],
        "indicators": indicators[:25],
        "recovered_data": (recovered_data or [])[:10],
        "summary": {
            "findings_preserved": len(findings),
            "actionable_findings": len(critical_findings),
            "highest_risk": highest_risk,
        },
    }


def _steps_for_finding(
    finding: Dict[str, Any], recommendation: str
) -> List[Dict[str, Any]]:
    text = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("url") or ""),
            json.dumps(finding.get("evidence") or {}, default=str),
        ]
    ).lower()
    steps: List[Dict[str, Any]] = [
        {
            "system": "soar",
            "action": "open_case",
            "parameters": {
                "title": finding.get("title") or "ARGUS high-risk exposure",
                "severity": finding.get("severity") or "HIGH",
                "recommendation": recommendation,
            },
        }
    ]
    if any(
        token in text for token in ["csp", "content-security-policy", "x-frame-options"]
    ):
        steps.append(
            {
                "system": "edge_firewall",
                "action": "enforce_security_headers",
                "parameters": {
                    "headers": {
                        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                        "X-Content-Type-Options": "nosniff",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                    },
                    "recommendation": recommendation,
                },
            }
        )
    if any(
        token in text for token in [".env", "api_key", "secret", "token", "private key"]
    ):
        steps.append(
            {
                "system": "iam",
                "action": "revoke_or_rotate_tokens",
                "parameters": {
                    "scope": "credentials referenced by public exposure evidence",
                    "evidence_url": finding.get("url"),
                    "rotation_priority": "immediate",
                },
            }
        )
    if any(
        token in text
        for token in ["s3", "bucket", "storage.googleapis", "blob.core.windows"]
    ):
        steps.append(
            {
                "system": "cloud_security",
                "action": "disable_public_storage_access",
                "parameters": {
                    "resource_hint": finding.get("url") or finding.get("title"),
                    "enforce_private_acl": True,
                    "block_public_policy": True,
                },
            }
        )
    if ".git/config" in text or "repository" in text:
        steps.append(
            {
                "system": "edge_firewall",
                "action": "block_path",
                "parameters": {
                    "path_pattern": ".git/*",
                    "evidence_url": finding.get("url"),
                },
            }
        )
    attacker_ip = IP_PATTERN.search(text)
    if attacker_ip:
        steps.append(
            {
                "system": "firewall",
                "action": "block_ip",
                "parameters": {"ip": attacker_ip.group(0), "duration": "24h"},
            }
        )
    return steps


def _containment_profile(finding: Dict[str, Any]) -> str:
    recommendations = finding.get("recommendations") or []
    if isinstance(recommendations, str):
        recommendations = [recommendations]
    text = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("url") or ""),
            json.dumps(finding.get("evidence") or {}, default=str),
            " ".join(recommendations),
        ]
    ).lower()
    if any(
        token in text
        for token in ["s3", "bucket", "storage.googleapis", "blob.core.windows"]
    ):
        return "public_cloud_storage"
    if any(
        token in text for token in [".env", "api_key", "secret", "token", "private key"]
    ):
        return "credential_exposure"
    if ".git/config" in text or "repository" in text:
        return "repository_metadata_exposure"
    if IP_PATTERN.search(text):
        return "network_indicator_block"
    if "csp" in text or "content-security-policy" in text:
        return "browser_policy_hardening"
    return "manual_triage"


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

        containment_payload = generate_remediation_payload(
            company_domain, findings, recovered_data, attacker
        )
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
            "containment_payload": containment_payload,
            "deployment_status": "Payload Ready for Deployment",
            "attacker": attacker,
            "recovered_data": recovered_data,
            "actions": actions,
            "summary": {
                "findings_preserved": len(findings),
                "records_recovered": len(recovered_data),
                "highest_risk": max(
                    [int(item.get("risk_score") or 0) for item in findings], default=0
                ),
                "playbook_steps": len(containment_payload.get("playbook_steps", [])),
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

        payload = generate_remediation_payload(
            company_domain, findings, recovered_data, attacker
        )
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
