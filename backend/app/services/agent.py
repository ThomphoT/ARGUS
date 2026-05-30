"""ARGUS scan orchestration and WebSocket streaming."""

import logging
from typing import AsyncIterator, List

from backend.app.clients.bright_data import BrightDataClient
from backend.app.collectors.attack_simulator import AttackSimulator
from backend.app.collectors.domain_monitor import DomainMonitor
from backend.app.collectors.leak_scanner import LeakScanner
from backend.app.collectors.threat_intel import ThreatIntel
from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding, ScanSummary, Severity
from backend.app.services.alerts import TriggerWareAlerts
from backend.app.services.memory import ThreatMemory
from backend.app.services.reasoning import ThreatReasoner

logger = logging.getLogger("argus")


class ArgusAgent:
    """Production-oriented ARGUS agent using Bright Data, LangGraph, Cognee, and TriggerWare.ai."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.bright_data = BrightDataClient(settings)
        self.reasoner = ThreatReasoner()
        self.memory = ThreatMemory(settings)
        self.alerts = TriggerWareAlerts(settings)
        self.collector_map = {
            "leak_scanner": LeakScanner(self.bright_data),
            "domain_monitor": DomainMonitor(self.bright_data),
            "threat_intel": ThreatIntel(self.bright_data),
            "attack_simulator": AttackSimulator(self.bright_data),
        }

    async def stream_scan(
        self, company_domain: str, focus: str = "full", attack_mode: bool = False
    ) -> AsyncIterator[dict]:
        classified_findings: List[ClassifiedFinding] = []
        for collector in self._select_collectors(focus, attack_mode):
            collector_name = type(collector).__name__
            logger.info(
                "Collector %s starting for domain=%s", collector_name, company_domain
            )
            try:
                async for raw in collector.collect(company_domain):
                    yield {
                        "type": "agent_step",
                        "data": {
                            "stage": "understands",
                            "collector": raw.collector.value,
                            "message": f"ARGUS collected signal from {raw.collector.value}: {raw.title}",
                        },
                    }
                    logger.debug(
                        "Collector %s found raw finding: %s",
                        collector_name,
                        raw.title[:60],
                    )
                    prior_context = {
                        "domain": company_domain,
                        "previous_investigation_count": len(
                            await self.memory.recall_domain(company_domain)
                        ),
                    }
                    finding = await self.reasoner.classify(raw, prior_context)
                    diff = await self.memory.diff_intelligence(company_domain, finding)
                    finding.evidence["diff_intelligence"] = diff
                    classified_findings.append(finding)
                    await self.memory.store(finding)
                    yield {
                        "type": "agent_step",
                        "data": {
                            "stage": "decides",
                            "collector": finding.collector.value,
                            "message": (
                                f"Risk scored {finding.risk_score}/100 "
                                f"({finding.severity.value}); {diff['diff_summary']}"
                            ),
                        },
                    }
                    alerted = await self.alerts.maybe_alert(finding)
                    if alerted:
                        yield {
                            "type": "agent_step",
                            "data": {
                                "stage": "acts",
                                "collector": finding.collector.value,
                                "message": "TriggerWare threat_detected workflow fired for autonomous defense.",
                            },
                        }
                    event_data = finding.model_dump(mode="json")
                    event_data["type"] = finding.collector.value
                    yield {"type": "finding", "data": event_data}
            except Exception as exc:
                logger.error(
                    "Collector %s failed for domain=%s: %s: %s",
                    collector_name,
                    company_domain,
                    type(exc).__name__,
                    exc,
                )

        summary = self.summarize(company_domain, classified_findings)
        summary_data = summary.model_dump(mode="json")
        summary_data["live_status"] = self.bright_data.status()
        if not classified_findings:
            if self.bright_data.last_mcp_error or self.bright_data.last_serp_error:
                summary_data["recommendations"] = [
                    "Live collection returned no findings. Verify Bright Data MCP connectivity and zone configuration.",
                    "No mock findings were used because live Bright Data credentials are configured.",
                ]
            else:
                summary_data["recommendations"] = [
                    "No public exposure signals were found by the selected collectors.",
                    "Run a full scan or enable attack mode for broader reconnaissance.",
                ]
        logger.info(
            "Scan summary for domain=%s: score=%d, findings=%d",
            company_domain,
            summary.score,
            summary.finding_count,
        )
        yield {"type": "complete", "data": summary_data}

    def _select_collectors(self, focus: str, attack_mode: bool):
        focus = (focus or "full").lower()
        names = {
            "vulnerabilities": ["leak_scanner"],
            "osint": ["domain_monitor", "threat_intel"],
            "social": ["domain_monitor", "threat_intel"],
            "attack": ["attack_simulator"],
            "full": ["leak_scanner", "domain_monitor", "threat_intel"],
        }.get(focus, ["leak_scanner", "domain_monitor", "threat_intel"])

        if attack_mode and "attack_simulator" not in names:
            names.append("attack_simulator")
        return [self.collector_map[name] for name in names]

    def summarize(
        self, company_domain: str, findings: List[ClassifiedFinding]
    ) -> ScanSummary:
        counts = {severity.value: 0 for severity in Severity}
        for finding in findings:
            counts[finding.severity.value] += 1
        score = max([finding.risk_score for finding in findings], default=0)
        recommendations: List[str] = []
        for finding in sorted(findings, key=lambda item: item.risk_score, reverse=True):
            for recommendation in finding.recommendations:
                if recommendation not in recommendations:
                    recommendations.append(recommendation)
        return ScanSummary(
            company_domain=company_domain,
            score=score,
            finding_count=len(findings),
            severity_counts=counts,
            recommendations=recommendations[:6],
        )
