"""ARGUS scan orchestration and WebSocket streaming."""

from typing import AsyncIterator, List

from backend.app.clients.bright_data import BrightDataClient
from backend.app.collectors.attack_simulator import AttackSimulator
from backend.app.collectors.domain_monitor import DomainMonitor
from backend.app.collectors.leak_scanner import LeakScanner
from backend.app.core.config import Settings
from backend.app.models import ClassifiedFinding, ScanSummary, Severity
from backend.app.services.alerts import TriggerWareAlerts
from backend.app.services.memory import ThreatMemory
from backend.app.services.reasoning import ThreatReasoner


class ArgusAgent:
    """Production-oriented ARGUS agent using Bright Data, LangGraph, Cognee, and TriggerWare.ai."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.bright_data = BrightDataClient(settings)
        self.reasoner = ThreatReasoner()
        self.memory = ThreatMemory(settings)
        self.alerts = TriggerWareAlerts(settings)
        self.collectors = [
            LeakScanner(self.bright_data),
            DomainMonitor(self.bright_data),
            AttackSimulator(self.bright_data),
        ]

    async def stream_scan(self, company_domain: str) -> AsyncIterator[dict]:
        classified_findings: List[ClassifiedFinding] = []
        for collector in self.collectors:
            async for raw in collector.collect(company_domain):
                finding = await self.reasoner.classify(raw)
                classified_findings.append(finding)
                await self.memory.store(finding)
                await self.alerts.maybe_alert(finding)
                event_data = finding.model_dump(mode="json")
                event_data["type"] = finding.collector.value
                yield {"type": "finding", "data": event_data}

        summary = self.summarize(company_domain, classified_findings)
        yield {"type": "complete", "data": summary.model_dump(mode="json")}

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
