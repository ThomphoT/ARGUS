"""Tests for collectors and ARGUS agent orchestration."""

import pytest

from backend.app.clients.bright_data import BrightDataClient
from backend.app.collectors.leak_scanner import LeakScanner
from backend.app.models import CollectorName
from backend.app.services.agent import ArgusAgent


@pytest.mark.asyncio
async def test_leak_scanner_emits_bright_data_finding(test_settings):
    client = BrightDataClient(test_settings)
    collector = LeakScanner(client)

    findings = [finding async for finding in collector.collect("example.com")]

    assert len(findings) == 1
    assert findings[0].collector == CollectorName.LEAK_SCANNER
    assert findings[0].source == "mock_serp"
    assert "query" in findings[0].evidence


def test_agent_selects_attack_simulator_only_when_requested(test_settings):
    agent = ArgusAgent(test_settings)

    standard = [type(item).__name__ for item in agent._select_collectors("full", False)]
    attack = [type(item).__name__ for item in agent._select_collectors("full", True)]

    assert standard == ["LeakScanner", "DomainMonitor", "ThreatIntel"]
    assert attack == ["LeakScanner", "DomainMonitor", "ThreatIntel", "AttackSimulator"]


def test_agent_selects_focus_specific_collectors(test_settings):
    agent = ArgusAgent(test_settings)

    vuln = [
        type(item).__name__
        for item in agent._select_collectors("vulnerabilities", False)
    ]
    osint = [type(item).__name__ for item in agent._select_collectors("osint", False)]

    assert vuln == ["LeakScanner"]
    assert osint == ["DomainMonitor", "ThreatIntel"]
