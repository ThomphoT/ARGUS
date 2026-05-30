"""Tests for TriggerWare webhook alert integration."""

import json

import pytest

from backend.app.models import ClassifiedFinding, CollectorName, Severity
from backend.app.services.alerts import TriggerWareAlerts


class _FakeResponse:
    def raise_for_status(self):
        return None


class _FakeAsyncClient:
    posts = []

    def __init__(self, *args, **kwargs):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def post(self, url, content, headers):
        self.posts.append({"url": url, "content": content, "headers": headers})
        return _FakeResponse()


def _finding(severity: Severity, risk_score: int) -> ClassifiedFinding:
    return ClassifiedFinding(
        company_domain="example.com",
        collector=CollectorName.LEAK_SCANNER,
        title="Exposed credential dump",
        description="Credentials associated with example.com were found.",
        severity=severity,
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_triggerware_alert_sends_threat_detected_event(
    monkeypatch, test_settings
):
    monkeypatch.setattr("backend.app.services.alerts.httpx.AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.posts = []
    test_settings.triggerware_webhook_url = "https://triggerware.example/webhook"

    sent = await TriggerWareAlerts(test_settings).maybe_alert(
        _finding(Severity.HIGH, 80)
    )

    assert sent is True
    assert len(_FakeAsyncClient.posts) == 1
    request = _FakeAsyncClient.posts[0]
    assert request["url"] == "https://triggerware.example/webhook"
    assert request["headers"]["Content-Type"] == "application/json"
    payload = json.loads(request["content"])
    assert payload["source"] == "ARGUS"
    assert payload["event"] == "threat_detected"
    assert payload["workflow"]["type"] == "autonomous_defense"
    assert "firewall_block_signal" in payload["workflow"]["simulated_actions"]
    assert payload["finding"]["severity"] == "HIGH"
    assert payload["finding"]["risk_score"] == 80


@pytest.mark.asyncio
async def test_triggerware_alert_skips_medium_findings(monkeypatch, test_settings):
    monkeypatch.setattr("backend.app.services.alerts.httpx.AsyncClient", _FakeAsyncClient)
    _FakeAsyncClient.posts = []
    test_settings.triggerware_webhook_url = "https://triggerware.example/webhook"

    sent = await TriggerWareAlerts(test_settings).maybe_alert(
        _finding(Severity.MEDIUM, 50)
    )

    assert sent is False
    assert _FakeAsyncClient.posts == []
