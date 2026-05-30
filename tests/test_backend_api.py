"""Tests for backend API and WebSocket scan contracts."""

import asyncio

from fastapi.testclient import TestClient

from backend.app.main import app


def test_scan_endpoint_streams_agent_events(monkeypatch):
    calls = []

    class FakeAgent:
        def __init__(self, settings):
            self.settings = settings

        async def stream_scan(self, domain, focus, attack_mode):
            calls.append((domain, focus, attack_mode))
            yield {
                "type": "complete",
                "data": {
                    "company_domain": domain,
                    "score": 0,
                    "finding_count": 0,
                    "severity_counts": {},
                    "recommendations": [],
                },
            }

    monkeypatch.setattr("backend.app.main.ArgusAgent", FakeAgent)
    client = TestClient(app)

    response = client.post(
        "/scan",
        json={
            "company_domain": "https://Example.com/login",
            "focus": "osint",
            "attack_mode": True,
        },
    )

    assert response.status_code == 200
    assert calls == [("example.com", "osint", True)]
    assert response.json()["events"][0]["type"] == "complete"


def test_websocket_scan_streams_findings_and_complete(monkeypatch):
    calls = []

    class FakeAgent:
        def __init__(self, settings):
            self.settings = settings

        async def stream_scan(self, domain, focus, attack_mode):
            calls.append((domain, focus, attack_mode))
            yield {
                "type": "finding",
                "data": {
                    "company_domain": domain,
                    "severity": "LOW",
                    "title": "Demo finding",
                    "type": "leak_scanner",
                },
            }
            yield {
                "type": "complete",
                "data": {
                    "company_domain": domain,
                    "score": 25,
                    "finding_count": 1,
                    "severity_counts": {"LOW": 1},
                    "recommendations": ["Review finding"],
                },
            }

    monkeypatch.setattr("backend.app.main.ArgusAgent", FakeAgent)
    client = TestClient(app)

    with client.websocket_connect("/ws/Example.com") as websocket:
        websocket.send_json({"focus": "vulnerabilities", "attack_mode": False})
        finding = websocket.receive_json()
        complete = websocket.receive_json()

    assert calls == [("example.com", "vulnerabilities", False)]
    assert finding["type"] == "finding"
    assert finding["data"]["title"] == "Demo finding"
    assert complete["type"] == "complete"
    assert complete["data"]["score"] == 25


def test_websocket_scan_reports_invalid_domain():
    client = TestClient(app)

    with client.websocket_connect("/ws/not-a-domain") as websocket:
        error = websocket.receive_json()

    assert error["type"] == "error"
    assert "valid domain" in error["data"]["message"]


def test_websocket_halt_returns_remediation_report(monkeypatch):
    class FakeAgent:
        def __init__(self, settings):
            self.settings = settings

        async def stream_scan(self, domain, focus, attack_mode):
            yield {
                "type": "finding",
                "data": {
                    "company_domain": domain,
                    "severity": "HIGH",
                    "risk_score": 80,
                    "title": "Suspicious exfiltration signal from 203.0.113.10",
                    "description": "Possible attacker node observed near Johannesburg",
                    "type": "attack_simulator",
                    "evidence": {"country": "South Africa"},
                },
            }
            await asyncio.sleep(10)

    monkeypatch.setattr("backend.app.main.ArgusAgent", FakeAgent)
    client = TestClient(app)

    with client.websocket_connect("/ws/Example.com") as websocket:
        websocket.send_json({"focus": "attack", "attack_mode": True})
        finding = websocket.receive_json()
        websocket.send_json({"type": "halt"})
        report = websocket.receive_json()

    assert finding["type"] == "finding"
    assert report["type"] == "remediation_report"
    assert report["data"]["containment_status"] == "pending_configuration"
    assert report["data"]["attacker"]["ip"] == "203.0.113.10"
    assert report["data"]["attacker"]["location"] == "South Africa"
    assert report["data"]["summary"]["records_recovered"] == 1


def test_remediate_endpoint_requires_halt_command():
    client = TestClient(app)

    response = client.post(
        "/api/remediate",
        json={
            "target_id": "example.com",
            "command": "deploy",
            "threat_data": {"severity": "HIGH", "risk_score": 80},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported remediation command."


def test_remediate_endpoint_returns_manual_payload():
    client = TestClient(app)

    response = client.post(
        "/api/remediate",
        json={
            "target_id": "example.com",
            "command": "halt",
            "threat_data": {
                "severity": "CRITICAL",
                "risk_score": 95,
                "title": "Public S3 bucket leaked API key",
                "url": "https://s3.amazonaws.com/example-public",
                "evidence": {
                    "defense_recommendation": (
                        "Audit bucket policies and rotate exposed API keys."
                    )
                },
            },
        },
    )

    assert response.status_code == 200
    data = response.json()
    payload = data["containment_payload"]
    actions = {step["action"] for step in payload["playbook_steps"]}
    assert data["deployment_status"] == "Payload Ready for Deployment"
    assert payload["authorization"]["mode"] == "human_in_the_loop"
    assert "disable_public_storage_access" in actions
    assert "revoke_or_rotate_tokens" in actions


def test_websocket_stop_cancels_scan_without_remediation(monkeypatch):
    class FakeAgent:
        def __init__(self, settings):
            self.settings = settings

        async def stream_scan(self, domain, focus, attack_mode):
            yield {
                "type": "finding",
                "data": {
                    "company_domain": domain,
                    "severity": "LOW",
                    "title": "Cancelable finding",
                    "type": "leak_scanner",
                },
            }
            await asyncio.sleep(10)

    monkeypatch.setattr("backend.app.main.ArgusAgent", FakeAgent)
    client = TestClient(app)

    with client.websocket_connect("/ws/Example.com") as websocket:
        websocket.send_json({"focus": "full", "attack_mode": False})
        finding = websocket.receive_json()
        websocket.send_json({"type": "stop"})
        stopped = websocket.receive_json()

    assert finding["type"] == "finding"
    assert stopped["type"] == "stopped"
    assert stopped["data"]["message"] == "Scan stopped by user."
