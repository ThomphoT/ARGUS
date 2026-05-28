"""Tests for backend API and WebSocket scan contracts."""

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
