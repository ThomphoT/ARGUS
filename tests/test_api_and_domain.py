"""Tests for API contracts and domain utilities."""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.utils.domain import normalize_domain


def test_health_reports_hackathon_integrations():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "unlock=mcp_unlocker" in body["bright_data"]["mcp_url"]
    assert "llm_provider" in body
    assert "triggerware_configured" in body


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        ("https://Example.com/login", "example.com"),
        ("example.com:443", "example.com"),
        ("sub.example.co.za", "sub.example.co.za"),
    ],
)
def test_normalize_domain_accepts_expected_values(input_value, expected):
    assert normalize_domain(input_value) == expected


def test_normalize_domain_rejects_invalid_values():
    with pytest.raises(ValueError):
        normalize_domain("not a domain")
