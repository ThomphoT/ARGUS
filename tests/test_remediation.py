"""Tests for ARGUS halt-exfiltration remediation payloads."""

from backend.app.services.remediation import generate_remediation_payload


def test_generate_remediation_payload_targets_high_risk_findings():
    payload = generate_remediation_payload(
        "example.com",
        [
            {
                "title": "Public .env file",
                "severity": "CRITICAL",
                "risk_score": 95,
                "url": "https://example.com/.env",
                "evidence": {"query": '"example.com" ".env"'},
            },
            {"title": "Low signal", "severity": "LOW", "risk_score": 20},
        ],
        recovered_data=[{"title": "Public .env file"}],
        attacker={"ip": "203.0.113.10"},
    )

    assert payload["event"] == "halt_exfiltration"
    assert payload["priority"] == "critical"
    assert payload["summary"]["findings_preserved"] == 2
    assert payload["summary"]["actionable_findings"] == 1
    assert payload["indicators"][0]["query"] == '"example.com" ".env"'
    assert payload["authorization"]["required"] is True
    assert payload["indicators"][0]["containment_profile"] == "credential_exposure"
    assert "block_related_network_indicators" in payload["actions"]


def test_generate_remediation_payload_uses_attack_simulator_recommendations():
    payload = generate_remediation_payload(
        "example.com",
        [
            {
                "title": "Indexed cloud storage exposure",
                "severity": "HIGH",
                "risk_score": 80,
                "url": "https://storage.googleapis.com/example-public",
                "evidence": {
                    "query": '"example" "storage.googleapis.com"',
                    "defense_recommendation": (
                        "Audit bucket policies, disable public listing, and enforce "
                        "least-privilege IAM on cloud storage."
                    ),
                },
            }
        ],
    )

    actions = {step["action"] for step in payload["playbook_steps"]}
    assert payload["indicators"][0]["recommendation"].startswith("Audit bucket policies")
    assert payload["indicators"][0]["containment_profile"] == "public_cloud_storage"
    assert "disable_public_storage_access" in actions
