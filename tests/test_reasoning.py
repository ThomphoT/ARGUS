"""Tests for LangGraph-backed risk reasoning."""

import pytest

from backend.app.models import CollectorName, RawFinding, Severity
from backend.app.services import reasoning
from backend.app.services.reasoning import ThreatReasoner, _fallback_analysis


def test_fallback_analysis_marks_exposed_secrets_critical():
    raw = RawFinding(
        company_domain="example.com",
        collector=CollectorName.LEAK_SCANNER,
        title="Potential .env exposure",
        description="API_KEY and SECRET_KEY appeared in a search result",
    )

    analysis = _fallback_analysis(raw)

    assert analysis["severity"] == "CRITICAL"
    assert analysis["risk_score"] == 95


@pytest.mark.asyncio
async def test_threat_reasoner_uses_fallback_when_llm_fails(monkeypatch):
    async def fail_llm(prompt):
        raise RuntimeError("provider down")

    monkeypatch.setattr(reasoning, "_call_llm", fail_llm)
    raw = RawFinding(
        company_domain="example.com",
        collector=CollectorName.ATTACK_SIMULATOR,
        title="Public S3 bucket",
        description="bucket listing discovered",
    )

    finding = await ThreatReasoner().classify(raw)

    assert finding.severity == Severity.HIGH
    assert finding.risk_score == 80
    assert finding.recommendations
