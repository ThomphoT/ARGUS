"""Tests for Cognee-backed memory fallback behavior."""

import json

import pytest

from backend.app.models import ClassifiedFinding, CollectorName, Severity
from backend.app.services.memory import ThreatMemory


def _finding() -> ClassifiedFinding:
    return ClassifiedFinding(
        company_domain="example.com",
        collector=CollectorName.LEAK_SCANNER,
        title="Exposed credential dump",
        description="Credentials associated with example.com were found.",
        severity=Severity.HIGH,
        risk_score=80,
    )


@pytest.mark.asyncio
async def test_cognee_failure_falls_back_to_local_jsonl(test_settings):
    test_settings.cognee_enabled = True
    memory = ThreatMemory(test_settings)

    await memory.store(_finding())

    records = [
        json.loads(line)
        for line in memory.local_path.read_text(encoding="utf-8").splitlines()
    ]
    assert memory.last_backend == "local_jsonl"
    assert "ModuleNotFoundError" in memory.last_error
    assert records[0]["company_domain"] == "example.com"
    assert records[0]["severity"] == "HIGH"
