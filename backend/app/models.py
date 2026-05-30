"""Shared data models for ARGUS threat intelligence."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CollectorName(str, Enum):
    LEAK_SCANNER = "leak_scanner"
    DOMAIN_MONITOR = "domain_monitor"
    ATTACK_SIMULATOR = "attack_simulator"
    THREAT_INTEL = "threat_intel"


class ScanRequest(BaseModel):
    company_domain: str = Field(..., min_length=3, max_length=255)
    focus: str = Field(default="full", max_length=64)
    attack_mode: bool = False


class RawFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    company_domain: str
    collector: CollectorName
    title: str
    description: str
    source: str = "Bright Data SERP API"
    url: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ClassifiedFinding(RawFinding):
    severity: Severity = Severity.LOW
    risk_score: int = Field(default=10, ge=0, le=100)
    reasoning: str = ""
    recommendations: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    company_domain: str
    score: int = Field(ge=0, le=100)
    finding_count: int
    severity_counts: Dict[str, int]
    recommendations: List[str]
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AlertPayload(BaseModel):
    finding: ClassifiedFinding
    destination: Optional[HttpUrl] = None


class RemediationRequest(BaseModel):
    target_id: str = Field(..., min_length=3, max_length=255)
    command: str = Field(default="halt", max_length=32)
    threat_data: Dict[str, Any] = Field(default_factory=dict)
