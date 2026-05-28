"""LangGraph orchestration for ARGUS risk reasoning."""

import json
import re
from typing import Any, Dict, TypedDict

from langgraph.graph import END, StateGraph

from backend.app.clients.ollama_client import call_ollama
from backend.app.models import ClassifiedFinding, RawFinding, Severity


class ReasoningState(TypedDict):
    raw: RawFinding
    analysis: Dict[str, Any]
    classified: ClassifiedFinding


def _fallback_analysis(raw: RawFinding) -> Dict[str, Any]:
    text = f"{raw.title} {raw.description} {raw.evidence}".lower()
    if any(token in text for token in ["private key", "secret_key", "api_key", ".env"]):
        return {
            "severity": "CRITICAL",
            "risk_score": 95,
            "reasoning": "Evidence suggests exposed secrets or environment configuration.",
            "recommendations": [
                "Rotate exposed credentials",
                "Remove indexed files",
                "Add secret scanning to CI",
            ],
        }
    if any(token in text for token in ["s3", "bucket", "admin", "login"]):
        return {
            "severity": "HIGH",
            "risk_score": 80,
            "reasoning": "Attacker-style reconnaissance discovered potentially exposed cloud or admin surfaces.",
            "recommendations": [
                "Review access controls",
                "Restrict public assets",
                "Monitor suspicious login infrastructure",
            ],
        }
    if "typo" in text or "brand-adjacent" in text:
        return {
            "severity": "MEDIUM",
            "risk_score": 55,
            "reasoning": "Brand-adjacent infrastructure may support phishing or impersonation.",
            "recommendations": [
                "Review domain ownership",
                "Add lookalike domain monitoring",
            ],
        }
    return {
        "severity": "LOW",
        "risk_score": 25,
        "reasoning": "Reconnaissance signal requires review but lacks direct exploit evidence.",
        "recommendations": [
            "Track for recurrence",
            "Correlate with historical findings",
        ],
    }


def _parse_json_response(text: str) -> Dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("Ollama response did not include JSON")
    return json.loads(match.group(0))


def analyze_finding(state: ReasoningState) -> ReasoningState:
    raw = state["raw"]
    prompt = f"""
You are ARGUS, an autonomous cyber intelligence analyst for Security & Compliance.
Classify this finding as CRITICAL, HIGH, MEDIUM, or LOW and return strict JSON only.

Finding:
{raw.model_dump_json()}

JSON schema:
{{"severity":"CRITICAL|HIGH|MEDIUM|LOW","risk_score":0-100,"reasoning":"short actionable rationale","recommendations":["action 1","action 2"]}}
"""
    try:
        analysis = _parse_json_response(call_ollama(prompt))
    except Exception:
        analysis = _fallback_analysis(raw)
    state["analysis"] = analysis
    return state


def classify_finding(state: ReasoningState) -> ReasoningState:
    raw = state["raw"]
    analysis = state["analysis"]
    severity = str(analysis.get("severity", "LOW")).upper()
    if severity not in Severity.__members__:
        severity = "LOW"
    risk_score = int(analysis.get("risk_score", 10))
    risk_score = max(0, min(100, risk_score))
    recommendations = analysis.get("recommendations") or []
    if isinstance(recommendations, str):
        recommendations = [recommendations]

    state["classified"] = ClassifiedFinding(
        **raw.model_dump(),
        severity=Severity[severity],
        risk_score=risk_score,
        reasoning=str(analysis.get("reasoning", "")),
        recommendations=[str(item) for item in recommendations][:5],
    )
    return state


def build_reasoning_graph():
    """Build the LangGraph StateGraph used to classify ARGUS findings."""

    graph = StateGraph(ReasoningState)
    graph.add_node("analyze_with_ollama", analyze_finding)
    graph.add_node("classify_risk", classify_finding)
    graph.set_entry_point("analyze_with_ollama")
    graph.add_edge("analyze_with_ollama", "classify_risk")
    graph.add_edge("classify_risk", END)
    return graph.compile()


class ThreatReasoner:
    def __init__(self):
        self.graph = build_reasoning_graph()

    async def classify(self, raw: RawFinding) -> ClassifiedFinding:
        result = await self.graph.ainvoke(
            {"raw": raw, "analysis": {}, "classified": None}
        )
        return result["classified"]
