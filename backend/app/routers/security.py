"""
security.py

FastAPI router for SentinelAI Phase 6 security analysis and Phase 7 decision.

Provides a dedicated endpoint for comprehensive security analysis
using the SecurityAgent to coordinate the existing pipeline, then
converts the threat classification into a safe decision recommendation.

This endpoint returns the complete OrchestrationResult plus a decision
field containing the structured SecurityDecision.
"""

from fastapi import APIRouter, HTTPException

from app.agents.security_agent import SecurityAgent
from app.services.decision_engine import DecisionEngine
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.SecurityRouter")

# Initialize the security agent once at module load
_security_agent = SecurityAgent()
_security_agent.start()


router = APIRouter(
    prefix="/api/security",
    tags=["Security"],
)


@router.post("/analyze")
def analyze_event(event: dict) -> dict:
    """
    Analyze a raw filesystem security event and produce a decision.

    Phase 6 — Security Analysis:
    The SecurityAgent coordinates the complete security analysis pipeline:
    - Event normalization (EventProcessor)
    - Filesystem investigation (Investigator)
    - Metadata analysis (Analyzer)
    - Threat scoring (AnalysisAgent)

    Phase 7 — Decision & Recommendation:
    The DecisionEngine converts threat classification into a safe decision:
    - LOW → ALLOW
    - MEDIUM → ALERT
    - HIGH/CRITICAL → ESCALATE

    Returns a consolidated result with threat classification, findings,
    and a structured decision recommendation.

    This endpoint remains read-only and does not perform any remediation
    or destructive action. All decisions are recommendations only.
    """

    result = _security_agent.analyze(event)

    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid event or security analysis failed safely.",
        )

    # Get the decision based on threat classification
    decision = DecisionEngine.make_decision(
        event_id=result.event_id,
        threat_score=result.threat_score,
        threat_level=result.threat_level,
    )

    if decision is None:
        raise HTTPException(
            status_code=500,
            detail="Decision engine failed safely; analysis available but decision unavailable.",
        )

    # Combine analysis and decision in response
    response = result.to_dict()
    response["decision"] = decision.to_dict()

    return response
