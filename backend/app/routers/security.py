"""
security.py

FastAPI router for SentinelAI Phase 6 security analysis.

Provides a dedicated endpoint for comprehensive security analysis
using the SecurityAgent to coordinate the existing pipeline.

This endpoint returns the same complete OrchestrationResult as the
pipeline endpoint but is semantically dedicated to security analysis
and provides a clean agent-based interface.
"""

from fastapi import APIRouter, HTTPException

from app.agents.security_agent import SecurityAgent
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
    Analyze a raw filesystem security event.

    The SecurityAgent coordinates the complete security analysis pipeline:
    - Event normalization (EventProcessor)
    - Filesystem investigation (Investigator)
    - Metadata analysis (Analyzer)
    - Threat scoring (AnalysisAgent)

    Returns a consolidated result with threat classification and recommendations.

    This endpoint remains read-only and does not perform any remediation
    or destructive action.
    """

    result = _security_agent.analyze(event)

    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid event or security analysis failed safely.",
        )

    return result.to_dict()
