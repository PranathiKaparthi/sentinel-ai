"""
security.py

FastAPI router for SentinelAI Phase 6-8 security analysis.

Provides a dedicated endpoint for comprehensive security analysis using
the SecurityOrchestrator (Phase 9) which coordinates the complete
Phase 1-8 pipeline:

Phase 1-5: Security event processing, investigation, and analysis
Phase 6: Security analysis coordination
Phase 7: Decision engine
Phase 8: Response recommendation and explainability
Phase 9: Centralized orchestration

The orchestrator handles all business logic; this router is responsible
for HTTP request/response handling only.
"""

from fastapi import APIRouter, HTTPException, Query

from app.repositories.security_event_repository import SecurityEventRepository
from app.services.security_orchestrator import get_security_orchestrator
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.SecurityRouter")

# Initialize the security orchestrator once at module load
_orchestrator = get_security_orchestrator()
_repository = SecurityEventRepository()


router = APIRouter(
    prefix="/api/security",
    tags=["Security"],
)


@router.post("/analyze")
def analyze_event(event: dict) -> dict:
    """
    Analyze a raw filesystem security event and produce a complete response.

    Phase 9 Orchestrator coordinates:
    - Phase 1-5: Security event processing and threat scoring
    - Phase 6: Security analysis coordination
    - Phase 7: Decision engine (LOW→ALLOW, MEDIUM→ALERT, HIGH/CRITICAL→ESCALATE)
    - Phase 8: Response recommendation and explainability

    Returns:
    - complete OrchestrationResult (Phase 1-5 data)
    - decision (Phase 7 SecurityDecision)
    - response_recommendation (Phase 8 ResponseRecommendation)

    This endpoint remains read-only. All decisions are recommendations only.
    No destructive or remediation actions are performed.
    """

    # Delegate all security analysis to the orchestrator
    analysis_result = _orchestrator.process(event)

    if analysis_result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid event or security analysis failed safely.",
        )

    # Response structure is identical to Phase 8 for backward compatibility
    return analysis_result.to_dict()


@router.get("/events")
def list_events(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    threat_level: str | None = Query(
        None, description="Filter by threat level (LOW, MEDIUM, HIGH, CRITICAL)"
    ),
    decision: str | None = Query(None, description="Filter by decision (ALLOW, ALERT, ESCALATE)"),
    event_type: str | None = Query(
        None, description="Filter by event type (created, modified, deleted, moved)"
    ),
) -> dict:
    """
    List persisted security events with optional filtering and pagination.

    Phase 10 endpoint: Retrieve audit history of security event analysis.

    Query Parameters:
    - skip: Number of records to skip (default 0)
    - limit: Maximum records to return (default 100, max 1000)
    - threat_level: Filter by threat level
    - decision: Filter by decision
    - event_type: Filter by event type

    Returns:
    - events: List of persisted security event records
    - total: Total count of records matching filters
    - skip: Skip value used
    - limit: Limit value used
    """
    records = _repository.list(
        skip=skip,
        limit=limit,
        threat_level=threat_level,
        decision=decision,
        event_type=event_type,
    )

    total = _repository.count(
        threat_level=threat_level,
        decision=decision,
        event_type=event_type,
    )

    return {
        "events": [record.to_dict() for record in records],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/alerts")
def list_alerts(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
) -> dict:
    """
    List events that need human attention (decision ALERT or ESCALATE),
    newest first. Includes events found by live monitoring.
    """
    records = _repository.list_alerts(skip=skip, limit=limit)
    return {
        "alerts": [record.to_dict() for record in records],
        "total": _repository.count_alerts(),
        "skip": skip,
        "limit": limit,
    }


@router.get("/stats")
def get_stats() -> dict:
    """
    Dashboard summary: total events, counts per threat level and decision,
    and the average threat score (SQL GROUP BY over the events table).
    """
    return _repository.stats()


@router.get("/events/{event_id}")
def get_event(event_id: str) -> dict:
    """
    Retrieve a specific persisted security event by event_id.

    Phase 10 endpoint: Get details of a single analyzed event.

    Args:
        event_id: The unique event identifier

    Returns:
        The complete security event record with all analysis data
    """
    record = _repository.get_by_event_id(event_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Event {event_id} not found",
        )

    return record.to_dict()
