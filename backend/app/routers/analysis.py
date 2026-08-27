"""
analysis.py

FastAPI router for SentinelAI Phase 3 deterministic analysis.

The endpoint:
- Accepts a normalized SecurityEvent.
- Performs safe filesystem investigation.
- Performs deterministic metadata analysis.
- Never executes files.
- Never modifies files.
- Never deletes or quarantines files.
- Does not perform malware detection or threat scoring.
"""

from fastapi import APIRouter, HTTPException

from app.models.security_event import SecurityEvent
from app.services.investigator import Investigator
from app.services.analyzer import Analyzer


router = APIRouter(
    prefix="/api/analysis",
    tags=["Analysis"],
)


@router.post("/analyze")
def analyze_event(event: dict) -> dict:
    """
    Investigate and deterministically analyze a SecurityEvent.
    """

    try:
        security_event = SecurityEvent(
            event_type=event["event_type"],
            path=event["path"],
            timestamp=event["timestamp"],
            is_directory=event["is_directory"],
            destination_path=event.get("destination_path"),
            event_id=event.get("event_id", ""),
            file_name=event.get("file_name", ""),
            extension=event.get("extension", ""),
            parent_directory=event.get("parent_directory", ""),
            file_size=event.get("file_size"),
        )

    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid SecurityEvent: {exc}",
        ) from exc

    investigation = Investigator.investigate(security_event)

    if investigation is None:
        raise HTTPException(
            status_code=500,
            detail="Investigation failed safely; analysis unavailable.",
        )

    analysis = Analyzer.analyze(
        security_event,
        investigation,
    )

    if analysis is None:
        raise HTTPException(
            status_code=500,
            detail="Analysis failed safely; no result available.",
        )

    return analysis.to_dict()