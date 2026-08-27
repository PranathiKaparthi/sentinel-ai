"""
investigation.py

FastAPI router for SentinelAI Phase 3 investigation.

Provides a safe, read-only endpoint that investigates a filesystem
event and returns structured metadata.

No files are executed, modified, deleted, or quarantined.
"""

from fastapi import APIRouter, HTTPException

from app.models.security_event import SecurityEvent
from app.services.investigator import Investigator


router = APIRouter(
    prefix="/api/investigation",
    tags=["Investigation"],
)


@router.post("/investigate")
def investigate_event(event: dict) -> dict:
    """
    Investigate a normalized SecurityEvent.

    The endpoint accepts the SecurityEvent dictionary produced by
    EventProcessor and returns read-only investigation metadata.
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

    result = Investigator.investigate(security_event)

    if result is None:
        raise HTTPException(
            status_code=500,
            detail="Investigation failed safely; no result available.",
        )

    return result.to_dict()