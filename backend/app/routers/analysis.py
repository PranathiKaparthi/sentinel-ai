"""
analysis.py

FastAPI router for SentinelAI Phase 3 deterministic analysis and Phase 4
additive scoring.

The original Phase 3 endpoint remains in place and unchanged in behavior.
A new Phase 4 assessment endpoint adds a deterministic scoring layer on top
of the existing investigation and analysis data without replacing the
Phase 3 analyzer.
"""

from fastapi import APIRouter, HTTPException

from app.agents.analysis_agent import AnalysisAgent, AnalysisAgentResult
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


@router.post("/assess")
def assess_event(event: dict) -> dict:
    """
    Run the Phase 4 analysis agent over the actual Phase 3 pipeline output.
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
            detail="Investigation failed safely; assessment unavailable.",
        )

    analysis = Analyzer.analyze(security_event, investigation)
    if analysis is None:
        raise HTTPException(
            status_code=500,
            detail="Phase 3 analysis failed safely; assessment unavailable.",
        )

    result = AnalysisAgent.analyze(security_event, investigation, analysis)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail="Phase 4 analysis failed safely; no assessment available.",
        )

    return result.model_dump()


@router.get("/history")
def list_history() -> list[dict]:
    """Return all saved Phase 4 assessment results."""
    return AnalysisAgent.list_history()


@router.get("/history/{result_id}")
def get_history_detail(result_id: str) -> dict:
    """Return one saved Phase 4 assessment result by id."""
    item = AnalysisAgent.get_history_item(result_id)
    if item is None:
        raise HTTPException(status_code=404, detail="History item not found.")
    return item.model_dump()