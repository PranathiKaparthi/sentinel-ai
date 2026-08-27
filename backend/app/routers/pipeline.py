"""
pipeline.py

FastAPI router for SentinelAI Phase 3 processing pipeline.

The endpoint accepts a raw filesystem event and sends it through:

Raw Event
    ↓
EventProcessor
    ↓
SecurityEvent
    ↓
Investigator
    ↓
InvestigationResult
    ↓
Analyzer
    ↓
PipelineResult

The pipeline is strictly read-only.
"""

from fastapi import APIRouter, HTTPException

from app.services.pipeline import ProcessingPipeline


router = APIRouter(
    prefix="/api/pipeline",
    tags=["Pipeline"],
)


@router.post("/process")
def process_event(event: dict) -> dict:
    """
    Process one raw filesystem event through the complete
    Phase 3 pipeline.

    Returns the complete pipeline result or HTTP 400 if
    the event is invalid / processing fails safely.
    """

    result = ProcessingPipeline.process(event)

    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid event or pipeline processing failed safely.",
        )

    return result.to_dict()