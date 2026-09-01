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

from app.agents.orchestrator_agent import OrchestratorAgent


router = APIRouter(
    prefix="/api/pipeline",
    tags=["Pipeline"],
)


@router.post("/process")
def process_event(event: dict) -> dict:
    """
    Process one raw filesystem event through the complete
    Phase 3 pipeline and the Phase 4 assessment layer.

    This endpoint remains additive and read-only: it does not perform
    any remediation or destructive action.
    """

    result = OrchestratorAgent.process(event)

    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid event or pipeline processing failed safely.",
        )

    return result.to_dict()