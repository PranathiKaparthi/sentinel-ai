"""
orchestrator_agent.py

Phase 5 orchestration layer for SentinelAI.

The orchestrator coordinates the existing read-only pipeline without
rewriting or replacing earlier Phase 3 / Phase 4 logic:

raw_event -> ProcessingPipeline -> SecurityEvent -> InvestigationResult -> AnalysisResult
                                     -> AnalysisAgent -> OrchestrationResult

This is intentionally additive and does not perform remediation actions.
"""

from __future__ import annotations

from typing import Optional

from app.agents.analysis_agent import AnalysisAgent
from app.agents.base_agent import BaseAgent
from app.models.orchestration_result import OrchestrationResult
from app.services.pipeline import ProcessingPipeline
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.Orchestrator")


class OrchestratorAgent(BaseAgent):
    """Coordinates the processed event flow through the existing Phase 3/4 stages."""

    def __init__(self, name: str = "OrchestratorAgent"):
        super().__init__(name)

    @staticmethod
    def process(raw_event: dict) -> Optional[OrchestrationResult]:
        """Run the complete processing -> investigation -> analysis flow with assessment."""
        try:
            pipeline_result = ProcessingPipeline.process(raw_event)
            if pipeline_result is None:
                logger.warning("Orchestrator rejected invalid event: %r", raw_event)
                return None

            assessment = AnalysisAgent.analyze(
                pipeline_result.security_event,
                pipeline_result.investigation,
                pipeline_result.analysis,
            )
            if assessment is None:
                logger.warning(
                    "Orchestrator could not assess event: %s",
                    pipeline_result.security_event.event_id,
                )
                return None

            return OrchestrationResult.create(
                event_id=pipeline_result.security_event.event_id,
                security_event=pipeline_result.security_event.to_dict(),
                investigation=pipeline_result.investigation.to_dict(),
                analysis=pipeline_result.analysis.to_dict(),
                suspicion_score=assessment.suspicion_score,
                threat_score=assessment.threat_score,
                threat_level=assessment.threat_level,
                findings=assessment.findings,
                reasons=assessment.reasons,
            )

        except Exception:
            logger.exception("Orchestrator failed while processing raw event: %r", raw_event)
            return None
