"""
security_orchestrator.py

SecurityOrchestrator service for SentinelAI Phase 9.

Coordinates the complete security analysis pipeline (Phase 1-8) into
a single, centralized service that returns a composite SecurityAnalysisResult.

This service does NOT duplicate or rewrite existing logic. It coordinates
existing components:
- SecurityAgent (Phase 6)
- DecisionEngine (Phase 7)
- ResponseRecommendationEngine (Phase 8)

The orchestrator is the primary entry point for security analysis,
replacing direct router coordination.
"""

from __future__ import annotations

from typing import Optional

from app.agents.security_agent import SecurityAgent
from app.models.security_analysis_result import SecurityAnalysisResult
from app.repositories.security_event_repository import SecurityEventRepository
from app.services.decision_engine import DecisionEngine
from app.services.response_recommendation import ResponseRecommendationEngine
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.SecurityOrchestrator")


class SecurityOrchestrator:
    """
    Centralized security analysis orchestrator.

    Coordinates the complete Phase 1-8 pipeline into a single,
    composable result without duplicating component logic.

    Pipeline Flow:
    1. SecurityAgent.analyze() → OrchestrationResult
    2. DecisionEngine.make_decision() → SecurityDecision
    3. ResponseRecommendationEngine.generate_recommendation() → ResponseRecommendation
    4. Compose into SecurityAnalysisResult
    """

    def __init__(self):
        """Initialize the orchestrator with SecurityAgent and repository."""
        self._security_agent = SecurityAgent()
        self._security_agent.start()
        self._repository = SecurityEventRepository()

    def process(self, raw_event: dict) -> Optional[SecurityAnalysisResult]:
        """
        Process a raw filesystem security event through the complete pipeline.

        Coordinates Phase 1-8 analysis and returns a composite result
        suitable for API response or further processing.

        Args:
            raw_event: Raw filesystem event dict

        Returns:
            SecurityAnalysisResult with complete analysis, decision, and
            recommendation, or None if processing failed safely.
        """
        try:
            return self._process(raw_event)
        except Exception:
            logger.exception(
                "SecurityOrchestrator failed to process event: %r",
                raw_event,
            )
            return None

    def _process(self, raw_event: dict) -> Optional[SecurityAnalysisResult]:
        """Perform the actual orchestration logic."""

        # Phase 1-6: Security analysis via SecurityAgent
        # (internally coordinates OrchestratorAgent → ProcessingPipeline)
        orchestration_result = self._security_agent.analyze(raw_event)

        if orchestration_result is None:
            logger.warning(
                "SecurityOrchestrator rejected invalid event: %r",
                raw_event,
            )
            return None

        # Phase 7: Decision engine
        security_decision = DecisionEngine.make_decision(
            event_id=orchestration_result.event_id,
            threat_score=orchestration_result.threat_score,
            threat_level=orchestration_result.threat_level,
        )

        if security_decision is None:
            logger.warning(
                "SecurityOrchestrator could not make decision for event: %s",
                orchestration_result.event_id,
            )
            return None

        # Phase 8: Response recommendation engine
        response_recommendation = ResponseRecommendationEngine.generate_recommendation(
            security_decision=security_decision,
            orchestration_data=orchestration_result.to_dict(),
        )

        if response_recommendation is None:
            logger.warning(
                "SecurityOrchestrator could not generate recommendation for event: %s",
                orchestration_result.event_id,
            )
            return None

        # Compose into single result
        analysis_result = SecurityAnalysisResult(
            orchestration_result=orchestration_result,
            security_decision=security_decision,
            response_recommendation=response_recommendation,
        )

        # Phase 10: Persist to database (does not change response)
        try:
            self._repository.create(analysis_result)
        except Exception:
            logger.exception(
                "Failed to persist event to database: %s",
                orchestration_result.event_id,
            )

        return analysis_result

    def stop(self) -> None:
        """Stop the orchestrator and clean up resources."""
        self._security_agent.stop()


# ----------------------------------------------------------------------
# Shared instance
# ----------------------------------------------------------------------

_shared_orchestrator: Optional[SecurityOrchestrator] = None


def get_security_orchestrator() -> SecurityOrchestrator:
    """
    Return the one SecurityOrchestrator used by the whole API.

    Both the /api/security router and the live MonitorAgent use this
    instance, so manual analysis and real-time monitoring share the same
    pipeline and the same database.
    """
    global _shared_orchestrator
    if _shared_orchestrator is None:
        _shared_orchestrator = SecurityOrchestrator()
    return _shared_orchestrator
