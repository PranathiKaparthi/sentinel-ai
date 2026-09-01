"""
security_agent.py

SecurityAgent for SentinelAI Phase 6.

The SecurityAgent is responsible for coordinating security analysis
and answering: "What should Sentinel AI do with this security event?"

It is a proper agent that:
- Extends BaseAgent for lifecycle management
- Coordinates the existing Phase 3/4/5 pipeline without duplicating logic
- Produces consolidated security results for decision/response layers

Architecture:

    raw_event
         |
         v
    SecurityAgent (orchestrates via OrchestratorAgent)
         |
         +---> EventProcessor
         |
         +---> Investigator
         |
         +---> Analyzer
         |
         +---> AnalysisAgent
         |
         v
    OrchestrationResult (threat classification, findings, reasons)

The agent is observation and analysis only.

It does NOT:
    - execute files
    - modify files
    - delete files
    - quarantine files
    - kill processes
    - perform autonomous response
"""

from __future__ import annotations

from typing import Optional

from app.agents.base_agent import BaseAgent
from app.agents.orchestrator_agent import OrchestratorAgent
from app.models.orchestration_result import OrchestrationResult
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.SecurityAgent")


class SecurityAgent(BaseAgent):
    """
    Security analysis coordinator for SentinelAI.

    Answers: "What should Sentinel AI do with this security event?"

    By analyzing the event through the existing pipeline and
    classifying the threat level / findings / recommendations.
    """

    def __init__(self, name: str = "SecurityAgent"):
        super().__init__(name)

    def analyze(self, raw_event: dict) -> Optional[OrchestrationResult]:
        """
        Analyze a raw filesystem security event.

        Coordinates the complete pipeline (investigation, analysis, scoring)
        and returns a consolidated result with threat classification.

        Args:
            raw_event: Raw filesystem event dict

        Returns:
            OrchestrationResult with complete security analysis, or None if processing failed.
        """
        if not self.is_running():
            self.logger.warning(
                "analyze() called on stopped agent; ignoring request"
            )
            return None

        return self._analyze(raw_event)

    @staticmethod
    def _analyze(raw_event: dict) -> Optional[OrchestrationResult]:
        """
        Perform the actual security analysis.

        Delegates to OrchestratorAgent which handles the complete
        Phase 3/4/5 pipeline without duplication.
        """
        try:
            result = OrchestratorAgent.process(raw_event)
            if result is None:
                logger.warning("Security analysis rejected invalid event: %r", raw_event)
                return None
            return result
        except Exception:
            logger.exception("Security analysis failed for event: %r", raw_event)
            return None
