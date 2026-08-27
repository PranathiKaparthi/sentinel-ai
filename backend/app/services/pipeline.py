"""
pipeline.py

SentinelAI Phase 3 processing pipeline.

Flow:

Raw filesystem event
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
AnalysisResult

This pipeline is strictly read-only.

It does not:
- execute files
- modify files
- delete files
- quarantine files
- kill processes
- perform malware detection
- assign threat scores
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.models.security_event import SecurityEvent
from app.models.investigation_result import InvestigationResult
from app.services.event_processor import EventProcessor
from app.services.investigator import Investigator
from app.services.analyzer import Analyzer
from app.utils.logger import get_logger


logger = get_logger("SentinelAI.Pipeline")


@dataclass
class PipelineResult:
    """Complete result produced by the Phase 3 processing pipeline."""

    security_event: SecurityEvent
    investigation: InvestigationResult
    analysis: object

    def to_dict(self) -> dict:
        """Return a JSON-serializable pipeline result."""
        return {
            "security_event": self.security_event.to_dict(),
            "investigation": self.investigation.to_dict(),
            "analysis": self.analysis.to_dict(),
        }


class ProcessingPipeline:
    """
    Coordinates Phase 3 event processing.

    The pipeline only coordinates existing services.
    It does not contain detection or response logic.
    """

    @staticmethod
    def process(
        raw_event: dict,
    ) -> Optional[PipelineResult]:
        """
        Process one raw filesystem event through Phase 3.

        Returns None if any stage safely fails.
        """

        try:
            security_event = EventProcessor.process(raw_event)

            if security_event is None:
                logger.warning(
                    "EventProcessor rejected raw event: %r",
                    raw_event,
                )
                return None

            investigation = Investigator.investigate(
                security_event
            )

            if investigation is None:
                logger.warning(
                    "Investigation failed for event: %s",
                    security_event.event_id,
                )
                return None

            analysis = Analyzer.analyze(
                security_event,
                investigation,
            )

            if analysis is None:
                logger.warning(
                    "Analysis failed for event: %s",
                    security_event.event_id,
                )
                return None

            return PipelineResult(
                security_event=security_event,
                investigation=investigation,
                analysis=analysis,
            )

        except Exception:
            logger.exception(
                "Phase 3 processing pipeline failed for event: %r",
                raw_event,
            )
            return None