"""
analyzer.py

Safe, deterministic analysis service for SentinelAI Phase 3.

The Analyzer:
- Receives a SecurityEvent and InvestigationResult.
- Performs rule-based metadata analysis only.
- Does not execute files.
- Does not modify files.
- Does not delete or quarantine files.
- Does not perform malware detection.
- Does not assign threat/risk scores.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

from app.models.investigation_result import InvestigationResult
from app.models.security_event import SecurityEvent
from app.utils.logger import get_logger


logger = get_logger("SentinelAI.Analyzer")


@dataclass
class AnalysisResult:
    """
    Deterministic, read-only analysis result.

    This is deliberately descriptive rather than a threat verdict.
    """

    event_id: str
    event_type: str
    path: str

    file_name: str
    extension: str
    parent_directory: str

    exists: bool
    is_directory: bool
    current_file_size: Optional[int]

    observations: list[str]
    analysis_timestamp: str

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""
        return asdict(self)


class Analyzer:
    """
    Performs safe, deterministic analysis using already collected metadata.
    """

    @staticmethod
    def analyze(
        event: SecurityEvent,
        investigation: InvestigationResult,
    ) -> Optional[AnalysisResult]:
        """
        Analyze an event and its investigation result.

        Any unexpected failure is handled safely and returns None.
        """

        try:
            return Analyzer._analyze(event, investigation)
        except Exception:
            logger.exception(
                "Analyzer failed for event: %r",
                event,
            )
            return None

    @staticmethod
    def _analyze(
        event: SecurityEvent,
        investigation: InvestigationResult,
    ) -> AnalysisResult:
        """Perform deterministic metadata analysis."""

        observations: list[str] = []

        if investigation.is_directory:
            observations.append("Path is a directory.")
        elif investigation.exists:
            observations.append("Path currently exists as a regular file.")
        else:
            observations.append("Path does not currently exist.")

        if event.event_type == "created":
            observations.append("Filesystem creation event detected.")
        elif event.event_type == "modified":
            observations.append("Filesystem modification event detected.")
        elif event.event_type == "deleted":
            observations.append("Filesystem deletion event detected.")
        elif event.event_type == "moved":
            observations.append("Filesystem move event detected.")

        if event.extension:
            observations.append(
                f"File extension identified: {event.extension}"
            )
        else:
            observations.append("No file extension identified.")

        if investigation.current_file_size is not None:
            observations.append(
                f"Current file size: {investigation.current_file_size} bytes."
            )

        if event.destination_path:
            observations.append(
                f"Destination path: {event.destination_path}"
            )

        return AnalysisResult(
            event_id=event.event_id,
            event_type=event.event_type,
            path=event.path,
            file_name=event.file_name,
            extension=event.extension,
            parent_directory=event.parent_directory,
            exists=investigation.exists,
            is_directory=investigation.is_directory,
            current_file_size=investigation.current_file_size,
            observations=observations,
            analysis_timestamp=investigation.investigation_timestamp,
        )