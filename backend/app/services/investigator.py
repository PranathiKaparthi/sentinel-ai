"""
investigator.py

Safe, read-only investigation service for SentinelAI Phase 3.

The Investigator:
- Receives a validated SecurityEvent.
- Collects basic filesystem metadata.
- Never executes files.
- Never modifies files.
- Never deletes or quarantines files.
- Never performs malware detection or threat scoring.
"""

from __future__ import annotations

import os
from typing import Optional

from app.models.investigation_result import InvestigationResult
from app.models.security_event import SecurityEvent
from app.utils.logger import get_logger


logger = get_logger("SentinelAI.Investigator")


class Investigator:
    """
    Performs safe, read-only investigation of a SecurityEvent.
    """

    @staticmethod
    def investigate(
        event: SecurityEvent,
    ) -> Optional[InvestigationResult]:
        """
        Investigate a SecurityEvent and return structured metadata.

        This method is deliberately defensive:
        unexpected errors are logged and return None instead of
        propagating into the monitoring pipeline.
        """

        try:
            return Investigator._investigate(event)
        except Exception:
            logger.exception(
                "Investigator failed to investigate event: %r",
                event,
            )
            return None

    @staticmethod
    def _investigate(
        event: SecurityEvent,
    ) -> InvestigationResult:
        """
        Perform the actual read-only filesystem investigation.
        """

        path = event.path

        # Deleted files may no longer exist, which is expected.
        exists = os.path.exists(path)

        is_directory = False
        current_file_size: Optional[int] = None

        if exists:
            try:
                is_directory = os.path.isdir(path)
            except OSError:
                is_directory = False

            # Only retrieve size for existing regular files.
            if not is_directory:
                try:
                    current_file_size = os.path.getsize(path)
                except OSError:
                    current_file_size = None

        return InvestigationResult.create(
            event_id=event.event_id,
            event_type=event.event_type,
            path=event.path,
            exists=exists,
            is_directory=is_directory,
            current_file_size=current_file_size,
            file_name=event.file_name,
            extension=event.extension,
            parent_directory=event.parent_directory,
        )