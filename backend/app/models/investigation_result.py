"""
investigation_result.py

Structured result produced by the InvestigationAgent.

Phase 3:
- Contains only safe, read-only investigation metadata.
- Does not perform malware detection or threat scoring.
- Does not execute, modify, delete, or quarantine files.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class InvestigationResult:
    """
    Read-only investigation information associated with a SecurityEvent.
    """

    event_id: str
    event_type: str
    path: str

    exists: bool
    is_directory: bool
    current_file_size: Optional[int]

    file_name: str
    extension: str
    parent_directory: str

    investigation_timestamp: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        event_type: str,
        path: str,
        exists: bool,
        is_directory: bool,
        current_file_size: Optional[int],
        file_name: str,
        extension: str,
        parent_directory: str,
    ) -> "InvestigationResult":
        """
        Create an InvestigationResult with the current UTC timestamp.
        """

        timestamp = datetime.now(timezone.utc).isoformat()

        return cls(
            event_id=event_id,
            event_type=event_type,
            path=path,
            exists=exists,
            is_directory=is_directory,
            current_file_size=current_file_size,
            file_name=file_name,
            extension=extension,
            parent_directory=parent_directory,
            investigation_timestamp=timestamp,
        )

    def to_dict(self) -> dict:
        """
        Convert the investigation result into a JSON-serializable dict.
        """

        return asdict(self)