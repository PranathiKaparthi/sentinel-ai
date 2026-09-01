"""
event_processor.py

EventProcessor: turns raw FileMonitor event dicts into validated,
enriched SecurityEvent objects (Phase 3).

    FileMonitor
         |
         v
    raw event dict
         |
         v
    EventProcessor.process()
         |
         v
    SecurityEvent | None

Design goals (per the Phase 3 spec):
    - Never raise out of process(): a malformed/unexpected raw event
      must not crash MonitorAgent or the filesystem observer thread.
      On failure, log and return None; the caller skips that event.
    - No blocking/expensive work: file size is a single, guarded
      os.stat() call (or none at all for directories/deleted files) —
      no hashing, no reading file contents.
    - No duplicate path-normalization logic: FileMonitor already
      resolves paths (Path(...).resolve()) before this ever sees them,
      so we only *parse* the given path string, we don't re-resolve it.
"""

from __future__ import annotations

import os
from typing import Optional

from app.models.security_event import SecurityEvent, _new_event_id, split_path
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.EventProcessor")

_VALID_EVENT_TYPES = {"created", "modified", "deleted", "moved"}


class EventProcessor:
    """
    Stateless transformer from raw FileMonitor dicts to SecurityEvent.

    Stateless by design: no per-instance mutable state is needed, so a
    single shared instance (or even calling the classmethod-like
    process() directly) is safe to reuse across every event.
    """

    @staticmethod
    def process(raw_event: dict) -> Optional[SecurityEvent]:
        """
        Validate and enrich a single raw event dict.

        Returns a SecurityEvent on success, or None if the raw event is
        missing required fields / malformed. Never raises.
        """
        try:
            return EventProcessor._process(raw_event)
        except Exception:
            # Defensive: whatever goes wrong here, the monitor must
            # keep running. Log with the raw event for debugging.
            logger.exception(
                "EventProcessor failed to process raw event; skipping: %r",
                raw_event,
            )
            return None

    @staticmethod
    def _process(raw_event: dict) -> Optional[SecurityEvent]:
        # --- Validation -------------------------------------------------
        event_id = raw_event.get("event_id")
        event_type = raw_event.get("event_type")
        path = raw_event.get("path")
        timestamp = raw_event.get("timestamp")
        is_directory = raw_event.get("is_directory")

        if event_type not in _VALID_EVENT_TYPES:
            logger.warning("Invalid event_type in raw event: %r", raw_event)
            return None

        if not path or not isinstance(path, str):
            logger.warning("Missing/invalid path in raw event: %r", raw_event)
            return None

        if timestamp is None:
            logger.warning("Missing timestamp in raw event: %r", raw_event)
            return None

        if not isinstance(is_directory, bool):
            # Be lenient but explicit: coerce rather than reject, since
            # this only affects a derived display field, not correctness
            # of detection.
            is_directory = bool(is_directory)

        destination_path = raw_event.get("destination_path")
        if destination_path is not None and not isinstance(destination_path, str):
            destination_path = None

        # --- Normalization / derived fields ------------------------------
        file_name, extension, parent_directory = split_path(path)

        # --- Enrichment: file size (Phase 3.4) --------------------------
        file_size = None
        if event_type != "deleted" and not is_directory:
            file_size = EventProcessor._safe_file_size(path)

        return SecurityEvent(
            event_id=event_id or _new_event_id(),
            event_type=event_type,
            path=path,
            timestamp=timestamp,
            is_directory=is_directory,
            destination_path=destination_path,
            file_name=file_name,
            extension=extension,
            parent_directory=parent_directory,
            file_size=file_size,
        )

    @staticmethod
    def _safe_file_size(path: str) -> Optional[int]:
        """
        Best-effort file size lookup. Returns None (never raises) if the
        file is missing, permission is denied, or a race means it was
        deleted between the event firing and us checking — all of which
        are expected/benign in a live filesystem monitor.
        """
        try:
            return os.path.getsize(path)
        except OSError:
            return None
