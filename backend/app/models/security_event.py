"""
security_event.py

Defines SecurityEvent: the normalized, enriched representation of a raw
filesystem event, produced by services/event_processor.py from the
dicts that FileMonitor/MonitorAgent already emit.

This is Phase 3's core data contract. Phase 4 (DetectionEngine, rules)
and Phase 5 (RiskEngine, AlertManager) should only ever depend on this
model — never on the raw watchdog/FileMonitor dict shape — so those
later phases stay decoupled from how events are collected.

Design notes:
    - Immutable (frozen dataclass): a SecurityEvent, once created,
      should not be mutated as it flows through the pipeline. Rules in
      Phase 4 read it; they don't change it.
    - Every field is a plain, JSON-serializable type (str, bool, int,
      Optional[...]) so `to_dict()` can feed straight into a FastAPI
      response without extra conversion.
    - Fields mirror the raw event 1:1 where possible, plus a small set
      of genuinely useful derived fields (Phase 3.4). We deliberately
      do NOT add a file hash or full metadata stat here — those are
      out of scope per the Phase 3 spec.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import PureWindowsPath, PurePosixPath
from typing import Optional


def _new_event_id() -> str:
    """Generate a short, unique id for a SecurityEvent."""
    return uuid.uuid4().hex


def split_path(path: str) -> tuple[str, str, str]:
    """
    Return (file_name, extension, parent_directory) for a path string.

    Uses PureWindowsPath when the string looks like a Windows path
    (drive letter or backslashes) and PurePosixPath otherwise, so this
    works correctly regardless of which OS SentinelAI is running on
    vs. what the monitored path looks like (per Phase 3.5).
    """
    is_windows_like = ":\\" in path or "\\" in path or (
        len(path) > 1 and path[1] == ":"
    )
    p = PureWindowsPath(path) if is_windows_like else PurePosixPath(path)

    file_name = p.name
    extension = p.suffix.lower()
    parent_directory = str(p.parent)
    return file_name, extension, parent_directory


@dataclass(frozen=True)
class SecurityEvent:
    """
    A normalized, enriched filesystem event.

    Required (mirrors the raw FileMonitor event):
        event_type         "created" | "modified" | "deleted" | "moved"
        path                resolved path of the affected file/directory
        timestamp           ISO-8601 timestamp, preserved from the raw event
        is_directory         whether the path is a directory

    Optional (mirrors the raw event):
        destination_path    resolved destination path, only for "moved"

    Derived (Phase 3.4 enrichment):
        event_id            unique id assigned at processing time
        file_name           e.g. "invoice.exe"
        extension           e.g. ".exe" (lowercased, "" if none)
        parent_directory    e.g. "C:\\test"
        file_size           size in bytes if available, else None
                             (never fetched for "deleted" events — the
                             file is already gone)
    """

    event_type: str
    path: str
    timestamp: str
    is_directory: bool
    destination_path: Optional[str] = None

    event_id: str = field(default_factory=_new_event_id)
    file_name: str = ""
    extension: str = ""
    parent_directory: str = ""
    file_size: Optional[int] = None

    def to_dict(self) -> dict:
        """JSON-serializable representation, for API responses and logging."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "path": self.path,
            "timestamp": self.timestamp,
            "is_directory": self.is_directory,
            "destination_path": self.destination_path,
            "file_name": self.file_name,
            "extension": self.extension,
            "parent_directory": self.parent_directory,
            "file_size": self.file_size,
        }
