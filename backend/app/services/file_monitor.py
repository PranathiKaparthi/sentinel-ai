"""
file_monitor.py

Low-level filesystem observation and event normalization.

This module knows about `watchdog` (the third-party file-watching library)
so nothing else in the codebase has to. It exposes a single class,
FileMonitor, that watches a directory and reports normalized event
dictionaries through a callback — MonitorAgent (agents/monitor_agent.py)
owns the lifecycle/policy (what directory, what to do with events);
this module only owns "how do I watch a folder and describe what changed."

Normalized event shape (matches the Phase 2 spec):
    {
        "event_type": "created" | "modified" | "deleted" | "moved",
        "path": "<resolved path>",
        "timestamp": "<ISO-8601 timestamp>",
        "is_directory": bool,
        "destination_path": "<resolved path> | None"   # only for "moved"
    }
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# The shape of the callback FileMonitor invokes for every normalized event.
EventCallback = Callable[[dict], None]


def _now_iso() -> str:
    """Return the current time as an ISO-8601 timestamp (UTC, with offset)."""
    return datetime.now(timezone.utc).isoformat()


class _NormalizingEventHandler(FileSystemEventHandler):
    """
    Translates raw watchdog events into SentinelAI's normalized event dict
    and forwards them to the provided callback.
    """

    def __init__(self, callback: EventCallback):
        super().__init__()
        self._callback = callback

    def _emit(
        self,
        event_type: str,
        path: str,
        is_directory: bool,
        destination_path: Optional[str] = None,
    ) -> None:
        self._callback(
            {
                "event_type": event_type,
                "path": str(Path(path).resolve()),
                "timestamp": _now_iso(),
                "is_directory": is_directory,
                "destination_path": (
                    str(Path(destination_path).resolve())
                    if destination_path
                    else None
                ),
            }
        )

    def on_created(self, event):
        self._emit("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        # watchdog also fires "modified" for directories when their
        # contents change; we pass is_directory through as-is so
        # consumers can filter if they only care about file changes.
        self._emit("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._emit("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self._emit(
            "moved",
            event.src_path,
            event.is_directory,
            destination_path=event.dest_path,
        )


class FileMonitor:
    """
    Watches a single directory (non-recursive-safe default: recursive)
    and reports normalized events via a callback.

    This class is intentionally unaware of BaseAgent, settings, or event
    storage — it only starts/stops a watchdog Observer safely, which
    keeps it easy to test and to swap out (e.g. for a different backend)
    without touching MonitorAgent.
    """

    def __init__(self, watch_path: Path, on_event: EventCallback):
        self._watch_path = watch_path
        self._on_event = on_event
        self._observer: Optional[Observer] = None
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._observer is not None and self._observer.is_alive()

    def start(self) -> None:
        """
        Start watching. Safe to call more than once — if already active,
        this is a no-op (prevents duplicate observers).
        """
        with self._lock:
            if self._observer is not None and self._observer.is_alive():
                return

            handler = _NormalizingEventHandler(self._on_event)
            observer = Observer()
            observer.schedule(handler, str(self._watch_path), recursive=True)
            observer.start()
            self._observer = observer

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop watching and release the observer thread. Safe to call more
        than once or when not running.
        """
        with self._lock:
            observer = self._observer
            self._observer = None

        if observer is not None:
            observer.stop()
            observer.join(timeout=timeout)
