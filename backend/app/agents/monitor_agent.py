"""
monitor_agent.py

SentinelAI MonitorAgent.

Responsibilities:
    - Watch the configured monitored directory.
    - Receive filesystem events from FileMonitor.
    - Send events through the Phase 3 ProcessingPipeline.
    - Store the resulting SecurityEvent in bounded memory.
    - Maintain monitor status.

Architecture:

    FileMonitor
         |
         v
    MonitorAgent
         |
         v
    ProcessingPipeline
         |
         +-------------------+
         |                   |
         v                   v
    EventProcessor      Investigator
                             |
                             v
                          Analyzer
                             |
                             v
                      PipelineResult

The agent remains observation-only.

It does NOT:
    - execute files
    - modify files
    - delete files
    - quarantine files
    - kill processes
    - assign threat scores
    - perform autonomous response
"""

from __future__ import annotations

import threading
from collections import deque
from pathlib import Path
from typing import Any, Callable, Deque, List, Optional

from app.agents.base_agent import BaseAgent
from app.config import settings
from app.services.file_monitor import FileMonitor
from app.services.pipeline import ProcessingPipeline


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

MAX_RECENT_EVENTS = 100


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------

class MonitorDirectoryError(RuntimeError):
    """Raised when the configured monitored directory cannot be watched."""


# ----------------------------------------------------------------------
# Monitor Agent
# ----------------------------------------------------------------------

class MonitorAgent(BaseAgent):
    """
    Watches settings.monitored_directory for filesystem changes.

    The MonitorAgent is responsible for observation and orchestration.

    It receives raw filesystem events from FileMonitor and sends them
    through ProcessingPipeline.

    Example:

        agent = MonitorAgent()

        agent.start()

        status = agent.get_status()

        events = agent.get_events()

        agent.stop()
    """

    def __init__(
        self,
        name: str = "MonitorAgent",
        event_sink: Optional[Callable[[dict], Any]] = None,
    ):
        super().__init__(name)

        # Optional real-time hand-off. When set (the API wires it to the
        # SecurityOrchestrator), every observed event is also scored,
        # given a decision, and persisted to SQLite as it happens.
        # Left as None, the agent behaves exactly as in Phase 2/3.
        self._event_sink = event_sink

        # Live alert counters (events whose decision was ALERT/ESCALATE).
        self._analyzed_count = 0
        self._alert_count = 0
        self._last_alert: Optional[dict] = None

        # Bounded in-memory event history.
        self._events: Deque[dict] = deque(
            maxlen=MAX_RECENT_EVENTS
        )

        # Protect event history because filesystem callbacks
        # may execute from observer threads.
        self._events_lock = threading.Lock()

        # Currently monitored directory.
        self._watch_path: Optional[Path] = None

        # Underlying filesystem monitor.
        self._file_monitor: Optional[FileMonitor] = None

    # ------------------------------------------------------------------
    # Directory validation
    # ------------------------------------------------------------------

    def _resolve_and_validate_directory(self) -> Path:
        """
        Resolve and validate the configured monitored directory.

        Raises:
            MonitorDirectoryError:
                If the configured path does not exist or is not a directory.
        """

        raw_path = settings.monitored_directory

        resolved = Path(raw_path).resolve()

        if not resolved.exists():
            raise MonitorDirectoryError(
                f"Configured monitored_directory does not exist: "
                f"{resolved} "
                f"(from settings value {raw_path!r})"
            )

        if not resolved.is_dir():
            raise MonitorDirectoryError(
                f"Configured monitored_directory is not a directory: "
                f"{resolved}"
            )

        return resolved

    # ------------------------------------------------------------------
    # Filesystem event callback
    # ------------------------------------------------------------------

    def _on_event(
        self,
        raw_event: dict,
    ) -> None:
        """
        Process one raw filesystem event.

        The event is sent through the complete Phase 3 pipeline:

            raw_event
                |
                v
        ProcessingPipeline
                |
                +--> EventProcessor
                |
                +--> Investigator
                |
                +--> Analyzer
                |
                v
          PipelineResult

        Only the normalized SecurityEvent is stored in the MonitorAgent
        event history. The complete pipeline result remains available
        to the pipeline layer and future API/alerting layers.
        """

        try:
            result = ProcessingPipeline.process(
                raw_event
            )

            # The pipeline safely returns None for invalid/unprocessable
            # events.
            if result is None:
                self.logger.warning(
                    "ProcessingPipeline rejected event: %r",
                    raw_event,
                )
                return

            # Extract the normalized SecurityEvent.
            event_dict = result.security_event.to_dict()

            # Store the event safely.
            with self._events_lock:
                self._events.append(event_dict)

            # Real-time analysis: forward the event (with its stable id)
            # to the sink so it is scored, decided and persisted now.
            self._forward_to_sink(raw_event, event_dict["event_id"])

            # Log moved events differently because they have both
            # source and destination paths.
            if event_dict["event_type"] == "moved":
                self.logger.info(
                    "moved: %s -> %s",
                    event_dict["path"],
                    event_dict["destination_path"],
                )
            else:
                self.logger.info(
                    "%s: %s",
                    event_dict["event_type"],
                    event_dict["path"],
                )

        except Exception:
            # Defensive protection around the observer callback.
            #
            # FileMonitor must never be allowed to die because of an
            # unexpected pipeline exception.
            self.logger.exception(
                "MonitorAgent failed to process filesystem event: %r",
                raw_event,
            )

    # ------------------------------------------------------------------
    # Real-time analysis hand-off
    # ------------------------------------------------------------------

    def _forward_to_sink(self, raw_event: dict, event_id: str) -> None:
        """
        Send one event to the configured sink and track alerts.

        Failures are logged and swallowed: analysis problems must never
        stop filesystem monitoring.
        """
        if self._event_sink is None:
            return

        try:
            result = self._event_sink({**raw_event, "event_id": event_id})
        except Exception:
            self.logger.exception("Event sink failed for event %s", event_id)
            return

        if result is None:
            return

        decision = getattr(
            getattr(result, "security_decision", None), "decision", None
        )

        with self._events_lock:
            self._analyzed_count += 1
            if decision in ("ALERT", "ESCALATE"):
                self._alert_count += 1
                self._last_alert = {
                    "event_id": event_id,
                    "path": raw_event.get("path"),
                    "decision": decision,
                    "threat_level": getattr(result, "threat_level", None),
                    "threat_score": getattr(result, "threat_score", None),
                }

        if decision in ("ALERT", "ESCALATE"):
            self.logger.warning(
                "ALERT %s (%s, score %s): %s",
                decision,
                getattr(result, "threat_level", "?"),
                getattr(result, "threat_score", "?"),
                raw_event.get("path"),
            )

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start monitoring the configured directory.

        Calling start() repeatedly while already running is safe.
        """

        # Prevent duplicate observers.
        if self.is_running():
            self.logger.info(
                "%s already running; ignoring duplicate start()",
                self.name,
            )
            return

        # Resolve and validate the monitored directory.
        try:
            self._watch_path = (
                self._resolve_and_validate_directory()
            )
        except MonitorDirectoryError as exc:
            self.logger.error(
                "Failed to start %s: %s",
                self.name,
                exc,
            )
            raise

        # Create the filesystem monitor.
        self._file_monitor = FileMonitor(
            self._watch_path,
            self._on_event,
        )

        # Start observing filesystem changes.
        self._file_monitor.start()

        # Update BaseAgent state.
        super().start()

        self.logger.info(
            "%s watching directory: %s",
            self.name,
            self._watch_path,
        )

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """
        Stop monitoring and release the filesystem observer.

        Safe to call repeatedly.
        """

        if self._file_monitor is not None:
            self._file_monitor.stop()
            self._file_monitor = None

        if self.is_running():
            super().stop()
        else:
            self.logger.info(
                "%s already stopped; ignoring duplicate stop()",
                self.name,
            )

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """
        Return the current monitor status.

        The returned object is JSON serializable.
        """

        with self._events_lock:
            event_count = len(self._events)
            analyzed_count = self._analyzed_count
            alert_count = self._alert_count
            last_alert = dict(self._last_alert) if self._last_alert else None

        return {
            "running": self.is_running(),
            "watching": (
                str(self._watch_path)
                if self._watch_path
                else None
            ),
            "event_count": event_count,
            "real_time_analysis": self._event_sink is not None,
            "analyzed_count": analyzed_count,
            "alert_count": alert_count,
            "last_alert": last_alert,
        }

    # ------------------------------------------------------------------
    # Event history
    # ------------------------------------------------------------------

    def get_events(
        self,
        limit: Optional[int] = None,
    ) -> List[dict]:
        """
        Return recent normalized security events.

        Args:
            limit:
                Optional maximum number of events.

        Returns:
            List of event dictionaries.

        Events are ordered from oldest to newest.
        """

        with self._events_lock:
            events = list(self._events)

        if limit is not None:
            events = events[-limit:]

        return events