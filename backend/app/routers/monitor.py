"""
monitor.py

GET  /api/monitor/status  — is MonitorAgent running, and what is it watching
GET  /api/monitor/events  — recent normalized filesystem events
POST /api/monitor/start   — start MonitorAgent (no-op if already running)
POST /api/monitor/stop    — stop MonitorAgent (no-op if already stopped)

This router owns a single module-level MonitorAgent instance. It is the
one and only place that watches settings.monitored_directory — clients
can start/stop monitoring of that pre-configured sandbox, but nothing in
this API lets a caller change *which* directory gets watched. That value
comes only from settings.monitored_directory (backend/.env), by design:
the Phase 2 spec requires that an arbitrary client can't silently redirect
monitoring elsewhere.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.agents.monitor_agent import MonitorAgent, MonitorDirectoryError
from app.services.security_orchestrator import get_security_orchestrator

router = APIRouter(prefix="/api/monitor", tags=["Monitor"])

# Single shared agent instance for the life of the FastAPI process.
# Every live event is forwarded to the shared SecurityOrchestrator, so it is
# scored, given a decision, and saved to SQLite in real time.
_monitor_agent = MonitorAgent(event_sink=get_security_orchestrator().process)


@router.get("/status")
def get_status() -> dict:
    """
    Return whether MonitorAgent is running and which directory it is
    watching.

    Example response:
        {
          "running": true,
          "watching": "C:\\...\\sentinel-ai\\test_environment",
          "event_count": 3
        }
    """
    return _monitor_agent.get_status()


@router.get("/events")
def get_events(
    limit: Optional[int] = Query(
        default=None,
        ge=1,
        le=100,
        description="Max number of most-recent events to return (1-100).",
    )
) -> dict:
    """
    Return recent normalized monitoring events (most recent last), up to
    the last 100 retained in memory. Optionally cap the count with `limit`.
    """
    return {"events": _monitor_agent.get_events(limit=limit)}


@router.post("/start")
def start_monitor() -> dict:
    """
    Start MonitorAgent if it isn't already running.

    Returns the resulting status. Returns HTTP 500 with a clear message
    if the configured monitored_directory is missing or invalid, rather
    than crashing the process.
    """
    try:
        _monitor_agent.start()
    except MonitorDirectoryError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return _monitor_agent.get_status()


@router.post("/stop")
def stop_monitor() -> dict:
    """Stop MonitorAgent cleanly. Safe to call even if already stopped."""
    _monitor_agent.stop()
    return _monitor_agent.get_status()


def shutdown() -> None:
    """Stop the shared MonitorAgent (called once when the app shuts down)."""
    _monitor_agent.stop()
