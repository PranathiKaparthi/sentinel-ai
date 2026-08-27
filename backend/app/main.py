"""
main.py

Entry point for the SentinelAI FastAPI backend.

This file is intentionally thin: it creates the FastAPI app, wires up
routers, and logs startup — it does not contain endpoint logic itself.
Actual endpoint implementations live in app/routers/, and (in future
phases) actual detection logic will live in app/services/ and
app/agents/. Keeping main.py small makes the codebase easier to navigate
as it grows.
"""

from fastapi import FastAPI

from app.config import settings
from app.utils.logger import get_logger
from app.routers import health, system, monitor, investigation, analysis, pipeline

logger = get_logger("SentinelAI")

app = FastAPI(
    title=settings.app_name,
    description="Autonomous Multi-Agent System for Intelligent Malware, "
    "Anomaly, Bug, and System Threat Detection — Phase 1 foundation.",
    version="0.1.0-phase1",
)

# Register routers. Each router owns its own URL prefix and tags, so this
# stays a simple list even as more routers are added in later phases.
app.include_router(health.router)
app.include_router(system.router)
app.include_router(monitor.router)
app.include_router(investigation.router)
app.include_router(analysis.router)
app.include_router(pipeline.router)


@app.on_event("startup")
def on_startup() -> None:
    """Log a clear startup message so it's obvious in the terminal when the app is ready."""
    logger.info(
        "%s starting up (env=%s, log_level=%s)",
        settings.app_name,
        settings.app_env,
        settings.log_level,
    )


@app.get("/")
def root() -> dict:
    """Basic root endpoint so visiting http://127.0.0.1:8000 shows something useful."""
    return {
        "message": f"{settings.app_name} backend is running.",
        "docs": "/docs",
        "health": "/api/health",
        "system_status": "/api/system/status",
        "monitor_status": "/api/monitor/status",
        "monitor_events": "/api/monitor/events",
        "investigation": "/api/investigation/investigate",
        "analysis": "/api/analysis/analyze",
        "pipeline": "/api/pipeline/process",
    }
