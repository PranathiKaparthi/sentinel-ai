"""
main.py

Entry point for the SentinelAI FastAPI backend.

This file is intentionally thin: it creates the FastAPI app, wires up
routers, and handles startup/shutdown. Endpoints live in app/routers/,
detection logic in app/agents/ and app/services/, and database access in
app/repositories/.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.utils.logger import get_logger
from app.routers import (
    analysis,
    dashboard,
    demo,
    health,
    investigation,
    monitor,
    pipeline,
    security,
    system,
)

logger = get_logger("SentinelAI")

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Log startup, and stop live monitoring cleanly on shutdown."""
    logger.info(
        "%s starting up (env=%s, log_level=%s)",
        settings.app_name,
        settings.app_env,
        settings.log_level,
    )
    # On a hosted deployment, start watching immediately so the dashboard
    # is live as soon as someone opens it.
    if os.getenv("AUTO_START_MONITOR", "false").strip().lower() in {"1", "true", "yes"}:
        try:
            monitor.start_monitor()
        except Exception as exc:  # never block startup on the watcher
            logger.warning("Auto-start of monitoring failed: %s", exc)
    yield
    monitor.shutdown()
    logger.info("%s shut down cleanly", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    description="Multi-agent, real-time file and process monitoring with "
    "explainable threat scoring, decisions, alerts, and SQLite history.",
    version="1.0.0",
    lifespan=lifespan,
)

# Register routers. Each router owns its own URL prefix and tags, so this
# stays a simple list even as more routers are added in later phases.
app.include_router(health.router)
app.include_router(system.router)
app.include_router(monitor.router)
app.include_router(investigation.router)
app.include_router(analysis.router)
app.include_router(pipeline.router)
app.include_router(security.router)
app.include_router(dashboard.router)
app.include_router(demo.router)


@app.get("/")
def root() -> dict:
    """Basic root endpoint so visiting http://127.0.0.1:8000 shows something useful."""
    return {
        "message": f"{settings.app_name} backend is running.",
        "dashboard": "/dashboard",
        "docs": "/docs",
        "health": "/api/health",
        "system_status": "/api/system/status",
        "monitor_status": "/api/monitor/status",
        "monitor_events": "/api/monitor/events",
        "investigation": "/api/investigation/investigate",
        "analysis": "/api/analysis/analyze",
        "pipeline": "/api/pipeline/process",
        "security": "/api/security/analyze",
        "security_events": "/api/security/events",
        "alerts": "/api/security/alerts",
        "stats": "/api/security/stats",
        "processes": "/api/system/processes",
        "suspicious_processes": "/api/system/processes/suspicious",
    }
