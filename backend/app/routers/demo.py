"""
demo.py

GET  /api/demo/status    — is demo mode enabled on this deployment
POST /api/demo/simulate  — create a few harmless sample files so the live
                           pipeline produces ALLOW / ALERT / ESCALATE results

Why this exists: when SentinelAI is hosted in the cloud, it watches the
server's own folder, so visitors have no way to cause file activity. This
router lets someone press one button and watch real events flow through
the monitor -> investigation -> analysis -> decision pipeline.

Safety:
- Disabled unless ENABLE_DEMO=true (it is off for local runs by default).
- Files are written only inside a "sentinel_demo" subfolder of the first
  configured monitored directory; callers cannot choose the location.
- Every file contains plain text. Nothing is ever executed.
"""

import os
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.agents.monitor_agent import MonitorDirectoryError
from app.routers import monitor
from app.utils.logger import get_logger

router = APIRouter(prefix="/api/demo", tags=["Demo"])
logger = get_logger("SentinelAI.Demo")

DEMO_SUBFOLDER = "sentinel_demo"
_HARMLESS_TEXT = "SentinelAI demo file. Plain text only; safe to delete.\n"


def demo_enabled() -> bool:
    """Demo mode is opt-in through the ENABLE_DEMO environment variable."""
    return os.getenv("ENABLE_DEMO", "false").strip().lower() in {"1", "true", "yes"}


@router.get("/status")
def demo_status() -> dict:
    """Tell the dashboard whether to show the 'Simulate activity' button."""
    return {"enabled": demo_enabled()}


@router.post("/simulate")
def simulate_activity() -> dict:
    """
    Start monitoring if needed, then create sample files:
    a normal text file, a script file, and a download renamed to .exe.
    """
    if not demo_enabled():
        raise HTTPException(status_code=404, detail="Demo mode is not enabled.")

    try:
        monitor._monitor_agent.start()
    except MonitorDirectoryError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    watched = monitor._monitor_agent.get_status().get("watching_all") or []
    if not watched:
        raise HTTPException(status_code=500, detail="No monitored directory is available.")

    demo_dir = Path(watched[0]) / DEMO_SUBFOLDER
    demo_dir.mkdir(parents=True, exist_ok=True)

    tag = uuid.uuid4().hex[:6]
    created = []

    normal = demo_dir / f"meeting_notes_{tag}.txt"
    normal.write_text(_HARMLESS_TEXT)
    created.append(normal.name)

    script = demo_dir / f"cleanup_{tag}.ps1"
    script.write_text("# " + _HARMLESS_TEXT)
    created.append(script.name)

    # A browser download finishing: partial file renamed to an executable.
    partial = demo_dir / f"invoice_{tag}.crdownload"
    partial.write_text(_HARMLESS_TEXT)
    time.sleep(0.3)
    final = demo_dir / f"invoice_{tag}.exe"
    partial.rename(final)
    created.append(final.name)

    logger.info("Demo activity created in %s: %s", demo_dir, created)
    return {
        "message": "Sample files created. Results appear on the dashboard within a few seconds.",
        "folder": str(demo_dir),
        "files": created,
    }
