"""
health.py

GET /api/health

A minimal endpoint that confirms the API process is alive and responding.
This is a standard pattern in backend systems: load balancers, monitoring
tools, and (later) the Orchestrator Agent can poll this endpoint to check
whether the backend is up, without needing to know anything about its
internals.
"""

from fastapi import APIRouter

from app.config import settings

router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health")
def health_check() -> dict:
    """
    Return a simple status payload confirming the app is running.

    Example response:
        {
          "status": "healthy",
          "application": "SentinelAI",
          "environment": "development"
        }
    """
    return {
        "status": "healthy",
        "application": settings.app_name,
        "environment": settings.app_env,
    }
