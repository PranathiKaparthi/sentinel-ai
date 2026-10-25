"""
dashboard.py

GET /dashboard — serves the live SentinelAI dashboard page.

The page (app/static/dashboard.html) is plain HTML + JavaScript with no
build step. It is served by this same FastAPI app, so its calls to
/api/... are same-origin and need no CORS configuration.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["Dashboard"])

_DASHBOARD_PAGE = Path(__file__).resolve().parent.parent / "static" / "dashboard.html"


@router.get("/dashboard", include_in_schema=False)
def dashboard() -> FileResponse:
    """Return the dashboard page."""
    return FileResponse(_DASHBOARD_PAGE, media_type="text/html")
