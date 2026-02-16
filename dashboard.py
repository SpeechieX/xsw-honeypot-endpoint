
# dashboard.py — Dashboard API router.

# Provides JSON endpoints consumed by the frontend dashboard, plus
# an optional basic-auth gate if credentials are configured.

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from ..models import DashboardStats, SAMLCapture
from ..services.storage import storage
from ..config import settings

router = APIRouter(prefix="/api", tags=["dashboard"])
security = HTTPBasic(auto_error=False)


def _check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    # Optional basic auth gate for dashboard API endpoints.
    if not settings.dashboard_username:
        return  # Auth disabled

    if credentials is None:
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
            detail="Authentication required",
        )

    username_ok = secrets.compare_digest(
        credentials.username.encode(), settings.dashboard_username.encode()
    )
    password_ok = secrets.compare_digest(
        credentials.password.encode(), settings.dashboard_password.encode()
    )
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/stats", response_model=DashboardStats)
async def get_stats(_: None = Depends(_check_auth)):
    # Aggregate statistics for the dashboard header cards.
    return await storage.get_stats()


@router.get("/captures", response_model=list[SAMLCapture])
async def list_captures(
    limit: int = Query(default=50, ge=1, le=500),
    _: None = Depends(_check_auth),
):
    # Return recent captures, newest first.
    return await storage.get_recent_captures(limit=limit)


@router.get("/captures/{capture_id}", response_model=SAMLCapture)
async def get_capture(
    capture_id: str,
    _: None = Depends(_check_auth),
):
    # Return a single capture by ID.
    capture = await storage.get_capture(capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return capture
