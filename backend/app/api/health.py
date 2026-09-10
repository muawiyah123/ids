"""
backend/app/api/health.py — Liveness and readiness endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.database import AsyncSessionLocal, check_db_health
from app.ml.model_manager import model_manager
from app.services.websocket_service import ws_manager, _redis_client

router = APIRouter(tags=["Health"])


@router.get("/health")
async def liveness() -> dict:
    """Liveness probe — app is running."""
    return {"status": "ok", "service": "ids-sentinel-api"}


@router.get("/ready")
async def readiness(response: Response) -> dict:
    """
    Readiness probe — checks DB, model, and optional Redis.
    Returns 503 if any critical component is not ready.
    """
    checks: dict = {}
    all_ready = True

    # Database
    db_ok = await check_db_health()
    checks["database"] = "ok" if db_ok else "unavailable"
    if not db_ok:
        all_ready = False

    # ML model
    model_ok = model_manager.is_ready
    checks["model"] = "ok" if model_ok else "unavailable"
    if not model_ok:
        all_ready = False
        checks["model_error"] = model_manager.load_error

    # Redis (optional — not critical)
    if _redis_client is not None:
        try:
            await _redis_client.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "unavailable"
    else:
        checks["redis"] = "disabled"

    # WebSocket
    checks["websocket_connections"] = ws_manager.connection_count

    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if all_ready else "not_ready",
        "checks": checks,
    }


@router.get("/api/v1/system/version")
async def get_version() -> dict:
    from app.config import get_settings
    settings = get_settings()
    return {
        "version": settings.APP_VERSION,
        "env": settings.APP_ENV,
        "model_version": model_manager.version if model_manager.is_ready else None,
    }
