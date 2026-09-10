"""
backend/app/api/analytics.py — Analytics endpoints for charts.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert
from app.models.detection import Detection, DetectionSeverity
from app.models.user import User
from app.security.dependencies import get_current_active_user

router = APIRouter(prefix="/analytics", tags=["Analytics"])


def _time_range(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


@router.get("/attack-distribution")
async def attack_distribution(
    hours: int = Query(default=24, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Count of each attack class over the given time window."""
    since = _time_range(hours)
    result = await db.execute(
        select(Detection.predicted_class, func.count(Detection.id).label("count"))
        .where(Detection.created_at >= since)
        .group_by(Detection.predicted_class)
        .order_by(func.count(Detection.id).desc())
    )
    return [{"class": r[0], "count": r[1]} for r in result.all()]


@router.get("/severity-distribution")
async def severity_distribution(
    hours: int = Query(default=24, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    since = _time_range(hours)
    result = await db.execute(
        select(Detection.severity, func.count(Detection.id).label("count"))
        .where(Detection.created_at >= since)
        .group_by(Detection.severity)
    )
    return [{"severity": r[0].value, "count": r[1]} for r in result.all()]


@router.get("/top-sources")
async def top_sources(
    limit: int = Query(default=10, ge=1, le=50),
    hours: int = Query(default=24, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Top source IPs by detection count (threat traffic only)."""
    since = _time_range(hours)
    result = await db.execute(
        select(Detection.source_ip, func.count(Detection.id).label("count"))
        .where(
            Detection.created_at >= since,
            Detection.source_ip.isnot(None),
            Detection.predicted_class != "BENIGN",
        )
        .group_by(Detection.source_ip)
        .order_by(func.count(Detection.id).desc())
        .limit(limit)
    )
    return [{"ip": r[0], "count": r[1]} for r in result.all()]


@router.get("/top-destinations")
async def top_destinations(
    limit: int = Query(default=10, ge=1, le=50),
    hours: int = Query(default=24, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    since = _time_range(hours)
    result = await db.execute(
        select(Detection.destination_ip, func.count(Detection.id).label("count"))
        .where(
            Detection.created_at >= since,
            Detection.destination_ip.isnot(None),
            Detection.predicted_class != "BENIGN",
        )
        .group_by(Detection.destination_ip)
        .order_by(func.count(Detection.id).desc())
        .limit(limit)
    )
    return [{"ip": r[0], "count": r[1]} for r in result.all()]


@router.get("/trends")
async def trends(
    hours: int = Query(default=168, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Daily detection counts over the given window."""
    since = _time_range(hours)
    result = await db.execute(
        select(
            func.date_trunc("day", Detection.created_at).label("day"),
            func.count(Detection.id).label("total"),
            func.count(
                func.nullif(Detection.predicted_class == "BENIGN", False)
            ).label("threats"),
        )
        .where(Detection.created_at >= since)
        .group_by(text("day"))
        .order_by(text("day"))
    )
    return [
        {"date": r[0].isoformat() if r[0] else None, "total": r[1], "threats": r[2]}
        for r in result.all()
    ]


@router.get("/confidence-distribution")
async def confidence_distribution(
    hours: int = Query(default=24, ge=1, le=720),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Bucketed confidence score distribution."""
    since = _time_range(hours)
    result = await db.execute(
        select(Detection.confidence)
        .where(Detection.created_at >= since, Detection.predicted_class != "BENIGN")
    )
    values = [r[0] for r in result.all()]

    buckets = {f"{i*10}-{(i+1)*10}%": 0 for i in range(10)}
    for v in values:
        idx = min(int(v * 10), 9)
        key = f"{idx*10}-{(idx+1)*10}%"
        buckets[key] = buckets.get(key, 0) + 1

    return [{"bucket": k, "count": v} for k, v in buckets.items()]
