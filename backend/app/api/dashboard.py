"""
backend/app/api/dashboard.py — Dashboard summary and timeline endpoints.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func, case, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.agent import Agent, AgentStatus
from app.models.detection import Detection, DetectionSeverity
from app.models.user import User
from app.ml.model_manager import model_manager
from app.security.dependencies import get_current_active_user
from app.services.websocket_service import ws_manager

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class DashboardSummary(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    total_detections: int
    threats_detected: int          # non-BENIGN detections
    critical_alerts: int
    open_alerts: int
    active_agents: int
    events_last_hour: int
    events_last_minute_rate: float
    model_status: str
    threat_level: str              # NORMAL | ELEVATED | HIGH | CRITICAL


class TimelinePoint(BaseModel):
    timestamp: str
    total: int
    benign: int
    threats: int


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    minute_ago = now - timedelta(minutes=1)
    day_ago = now - timedelta(days=1)

    # Total detections
    total = (await db.execute(select(func.count(Detection.id)))).scalar_one()

    # Threats (non-BENIGN)
    threats = (await db.execute(
        select(func.count(Detection.id)).where(Detection.predicted_class != "BENIGN")
    )).scalar_one()

    # Critical alerts
    critical = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity == DetectionSeverity.CRITICAL,
            Alert.status.notin_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]),
        )
    )).scalar_one()

    # Open alerts
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.status.notin_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
        )
    )).scalar_one()

    # Active agents (heartbeat within threshold)
    active_agents = 0
    agents_result = await db.execute(select(Agent).where(Agent.is_active == True, Agent.is_deleted == False))
    for agent in agents_result.scalars().all():
        if agent.last_heartbeat_at:
            age = (now - agent.last_heartbeat_at).total_seconds()
            if age <= 180:  # ONLINE or DEGRADED
                active_agents += 1

    # Events last hour
    events_hour = (await db.execute(
        select(func.count(Detection.id)).where(Detection.created_at >= hour_ago)
    )).scalar_one()

    # Events last minute (for rate)
    events_minute = (await db.execute(
        select(func.count(Detection.id)).where(Detection.created_at >= minute_ago)
    )).scalar_one()

    # Threat level based on recent data
    threat_level = _compute_threat_level(critical, open_alerts, events_hour)

    return DashboardSummary(
        total_detections=total,
        threats_detected=threats,
        critical_alerts=critical,
        open_alerts=open_alerts,
        active_agents=active_agents,
        events_last_hour=events_hour,
        events_last_minute_rate=float(events_minute),
        model_status="READY" if model_manager.is_ready else "UNAVAILABLE",
        threat_level=threat_level,
    )


@router.get("/timeline", response_model=List[TimelinePoint])
async def get_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=5, le=1440),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return detection timeline bucketed by time interval."""
    now = datetime.now(timezone.utc)
    from_time = now - timedelta(hours=hours)

    result = await db.execute(
        select(Detection.created_at, Detection.predicted_class)
        .where(Detection.created_at >= from_time)
        .order_by(Detection.created_at.asc())
    )
    rows = result.all()

    # Build buckets
    bucket_secs = bucket_minutes * 60
    buckets: dict = {}
    for ts, cls in rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        bucket_start = datetime.fromtimestamp(
            (ts.timestamp() // bucket_secs) * bucket_secs, tz=timezone.utc
        )
        key = bucket_start.isoformat()
        if key not in buckets:
            buckets[key] = {"total": 0, "benign": 0, "threats": 0}
        buckets[key]["total"] += 1
        if cls == "BENIGN":
            buckets[key]["benign"] += 1
        else:
            buckets[key]["threats"] += 1

    return [
        TimelinePoint(timestamp=k, **v)
        for k, v in sorted(buckets.items())
    ]


def _compute_threat_level(critical: int, open_alerts: int, events_hour: int) -> str:
    """
    Application-level threat indicator. NOT a mathematically proven security score.
    Based on recent alert/detection data as a rough operational guide.
    """
    if critical >= 5 or (critical >= 1 and events_hour > 500):
        return "CRITICAL"
    if critical >= 1 or open_alerts >= 10:
        return "HIGH"
    if open_alerts >= 3 or events_hour > 100:
        return "ELEVATED"
    return "NORMAL"
