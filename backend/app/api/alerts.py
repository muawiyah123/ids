"""
backend/app/api/alerts.py — Alert management router.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert, AlertEvent, AlertStatus
from app.models.detection import DetectionSeverity
from app.models.user import User, UserRole
from app.security.dependencies import get_current_active_user, require_roles
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.services.websocket_service import ws_manager
from app.services.attack_advisor import explain_attack
from app.utils.pagination import Page, PageParams

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)

ALLOWED_SORT_FIELDS = {
    "created_at": Alert.created_at,
    "severity": Alert.severity,
    "confidence": Alert.confidence,
    "last_seen_at": Alert.last_seen_at,
    "event_count": Alert.event_count,
    "status": Alert.status,
}


class AlertResponse(BaseModel):
    id: str
    detection_id: Optional[str]
    title: str
    attack_class: str
    severity: str
    status: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    agent_id: Optional[str]
    confidence: float
    event_count: int
    first_seen_at: str
    last_seen_at: str
    assigned_to_id: Optional[str]
    notes: Optional[str]
    created_at: str
    acknowledged_at: Optional[str]
    resolved_at: Optional[str]


class AlertUpdateRequest(BaseModel):
    notes: Optional[str] = None
    assigned_to_id: Optional[str] = None


class StatusChangeRequest(BaseModel):
    comment: Optional[str] = None


def _alert_to_response(a: Alert) -> AlertResponse:
    return AlertResponse(
        id=str(a.id),
        detection_id=str(a.detection_id) if a.detection_id else None,
        title=a.title,
        attack_class=a.attack_class,
        severity=a.severity.value,
        status=a.status.value,
        source_ip=a.source_ip,
        destination_ip=a.destination_ip,
        source_port=a.source_port,
        destination_port=a.destination_port,
        protocol=a.protocol,
        agent_id=str(a.agent_id) if a.agent_id else None,
        confidence=round(a.confidence, 4),
        event_count=a.event_count,
        first_seen_at=a.first_seen_at.isoformat(),
        last_seen_at=a.last_seen_at.isoformat(),
        assigned_to_id=str(a.assigned_to_id) if a.assigned_to_id else None,
        notes=a.notes,
        created_at=a.created_at.isoformat(),
        acknowledged_at=a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        resolved_at=a.resolved_at.isoformat() if a.resolved_at else None,
    )


@router.get("", response_model=Page[AlertResponse])
async def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    attack_class: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    conditions = []
    if severity:
        try:
            conditions.append(Alert.severity == DetectionSeverity(severity))
        except ValueError:
            pass
    if status_filter:
        try:
            conditions.append(Alert.status == AlertStatus(status_filter))
        except ValueError:
            pass
    if attack_class:
        conditions.append(Alert.attack_class == attack_class)
    if source_ip:
        conditions.append(Alert.source_ip == source_ip)

    sort_col = ALLOWED_SORT_FIELDS.get(sort_by, Alert.created_at)
    sort_clause = sort_col.desc() if sort_dir == "desc" else sort_col.asc()
    where_clause = and_(*conditions) if conditions else True

    total = (await db.execute(select(func.count(Alert.id)).where(where_clause))).scalar_one()
    params = PageParams(page=page, page_size=page_size)
    result = await db.execute(
        select(Alert).where(where_clause).order_by(sort_clause).offset(params.offset).limit(params.page_size)
    )
    alerts = result.scalars().all()
    return Page.create([_alert_to_response(a) for a in alerts], total, params)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_response(alert)


@router.post("/{alert_id}/explanation")
async def get_alert_explanation(
    alert_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return defensive guidance directly from the alert's stored classification."""
    alert = await _get_alert_or_404(alert_id, db)
    context = {
        "severity": alert.severity.value,
        "confidence": round(alert.confidence, 4),
        "source_port": alert.source_port,
        "destination_port": alert.destination_port,
        "protocol": alert.protocol,
    }
    return await explain_attack(alert.attack_class, context)


@router.get("/{alert_id}/events")
async def get_alert_events(
    alert_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(
        select(AlertEvent).where(AlertEvent.alert_id == alert_id).order_by(AlertEvent.created_at.asc())
    )
    events = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "action": e.action,
            "from_status": e.from_status,
            "to_status": e.to_status,
            "comment": e.comment,
            "actor_id": str(e.actor_id) if e.actor_id else None,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    body: StatusChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    alert = await _get_alert_or_404(alert_id, db)
    svc = AlertService(db)
    alert = await svc.transition_status(alert, AlertStatus.ACKNOWLEDGED, current_user, body.comment)
    await _audit_and_broadcast(alert, "ALERT_ACKNOWLEDGED", current_user, db)
    await db.commit()
    return _alert_to_response(alert)


@router.post("/{alert_id}/investigate", response_model=AlertResponse)
async def set_investigating(
    alert_id: str,
    body: StatusChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    alert = await _get_alert_or_404(alert_id, db)
    svc = AlertService(db)
    alert = await svc.transition_status(alert, AlertStatus.INVESTIGATING, current_user, body.comment)
    await _audit_and_broadcast(alert, "ALERT_INVESTIGATING", current_user, db)
    await db.commit()
    return _alert_to_response(alert)


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    body: StatusChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    alert = await _get_alert_or_404(alert_id, db)
    svc = AlertService(db)
    alert = await svc.transition_status(alert, AlertStatus.RESOLVED, current_user, body.comment)
    await _audit_and_broadcast(alert, "ALERT_RESOLVED", current_user, db)
    await db.commit()
    return _alert_to_response(alert)


@router.post("/{alert_id}/false-positive", response_model=AlertResponse)
async def mark_false_positive(
    alert_id: str,
    body: StatusChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    alert = await _get_alert_or_404(alert_id, db)
    svc = AlertService(db)
    alert = await svc.transition_status(alert, AlertStatus.FALSE_POSITIVE, current_user, body.comment)
    await _audit_and_broadcast(alert, "ALERT_FALSE_POSITIVE", current_user, db)
    await db.commit()
    return _alert_to_response(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    body: AlertUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    alert = await _get_alert_or_404(alert_id, db)
    if body.notes is not None:
        alert.notes = body.notes
    if body.assigned_to_id is not None:
        alert.assigned_to_id = body.assigned_to_id
    await db.commit()
    return _alert_to_response(alert)


async def _get_alert_or_404(alert_id: str, db: AsyncSession) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


async def _audit_and_broadcast(
    alert: Alert, action: str, actor: User, db: AsyncSession
) -> None:
    audit = AuditService(db)
    await audit.log(
        action=action,
        result="SUCCESS",
        actor=actor,
        resource_type="alert",
        resource_id=str(alert.id),
    )
    await ws_manager.broadcast("alert.updated", {
        "id": str(alert.id),
        "status": alert.status.value,
        "severity": alert.severity.value,
    })
