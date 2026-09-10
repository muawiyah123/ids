"""
backend/app/api/audit.py — Audit log read endpoints.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.security.dependencies import get_current_active_user, require_roles
from app.utils.pagination import Page, PageParams

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("", response_model=Page[dict])
async def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: Optional[str] = Query(default=None),
    actor_email: Optional[str] = Query(default=None),
    from_time: Optional[datetime] = Query(default=None),
    to_time: Optional[datetime] = Query(default=None),
    current_user: User = Depends(require_roles(
        UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SOC_ANALYST
    )),
    db: AsyncSession = Depends(get_db),
) -> Any:
    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if actor_email:
        conditions.append(AuditLog.actor_email == actor_email)
    if from_time:
        conditions.append(AuditLog.created_at >= from_time)
    if to_time:
        conditions.append(AuditLog.created_at <= to_time)

    where = and_(*conditions) if conditions else True
    total = (await db.execute(select(func.count(AuditLog.id)).where(where))).scalar_one()
    params = PageParams(page=page, page_size=page_size)

    result = await db.execute(
        select(AuditLog)
        .where(where)
        .order_by(AuditLog.created_at.desc())
        .offset(params.offset)
        .limit(params.page_size)
    )

    logs = [
        {
            "id": str(log.id),
            "actor_email": log.actor_email,
            "actor_role": log.actor_role,
            "action": log.action,
            "result": log.result,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat(),
        }
        for log in result.scalars().all()
    ]

    return Page.create(logs, total, params)
