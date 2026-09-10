"""
backend/app/services/audit_service.py

Audit logging service — append-only, never modifiable.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

logger = logging.getLogger(__name__)


class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        action: str,
        result: str = "SUCCESS",
        actor: Optional[User] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        actor_role: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Create an immutable audit log entry.
        NEVER include passwords, tokens, or secrets in metadata.
        """
        if actor:
            actor_id = actor.id
            actor_email = actor.email
            actor_role = actor.role.value if actor.role else None

        entry = AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            action=action,
            result=result,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata_=metadata,
        )
        self.db.add(entry)
        # Don't commit here — caller controls the transaction
        await self.db.flush()
        return entry
