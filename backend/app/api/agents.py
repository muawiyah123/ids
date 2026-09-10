"""
backend/app/api/agents.py — Agent management and ingestion endpoints.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.agent import Agent, AgentHeartbeat, AgentStatus
from app.models.user import User, UserRole
from app.security.dependencies import get_agent, get_current_active_user, require_roles
from app.security.hashing import generate_secure_token, hash_token
from app.services.audit_service import AuditService
from app.services.websocket_service import ws_manager

router = APIRouter(prefix="/agents", tags=["Agents"])
settings = get_settings()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    hostname: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = Field(default=None)
    environment: Optional[str] = Field(default=None, max_length=100)


class AgentResponse(BaseModel):
    id: str
    name: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os_info: Optional[str]
    description: Optional[str]
    environment: Optional[str]
    version: Optional[str]
    status: str
    last_heartbeat_at: Optional[str]
    connected_since: Optional[str]
    events_sent: int
    is_active: bool
    created_at: str


class AgentRegisterResponse(AgentResponse):
    """Returned only on registration — contains the plain-text token (shown once)."""
    token: str
    server_url: str


class HeartbeatRequest(BaseModel):
    version: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    ip_address: Optional[str] = None
    agent_protocol_version: Optional[str] = None
    extra: Optional[dict] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _determine_status(agent: Agent) -> AgentStatus:
    if not agent.last_heartbeat_at:
        return AgentStatus.OFFLINE
    age = (datetime.now(timezone.utc) - agent.last_heartbeat_at).total_seconds()
    if age <= settings.AGENT_ONLINE_THRESHOLD_SECONDS:
        return AgentStatus.ONLINE
    if age <= settings.AGENT_DEGRADED_THRESHOLD_SECONDS:
        return AgentStatus.DEGRADED
    return AgentStatus.OFFLINE


def _agent_to_response(agent: Agent, actual_status: Optional[AgentStatus] = None) -> AgentResponse:
    s = actual_status or _determine_status(agent)
    return AgentResponse(
        id=str(agent.id),
        name=agent.name,
        hostname=agent.hostname,
        ip_address=agent.ip_address,
        os_info=agent.os_info,
        description=agent.description,
        environment=agent.environment,
        version=agent.version,
        status=s.value,
        last_heartbeat_at=agent.last_heartbeat_at.isoformat() if agent.last_heartbeat_at else None,
        connected_since=agent.connected_since.isoformat() if agent.connected_since else None,
        events_sent=agent.events_sent,
        is_active=agent.is_active,
        created_at=agent.created_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=List[AgentResponse])
async def list_agents(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List all registered agents."""
    result = await db.execute(
        select(Agent).where(Agent.is_deleted == False).order_by(Agent.created_at.desc())
    )
    agents = result.scalars().all()
    return [_agent_to_response(a) for a in agents]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent_detail(
    agent_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_response(agent)


@router.post("/register", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    body: AgentCreateRequest,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Register a new agent. Returns a plain-text token shown ONCE.
    Store it securely — it cannot be retrieved again.
    """
    raw_token = generate_secure_token(48)

    agent = Agent(
        name=body.name,
        hostname=body.hostname,
        description=body.description,
        environment=body.environment,
        token_hash=hash_token(raw_token),
        status=AgentStatus.OFFLINE,
    )
    db.add(agent)
    await db.flush()

    audit = AuditService(db)
    await audit.log(
        action="AGENT_REGISTERED",
        result="SUCCESS",
        actor=current_user,
        resource_type="agent",
        resource_id=str(agent.id),
        metadata={"name": agent.name},
    )
    await db.commit()
    await db.refresh(agent)

    logger.info("Agent registered: %s by %s", agent.id, current_user.email)

    # Build the installation command/URL for the UI
    server_url = str(request.base_url).rstrip("/")

    response = AgentRegisterResponse(
        **_agent_to_response(agent).model_dump(),
        token=raw_token,
        server_url=server_url,
    )
    return response


@router.post("/{agent_id}/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(
    agent_id: str,
    body: HeartbeatRequest,
    auth_agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Agent heartbeat endpoint. Must be called with the agent's API token.
    Updates status, version, and last_heartbeat_at.
    """
    # Verify the authenticated agent matches the path ID
    if str(auth_agent.id) != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    now = datetime.now(timezone.utc)
    auth_agent.last_heartbeat_at = now
    auth_agent.status = AgentStatus.ONLINE

    if body.version:
        auth_agent.version = body.version
    if body.hostname:
        auth_agent.hostname = body.hostname
    if body.os_info:
        auth_agent.os_info = body.os_info
    if body.ip_address:
        auth_agent.ip_address = body.ip_address
    if body.agent_protocol_version:
        auth_agent.agent_protocol_version = body.agent_protocol_version

    if not auth_agent.connected_since:
        auth_agent.connected_since = now

    # Store heartbeat record
    heartbeat = AgentHeartbeat(
        agent_id=auth_agent.id,
        version=body.version,
        extra=body.extra,
    )
    db.add(heartbeat)
    await db.commit()

    # Broadcast status change
    await ws_manager.broadcast("agent.heartbeat", {
        "agent_id": str(auth_agent.id),
        "status": AgentStatus.ONLINE.value,
        "last_heartbeat_at": now.isoformat(),
    })

    return {"status": "ok", "agent_id": agent_id, "received_at": now.isoformat()}


@router.delete("/{agent_id}")
async def disable_agent(
    agent_id: str,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.is_deleted == False))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.is_active = False
    agent.is_deleted = True
    audit = AuditService(db)
    await audit.log(
        action="AGENT_DISABLED",
        result="SUCCESS",
        actor=current_user,
        resource_type="agent",
        resource_id=agent_id,
    )
    await db.commit()
    return {"status": "ok", "agent_id": agent_id}
