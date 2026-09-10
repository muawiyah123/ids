"""
backend/app/security/dependencies.py

FastAPI security dependencies:
  - get_current_user       — validates JWT, returns User
  - require_roles(...)     — RBAC decorator factory
  - get_agent              — validates agent API key for agent endpoints
"""
from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import User, UserRole
from app.models.agent import Agent
from app.security.jwt import decode_access_token
from app.security.hashing import verify_token

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate Bearer JWT and return the authenticated User.
    Raises 401 on any auth failure with a generic message.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id_str: str = payload.get("sub", "")
        if not user_id_str:
            raise credentials_exception
        user_id = uuid.UUID(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.is_active == True,
            User.is_deleted == False,
        )
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception

    return user


def require_roles(*roles: UserRole):
    """
    Dependency factory that restricts access to users with any of the given roles.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_roles(UserRole.ADMIN, UserRole.SUPER_ADMIN))])
    """
    async def _check(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _check


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Standard dependency for any authenticated endpoint."""
    return current_user


async def get_agent(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """
    Validate agent API key (Bearer token) and return the authenticated Agent.
    Used on ingestion and heartbeat endpoints.
    """
    agent_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid agent credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise agent_exception

    token = credentials.credentials

    # Fetch all active agents and verify token hash (constant-time compare)
    # In production with many agents, index on token_hash is used.
    result = await db.execute(
        select(Agent).where(Agent.is_active == True, Agent.is_deleted == False)
    )
    agents = result.scalars().all()

    matched: Optional[Agent] = None
    for agent in agents:
        if verify_token(token, agent.token_hash):
            matched = agent
            break

    if matched is None:
        raise agent_exception

    return matched
