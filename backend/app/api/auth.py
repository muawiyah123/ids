"""
backend/app/api/auth.py — Authentication router.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security.dependencies import get_current_active_user
from app.services.auth_service import AuthService, AuthenticationError
from app.services.audit_service import AuditService

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()
logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Authenticate with email/password and receive JWT token pair."""
    svc = AuthService(db)
    audit = AuditService(db)
    ip = _get_client_ip(request)

    try:
        user = await svc.authenticate(body.email, body.password)
        access_token, refresh_token = await svc.create_tokens(user)

        await audit.log(
            action="USER_LOGIN",
            result="SUCCESS",
            actor=user,
            resource_type="user",
            resource_id=str(user.id),
            ip_address=ip,
            user_agent=request.headers.get("User-Agent", "")[:512],
        )
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    except AuthenticationError:
        await audit.log(
            action="USER_LOGIN",
            result="FAILURE",
            actor_email=body.email,
            ip_address=ip,
            user_agent=request.headers.get("User-Agent", "")[:512],
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Register a new user account (default role: VIEWER)."""
    svc = AuthService(db)
    audit = AuditService(db)
    ip = _get_client_ip(request)

    try:
        user = await svc.register(
            email=body.email,
            password=body.password,
            full_name=body.full_name,
            role=UserRole.VIEWER,
        )
        await audit.log(
            action="USER_REGISTER",
            result="SUCCESS",
            actor=user,
            resource_type="user",
            resource_id=str(user.id),
            ip_address=ip,
        )
        await db.commit()
        return _user_response(user)
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Rotate refresh token and return new access + refresh token pair."""
    svc = AuthService(db)
    try:
        access_token, new_refresh = await svc.refresh_tokens(body.refresh_token)
        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke all sessions for the current user."""
    svc = AuthService(db)
    audit = AuditService(db)
    await svc.revoke_all_tokens(current_user.id)
    await audit.log(
        action="USER_LOGOUT",
        result="SUCCESS",
        actor=current_user,
        ip_address=_get_client_ip(request),
    )
    await db.commit()
    return {"status": "ok"}


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """Return the current authenticated user's profile."""
    return _user_response(current_user)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Change the current user's password and invalidate all sessions."""
    svc = AuthService(db)
    audit = AuditService(db)
    try:
        await svc.change_password(current_user, body.current_password, body.new_password)
        await audit.log(
            action="PASSWORD_CHANGE",
            result="SUCCESS",
            actor=current_user,
            resource_type="user",
            resource_id=str(current_user.id),
            ip_address=_get_client_ip(request),
        )
        await db.commit()
        return {"status": "ok"}
    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        is_active=user.is_active,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat(),
    )
