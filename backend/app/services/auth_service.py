"""
backend/app/services/auth_service.py

Authentication and session management service.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.user import User, UserRole, RefreshToken
from app.security.hashing import (
    hash_password,
    verify_password,
    generate_secure_token,
    hash_token,
    verify_token,
)
from app.security.jwt import create_access_token

settings = get_settings()
logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Generic auth error — do not include specifics in user-facing messages."""


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Register
    # ------------------------------------------------------------------
    async def register(
        self,
        email: str,
        password: str,
        full_name: str,
        role: UserRole = UserRole.VIEWER,
    ) -> User:
        # Check uniqueness
        existing = await self.db.execute(
            select(User).where(User.email == email.lower(), User.is_deleted == False)
        )
        if existing.scalar_one_or_none():
            raise AuthenticationError("Email already registered")

        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name=full_name,
            role=role,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        logger.info("User registered: %s role=%s", user.email, user.role)
        return user

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    async def authenticate(self, email: str, password: str) -> User:
        result = await self.db.execute(
            select(User).where(
                User.email == email.lower(),
                User.is_active == True,
                User.is_deleted == False,
            )
        )
        user = result.scalar_one_or_none()

        # Always run verify to prevent timing oracle attacks
        dummy_hash = "$2b$12$placeholder_to_prevent_timing_oracle_attack"
        candidate_hash = user.hashed_password if user else dummy_hash

        if not verify_password(password, candidate_hash) or user is None:
            raise AuthenticationError("Invalid credentials")

        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        await self.db.commit()
        return user

    # ------------------------------------------------------------------
    # Token pair
    # ------------------------------------------------------------------
    async def create_tokens(self, user: User) -> Tuple[str, str]:
        """Create access + refresh token pair."""
        access_token = create_access_token(
            subject=str(user.id),
            role=user.role.value,
        )

        # Refresh token: cryptographically secure random string, stored hashed
        raw_refresh = generate_secure_token(48)
        hashed_refresh = hash_token(raw_refresh)

        refresh_record = RefreshToken(
            user_id=user.id,
            token_hash=hashed_refresh,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        self.db.add(refresh_record)
        await self.db.commit()
        return access_token, raw_refresh

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------
    async def refresh_tokens(self, raw_refresh: str) -> Tuple[str, str]:
        """Rotate refresh token — revoke old, issue new pair."""
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        )
        all_active = result.scalars().all()

        matched: Optional[RefreshToken] = None
        for rt in all_active:
            if verify_token(raw_refresh, rt.token_hash):
                matched = rt
                break

        if not matched:
            raise AuthenticationError("Invalid or expired refresh token")

        # Revoke old token (rotation)
        matched.is_revoked = True

        # Load user
        user_result = await self.db.execute(
            select(User).where(User.id == matched.user_id, User.is_active == True)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            raise AuthenticationError("User not found or inactive")

        await self.db.commit()
        return await self.create_tokens(user)

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------
    async def revoke_all_tokens(self, user_id: uuid.UUID) -> None:
        """Revoke all refresh tokens for a user (logout all sessions)."""
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            )
        )
        for rt in result.scalars().all():
            rt.is_revoked = True
        await self.db.commit()

    # ------------------------------------------------------------------
    # Password change
    # ------------------------------------------------------------------
    async def change_password(
        self, user: User, current_password: str, new_password: str
    ) -> None:
        if not verify_password(current_password, user.hashed_password):
            raise AuthenticationError("Current password is incorrect")
        user.hashed_password = hash_password(new_password)
        # Invalidate all sessions after password change
        await self.revoke_all_tokens(user.id)
        await self.db.commit()
