"""
backend/app/security/jwt.py

JWT access token creation and verification.
Refresh tokens use the secure random token approach (not JWT) and are
stored as hashed values in the database.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()

ACCESS_TOKEN_TYPE = "access"


def create_access_token(
    subject: str,  # user UUID as string
    role: str,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Raises:
        JWTError: if the token is invalid, expired, or tampered.
    """
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise JWTError("Invalid token type")
    return payload
