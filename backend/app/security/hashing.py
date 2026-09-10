"""
backend/app/security/hashing.py

Password and token hashing utilities.
Uses bcrypt via passlib — strong, salted, adaptive.
"""
from __future__ import annotations

import hashlib
import secrets

from passlib.context import CryptContext

# bcrypt is the recommended scheme — auto-rehash on verify if rounds change
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password. Returns a bcrypt hash string."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe token string."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """
    One-way hash a token for storage.
    We store the hash, not the raw token, so database leaks
    do not expose valid credentials.
    Uses SHA-256 (fast is acceptable here — tokens are already high-entropy).
    """
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    """Check a raw token against its stored hash."""
    return secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), token_hash)
