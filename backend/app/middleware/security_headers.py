"""
backend/app/middleware/security_headers.py

Adds security headers to every response.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"  # modern browsers ignore it; CSP is better
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # HSTS is set by the reverse proxy in production, not here
        return response
