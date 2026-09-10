"""
backend/app/middleware/logging.py

Structured request/response logging middleware.
Adds request_id to every log line within a request context.
"""
from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("ids.http")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Attach request_id for downstream use
        request.state.request_id = request_id

        response = await call_next(request)

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Never log auth headers or cookie values
        logger.info(
            "request_id=%s method=%s path=%s status=%d latency_ms=%.1f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )

        response.headers["X-Request-ID"] = request_id
        return response
