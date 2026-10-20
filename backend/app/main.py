"""
backend/app/main.py

FastAPI application entry point.
Handles lifespan (startup/shutdown), middleware, CORS, and router registration.
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("ids.main")


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application startup sequence:
    1. Load ML model (critical — marks /ready as unavailable if fails)
    2. Connect Redis (optional)
    3. Register model version in DB
    """
    # ---- Startup ----
    logger.info("IDS Sentinel starting up (env=%s)", settings.APP_ENV)

    # 1. Load ML model
    from app.ml.model_manager import model_manager
    try:
        model_manager.load(
            pipeline_path=settings.pipeline_path,
            encoder_path=settings.encoder_path,
            metadata_path=settings.metadata_path,
        )
    except Exception as e:
        # Not fatal — app continues, /ready returns 503
        logger.error("Failed to load model: %s", e)

    # 2. Redis (optional)
    redis_client = None
    if settings.REDIS_ENABLED and settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis
            redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await redis_client.ping()
            from app.services.websocket_service import set_redis_client
            set_redis_client(redis_client)
            logger.info("Redis connected: %s", settings.REDIS_URL)
        except Exception as e:
            logger.warning("Redis unavailable (non-critical): %s", e)

    # Optional first administrator bootstrap. This is only enabled when both
    # values are explicitly configured and never resets an existing account.
    if settings.SEED_ADMIN_EMAIL and settings.SEED_ADMIN_PASSWORD:
        try:
            from sqlalchemy import select
            from app.database import AsyncSessionLocal
            from app.models.user import User, UserRole
            from app.services.auth_service import AuthService

            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(User).where(User.email == settings.SEED_ADMIN_EMAIL.lower())
                )
                if result.scalar_one_or_none() is None:
                    await AuthService(session).register(
                        email=settings.SEED_ADMIN_EMAIL,
                        password=settings.SEED_ADMIN_PASSWORD,
                        full_name="IDS Sentinel Administrator",
                        role=UserRole.SUPER_ADMIN,
                    )
                    logger.info("Bootstrapped initial administrator account")
                else:
                    logger.info("Configured administrator already exists; leaving it unchanged")
        except Exception as e:
            logger.error("Administrator bootstrap failed: %s", e)

    # 3. Register/update model version in DB
    if model_manager.is_ready:
        try:
            from app.database import AsyncSessionLocal
            from app.models.model_version import ModelVersion, ModelVersionStatus
            from sqlalchemy import select
            async with AsyncSessionLocal() as session:
                existing = (await session.execute(
                    select(ModelVersion).where(ModelVersion.version == settings.MODEL_VERSION)
                )).scalar_one_or_none()

                if not existing:
                    mv = ModelVersion(
                        version=settings.MODEL_VERSION,
                        model_type=model_manager.metadata.get("model_type", "xgboost"),
                        artifact_hash=model_manager.artifact_hash,
                        feature_count=len(model_manager.feature_names),
                        class_count=len(model_manager.classes),
                        classes=model_manager.classes,
                        training_run_id=model_manager.version,
                        metrics={
                            "macro_f1_test": model_manager.metadata.get("macro_f1_test"),
                            "weighted_f1_test": model_manager.metadata.get("weighted_f1_test"),
                        },
                        status=ModelVersionStatus.ACTIVE,
                        is_loaded=True,
                    )
                    session.add(mv)
                else:
                    existing.is_loaded = True
                    existing.artifact_hash = model_manager.artifact_hash
                await session.commit()
        except Exception as e:
            logger.warning("Could not register model version in DB: %s", e)

    logger.info("Startup complete. Model ready: %s", model_manager.is_ready)

    yield  # App is running

    # ---- Shutdown ----
    logger.info("Shutting down IDS Sentinel…")
    if redis_client:
        await redis_client.close()
    from app.database import engine
    await engine.dispose()
    logger.info("Shutdown complete.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_app() -> FastAPI:
    app = FastAPI(
        title="IDS Sentinel API",
        description=(
            "AI-Powered Real-Time Network Intrusion Detection & Security Monitoring\n\n"
            "**Security monitoring system — authorized use only.**\n\n"
            "AI detections are not infallible and must be validated by security personnel."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ---- Middleware (order matters: outermost runs first on request) ----
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---- Error handlers ----
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    # ---- Routers ----
    from app.api import auth, agents, events, detections, alerts
    from app.api import dashboard, analytics, models_api, audit, health, websocket

    prefix = settings.API_V1_PREFIX

    # Health (no auth, no prefix for Docker health checks)
    app.include_router(health.router)

    # Versioned API
    app.include_router(auth.router, prefix=prefix)
    app.include_router(agents.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(detections.router, prefix=prefix)
    app.include_router(alerts.router, prefix=prefix)
    app.include_router(dashboard.router, prefix=prefix)
    app.include_router(analytics.router, prefix=prefix)
    app.include_router(models_api.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)
    app.include_router(websocket.router, prefix=prefix)

    return app


app = create_app()
