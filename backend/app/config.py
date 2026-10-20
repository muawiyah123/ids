"""
backend/app/config.py

Centralised application configuration backed by environment variables.
Validates at startup so missing/invalid config surfaces immediately.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "IDS Sentinel"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"  # development | staging | production
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    SECRET_KEY: str  # Required — must be set in .env / environment
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str  # Required — postgresql+asyncpg://user:pass@host/db
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # -------------------------------------------------------------------------
    # Redis (optional — graceful degradation if unavailable)
    # -------------------------------------------------------------------------
    REDIS_URL: Optional[str] = None
    REDIS_ENABLED: bool = True  # set False to skip Redis entirely

    # -------------------------------------------------------------------------
    # ML Model
    # -------------------------------------------------------------------------
    # Local startup runs Uvicorn from backend/, beside the top-level model/ directory.
    MODEL_DIR: str = "../model/artifacts"
    MODEL_PIPELINE_FILE: str = "ids_pipeline.pkl"
    MODEL_ENCODER_FILE: str = "label_encoder.pkl"
    MODEL_METADATA_FILE: str = "metadata.json"
    MODEL_VERSION: str = "1.0.0"

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    # Comma-separated list of allowed origins
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    PUBLIC_SERVER_URL: Optional[str] = None

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_REGISTER_PER_MINUTE: int = 5
    RATE_LIMIT_EVENTS_PER_MINUTE: int = 6000  # high-volume agent ingestion
    RATE_LIMIT_API_PER_MINUTE: int = 300

    # -------------------------------------------------------------------------
    # Agent / Heartbeat
    # -------------------------------------------------------------------------
    AGENT_ONLINE_THRESHOLD_SECONDS: int = 60
    AGENT_DEGRADED_THRESHOLD_SECONDS: int = 180

    # -------------------------------------------------------------------------
    # Alert Engine
    # -------------------------------------------------------------------------
    ALERT_CONFIDENCE_THRESHOLD: float = 0.60  # min confidence to create alert
    ALERT_DEDUP_WINDOW_MINUTES: int = 10       # window for deduplication

    # -------------------------------------------------------------------------
    # Data Retention (days)
    # -------------------------------------------------------------------------
    DETECTION_RETENTION_DAYS: int = 90
    ALERT_RETENTION_DAYS: int = 365
    AUDIT_RETENTION_DAYS: int = 730

    # -------------------------------------------------------------------------
    # Demo / Feature Flags
    # -------------------------------------------------------------------------
    DEMO_MODE: bool = False
    ENABLE_EMAIL_ALERTS: bool = False
    ENABLE_THREAT_INTEL: bool = False

    # -------------------------------------------------------------------------
    # API
    # -------------------------------------------------------------------------
    API_V1_PREFIX: str = "/api/v1"
    MAX_EVENT_BATCH_SIZE: int = 500

    # -------------------------------------------------------------------------
    # Admin seed (development only — never use in production)
    # -------------------------------------------------------------------------
    SEED_ADMIN_EMAIL: Optional[str] = None
    SEED_ADMIN_PASSWORD: Optional[str] = None

    # -------------------------------------------------------------------------
    # Computed helpers
    # -------------------------------------------------------------------------
    @property
    def model_dir_path(self) -> Path:
        return Path(self.MODEL_DIR).resolve()

    @property
    def pipeline_path(self) -> Path:
        return self.model_dir_path / self.MODEL_PIPELINE_FILE

    @property
    def encoder_path(self) -> Path:
        return self.model_dir_path / self.MODEL_ENCODER_FILE

    @property
    def metadata_path(self) -> Path:
        return self.model_dir_path / self.MODEL_METADATA_FILE

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.is_production:
            insecure_prefixes = ("replace_me", "changeme", "dev_", "test_")
            if len(self.SECRET_KEY) < 32 or self.SECRET_KEY.lower().startswith(insecure_prefixes):
                raise ValueError("SECRET_KEY must be at least 32 non-placeholder characters in production")
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings singleton. Import this everywhere."""
    return Settings()
