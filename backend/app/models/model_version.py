"""
backend/app/models/model_version.py

ML model version tracking.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Integer, JSON, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

import enum


class ModelVersionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    STAGED = "STAGED"
    RETIRED = "RETIRED"
    INVALID = "INVALID"


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    model_type: Mapped[str] = mapped_column(String(50), nullable=False)  # xgboost | random_forest

    # Artifact integrity
    artifact_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)  # SHA256
    pipeline_file: Mapped[str | None] = mapped_column(String(512), nullable=True)
    encoder_file: Mapped[str | None] = mapped_column(String(512), nullable=True)

    status: Mapped[ModelVersionStatus] = mapped_column(
        Enum(ModelVersionStatus, name="model_version_status"),
        nullable=False,
        default=ModelVersionStatus.ACTIVE,
    )

    # Training metadata (from metadata.json)
    feature_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    class_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classes: Mapped[list | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    training_run_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metrics: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)

    # Status
    is_loaded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    load_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    loaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
