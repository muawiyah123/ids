"""
backend/app/models/detection.py

Detection ORM model — one record per classified network flow.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

import enum


class DetectionSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Deduplication key from the agent
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True, index=True)

    # Timing
    flow_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Agent
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Network context
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # ML result
    predicted_class: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[DetectionSeverity] = mapped_column(
        Enum(DetectionSeverity, name="detection_severity"), nullable=False, index=True
    )
    model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    inference_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Probability distribution (optional — XGBoost provides these)
    probabilities: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Raw feature payload (stored for investigation / reanalysis)
    raw_features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Extra metadata from agent
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="detections")  # type: ignore[name-defined]
    alerts: Mapped[list["Alert"]] = relationship(  # type: ignore[name-defined]
        "Alert", back_populates="detection"
    )
