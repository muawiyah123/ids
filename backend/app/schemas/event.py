"""
backend/app/schemas/event.py

Strict Pydantic schema for incoming agent events.
Validates network flow feature payload before it reaches the ML model.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# IP validation helpers
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")

def _is_valid_ip(v: str) -> bool:
    return bool(_IPV4_RE.match(v) or _IPV6_RE.match(v))


class AgentEvent(BaseModel):
    """
    A single network-flow event from an agent.
    The `features` dict may contain all CICFlowMeter columns;
    the backend picks the 47 needed by the model.
    """
    # Deduplication / idempotency key (optional, agent-generated UUID)
    event_id: Optional[str] = Field(default=None, max_length=128)

    # Schema version for forward compatibility
    schema_version: str = Field(default="1.0", max_length=20)

    # Timestamp of the flow (not the submission time)
    timestamp: Optional[datetime] = None

    # Network context (optional — agent may not always have this)
    source_ip: Optional[str] = Field(default=None, max_length=45)
    destination_ip: Optional[str] = Field(default=None, max_length=45)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=10)

    # The full feature payload (required)
    features: Dict[str, Any] = Field(
        description="CICFlowMeter-style feature dict. All numeric values."
    )

    # Optional metadata
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Any) -> Optional[str]:
        if v is None or v == "":
            return None
        if not _is_valid_ip(str(v)):
            return None  # accept but nullify invalid IPs rather than rejecting the whole event
        return str(v)

    @field_validator("protocol", mode="before")
    @classmethod
    def normalise_protocol(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return str(v).upper()[:10]

    @model_validator(mode="after")
    def check_features_not_empty(self) -> "AgentEvent":
        if not self.features:
            raise ValueError("features dict must not be empty")
        return self


class BatchEventRequest(BaseModel):
    """Batch of up to MAX_EVENT_BATCH_SIZE events."""
    events: List[AgentEvent] = Field(min_length=1)

    @field_validator("events")
    @classmethod
    def limit_batch_size(cls, v: List[AgentEvent]) -> List[AgentEvent]:
        from app.config import get_settings
        max_size = get_settings().MAX_EVENT_BATCH_SIZE
        if len(v) > max_size:
            raise ValueError(f"Batch exceeds maximum size of {max_size}")
        return v


class EventIngestionResult(BaseModel):
    accepted: int
    rejected: int
    results: List[Dict[str, Any]] = []
