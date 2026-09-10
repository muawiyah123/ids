"""
backend/app/api/events.py — Event ingestion endpoints for agents.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.agent import Agent
from app.schemas.event import AgentEvent, BatchEventRequest, EventIngestionResult
from app.security.dependencies import get_agent
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/events", tags=["Event Ingestion"])
logger = logging.getLogger(__name__)


@router.post("", response_model=dict)
async def ingest_event(
    event: AgentEvent,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Ingest a single network flow event from an authenticated agent.
    Runs ML inference, stores detection, creates alert if applicable.
    """
    svc = DetectionService(db)
    result = await svc.process_event(event, agent)
    return result


@router.post("/batch", response_model=EventIngestionResult)
async def ingest_batch(
    body: BatchEventRequest,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Ingest a batch of events. Validates and processes each independently.
    Returns per-event results and aggregate accepted/rejected counts.
    """
    svc = DetectionService(db)
    results = []
    accepted = 0
    rejected = 0

    for event in body.events:
        try:
            result = await svc.process_event(event, agent)
            results.append(result)
            if result.get("status") in ("accepted", "duplicate"):
                accepted += 1
            else:
                rejected += 1
        except Exception as e:
            logger.error("Event processing error: %s", e)
            results.append({"status": "error", "reason": "Internal processing error"})
            rejected += 1

    return EventIngestionResult(accepted=accepted, rejected=rejected, results=results)
