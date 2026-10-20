"""
backend/app/api/detections.py — Detection list, detail, and export.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection, DetectionSeverity
from app.models.user import User
from app.security.dependencies import get_current_active_user
from app.utils.pagination import Page, PageParams

router = APIRouter(prefix="/detections", tags=["Detections"])
logger = logging.getLogger(__name__)

ALLOWED_SORT_FIELDS = {
    "created_at": Detection.created_at,
    "flow_timestamp": Detection.flow_timestamp,
    "confidence": Detection.confidence,
    "severity": Detection.severity,
    "predicted_class": Detection.predicted_class,
    "source_ip": Detection.source_ip,
}


class DetectionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    id: str
    event_id: Optional[str]
    flow_timestamp: str
    created_at: str
    agent_id: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    predicted_class: str
    confidence: float
    severity: str
    model_version: Optional[str]
    inference_ms: Optional[float]
    probabilities: Optional[dict]


def _det_to_response(d: Detection) -> DetectionResponse:
    return DetectionResponse(
        id=str(d.id),
        event_id=d.event_id,
        flow_timestamp=d.flow_timestamp.isoformat(),
        created_at=d.created_at.isoformat(),
        agent_id=str(d.agent_id) if d.agent_id else None,
        source_ip=d.source_ip,
        destination_ip=d.destination_ip,
        source_port=d.source_port,
        destination_port=d.destination_port,
        protocol=d.protocol,
        predicted_class=d.predicted_class,
        confidence=round(d.confidence, 4),
        severity=d.severity.value,
        model_version=d.model_version,
        inference_ms=d.inference_ms,
        probabilities=d.probabilities,
    )


@router.get("", response_model=Page[DetectionResponse])
async def list_detections(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    severity: Optional[str] = Query(default=None),
    predicted_class: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    destination_ip: Optional[str] = Query(default=None),
    agent_id: Optional[str] = Query(default=None),
    from_time: Optional[datetime] = Query(default=None),
    to_time: Optional[datetime] = Query(default=None),
    min_confidence: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    conditions = []
    if severity:
        try:
            conditions.append(Detection.severity == DetectionSeverity(severity))
        except ValueError:
            pass
    if predicted_class:
        conditions.append(Detection.predicted_class == predicted_class)
    if source_ip:
        conditions.append(Detection.source_ip == source_ip)
    if destination_ip:
        conditions.append(Detection.destination_ip == destination_ip)
    if agent_id:
        conditions.append(Detection.agent_id == agent_id)
    if from_time:
        conditions.append(Detection.flow_timestamp >= from_time)
    if to_time:
        conditions.append(Detection.flow_timestamp <= to_time)
    if min_confidence is not None:
        conditions.append(Detection.confidence >= min_confidence)

    sort_col = ALLOWED_SORT_FIELDS.get(sort_by, Detection.created_at)
    sort_clause = sort_col.desc() if sort_dir == "desc" else sort_col.asc()

    where_clause = and_(*conditions) if conditions else True

    total_result = await db.execute(select(func.count(Detection.id)).where(where_clause))
    total = total_result.scalar_one()

    params = PageParams(page=page, page_size=page_size)
    items_result = await db.execute(
        select(Detection)
        .where(where_clause)
        .order_by(sort_clause)
        .offset(params.offset)
        .limit(params.page_size)
    )
    items = items_result.scalars().all()

    return Page.create([_det_to_response(d) for d in items], total, params)


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    result = await db.execute(select(Detection).where(Detection.id == detection_id))
    det = result.scalar_one_or_none()
    if not det:
        raise HTTPException(status_code=404, detail="Detection not found")
    return _det_to_response(det)


@router.get("/{detection_id}/features")
async def get_detection_features(
    detection_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return the raw feature payload for a detection (for investigation)."""
    result = await db.execute(select(Detection).where(Detection.id == detection_id))
    det = result.scalar_one_or_none()
    if not det:
        raise HTTPException(status_code=404, detail="Detection not found")
    return {"detection_id": detection_id, "features": det.raw_features or {}}


@router.get("/export/csv")
async def export_detections_csv(
    from_time: Optional[datetime] = Query(default=None),
    to_time: Optional[datetime] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Stream detection export as CSV."""
    conditions = []
    if from_time:
        conditions.append(Detection.flow_timestamp >= from_time)
    if to_time:
        conditions.append(Detection.flow_timestamp <= to_time)
    if severity:
        try:
            conditions.append(Detection.severity == DetectionSeverity(severity))
        except ValueError:
            pass

    where_clause = and_(*conditions) if conditions else True
    result = await db.execute(
        select(Detection).where(where_clause).order_by(Detection.created_at.desc()).limit(50000)
    )
    detections = result.scalars().all()

    def generate():
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "id", "flow_timestamp", "source_ip", "destination_ip",
            "source_port", "destination_port", "protocol",
            "predicted_class", "confidence", "severity", "model_version"
        ])
        writer.writeheader()
        for d in detections:
            writer.writerow({
                "id": str(d.id),
                "flow_timestamp": d.flow_timestamp.isoformat(),
                "source_ip": d.source_ip or "",
                "destination_ip": d.destination_ip or "",
                "source_port": d.source_port or "",
                "destination_port": d.destination_port or "",
                "protocol": d.protocol or "",
                "predicted_class": d.predicted_class,
                "confidence": round(d.confidence, 4),
                "severity": d.severity.value,
                "model_version": d.model_version or "",
            })
        yield output.getvalue()

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=detections.csv"},
    )
