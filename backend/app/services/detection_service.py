"""
backend/app/services/detection_service.py

DetectionService — the core detection pipeline:
  1. Validate event
  2. Check idempotency (event_id dedup)
  3. Run ML inference
  4. Calculate severity
  5. Store Detection
  6. Run AlertService
  7. Broadcast WebSocket event
  8. Return result
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ml.inference import inference_service, FeatureValidationError
from app.models.agent import Agent
from app.models.detection import Detection, DetectionSeverity
from app.schemas.event import AgentEvent
from app.services.alert_service import AlertService
from app.services.websocket_service import ws_manager
from app.utils.severity import compute_severity

logger = logging.getLogger(__name__)


class DetectionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def process_event(
        self,
        event: AgentEvent,
        agent: Agent,
    ) -> Dict[str, Any]:
        """
        Full detection pipeline for a single event.
        Returns a result dict (accepted or rejected with reason).
        """
        # 1. Idempotency — skip if event_id already processed
        if event.event_id:
            existing = await self.db.execute(
                select(Detection).where(Detection.event_id == event.event_id)
            )
            if existing.scalar_one_or_none():
                logger.debug("Duplicate event_id=%s — skipped", event.event_id)
                return {
                    "status": "duplicate",
                    "event_id": event.event_id,
                    "message": "Event already processed",
                }

        # 2. Run ML inference
        try:
            inference_result = inference_service.validate_and_predict(event.features)
        except FeatureValidationError as e:
            return {"status": "rejected", "reason": str(e)}
        except RuntimeError as e:
            logger.error("Inference runtime error: %s", e)
            return {"status": "error", "reason": "Model inference unavailable"}

        predicted_class = inference_result["prediction"]
        confidence = inference_result["confidence"]

        # 3. Compute severity
        severity = compute_severity(predicted_class, confidence)

        # 4. Resolve flow timestamp
        flow_ts = event.timestamp or datetime.now(timezone.utc)
        if flow_ts.tzinfo is None:
            flow_ts = flow_ts.replace(tzinfo=timezone.utc)

        # 5. Store detection
        detection = Detection(
            event_id=event.event_id,
            flow_timestamp=flow_ts,
            agent_id=agent.id,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            predicted_class=predicted_class,
            confidence=confidence,
            severity=severity,
            model_version=inference_result.get("model_version"),
            inference_ms=inference_result.get("inference_ms"),
            probabilities=inference_result.get("probabilities"),
            raw_features=dict(event.features),  # store as-is (full agent payload)
            metadata_=event.metadata,
        )
        self.db.add(detection)

        # Update agent event count and heartbeat
        agent.events_sent = (agent.events_sent or 0) + 1
        agent.last_heartbeat_at = datetime.now(timezone.utc)
        await self.db.flush()  # assigns detection.id

        # 6. Alert engine
        alert_service = AlertService(self.db)
        alert = await alert_service.process_detection(detection)

        await self.db.commit()
        await self.db.refresh(detection)

        # 7. Broadcast WebSocket event
        await self._broadcast(detection, alert)

        result = {
            "status": "accepted",
            "detection_id": str(detection.id),
            "prediction": predicted_class,
            "confidence": round(confidence, 4),
            "severity": severity.value,
            "alert_id": str(alert.id) if alert else None,
        }

        logger.info(
            "Detection: id=%s class=%s conf=%.3f sev=%s agent=%s inference_ms=%.1f",
            detection.id,
            predicted_class,
            confidence,
            severity.value,
            agent.id,
            inference_result.get("inference_ms", 0),
        )

        return result

    async def _broadcast(
        self, detection: Detection, alert: Optional[Any]
    ) -> None:
        """Broadcast detection (and optional alert) via WebSocket."""
        detection_data = {
            "id": str(detection.id),
            "flow_timestamp": detection.flow_timestamp.isoformat(),
            "source_ip": detection.source_ip,
            "destination_ip": detection.destination_ip,
            "source_port": detection.source_port,
            "destination_port": detection.destination_port,
            "protocol": detection.protocol,
            "predicted_class": detection.predicted_class,
            "confidence": detection.confidence,
            "severity": detection.severity.value,
            "agent_id": str(detection.agent_id) if detection.agent_id else None,
            "model_version": detection.model_version,
            "inference_ms": detection.inference_ms,
        }
        try:
            await ws_manager.broadcast("detection.created", detection_data)

            if alert:
                await ws_manager.broadcast("alert.created", {
                    "id": str(alert.id),
                    "title": alert.title,
                    "attack_class": alert.attack_class,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "confidence": alert.confidence,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "event_count": alert.event_count,
                })
        except Exception as e:
            logger.warning("WS broadcast failed: %s", e)
