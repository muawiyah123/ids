"""
backend/app/services/alert_service.py

AlertService — creates, deduplicates, and manages alert lifecycle.

Deduplication strategy:
  Same (attack_class, source_ip, destination_ip) within DEDUP_WINDOW_MINUTES
  → update existing NEW/ACKNOWLEDGED alert (increment count, update last_seen).
  → do NOT create a duplicate alert.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.alert import Alert, AlertEvent, AlertStatus
from app.models.detection import Detection, DetectionSeverity
from app.models.user import User

settings = get_settings()
logger = logging.getLogger(__name__)

# States where we will update rather than create a new alert
DEDUP_OPEN_STATES = (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING)


class AlertService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def process_detection(self, detection: Detection) -> Optional[Alert]:
        """
        Evaluate a detection and create or update an alert.
        Returns the alert if one was created/updated, else None.
        """
        from app.utils.severity import should_create_alert

        rule_detected = (detection.metadata_ or {}).get("detection_rule") in {
            "tcp_port_scan_correlation",
            "tcp_syn_flood_rate",
        }
        if not rule_detected and not should_create_alert(
            detection.predicted_class,
            detection.confidence,
            threshold=settings.ALERT_CONFIDENCE_THRESHOLD,
        ):
            return None  # BENIGN or below threshold — no alert

        # Try to find an existing open alert for deduplication
        existing = await self._find_dedup_alert(
            attack_class=detection.predicted_class,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
        )

        if existing:
            # Update existing alert
            existing.event_count += 1
            existing.last_seen_at = detection.created_at
            # Escalate severity if detection is worse
            if self._severity_value(detection.severity) > self._severity_value(existing.severity):
                existing.severity = detection.severity
            if detection.confidence > existing.confidence:
                existing.confidence = detection.confidence
            existing.updated_at = datetime.now(timezone.utc)

            # Record the update event
            alert_event = AlertEvent(
                alert_id=existing.id,
                action="DETECTION_CORRELATED",
                comment=f"Correlated detection {detection.id} (count={existing.event_count})",
            )
            self.db.add(alert_event)
            await self.db.flush()
            logger.debug("Alert %s updated (count=%d)", existing.id, existing.event_count)
            return existing

        # Create new alert
        now = datetime.now(timezone.utc)
        alert = Alert(
            detection_id=detection.id,
            title=self._generate_title(detection),
            attack_class=detection.predicted_class,
            severity=detection.severity,
            status=AlertStatus.NEW,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            source_port=detection.source_port,
            destination_port=detection.destination_port,
            protocol=detection.protocol,
            agent_id=detection.agent_id,
            confidence=detection.confidence,
            event_count=1,
            first_seen_at=detection.flow_timestamp,
            last_seen_at=detection.flow_timestamp,
        )
        self.db.add(alert)
        await self.db.flush()

        # Record creation event
        alert_event = AlertEvent(
            alert_id=alert.id,
            action="ALERT_CREATED",
            to_status=AlertStatus.NEW.value,
            comment=f"Alert generated from detection {detection.id}",
        )
        self.db.add(alert_event)
        await self.db.flush()
        logger.info(
            "Alert created: %s class=%s severity=%s",
            alert.id, alert.attack_class, alert.severity,
        )
        return alert

    async def _find_dedup_alert(
        self,
        attack_class: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
    ) -> Optional[Alert]:
        """Find open alert matching same class + source/dest within dedup window."""
        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=settings.ALERT_DEDUP_WINDOW_MINUTES
        )
        conditions = [
            Alert.attack_class == attack_class,
            Alert.status.in_(DEDUP_OPEN_STATES),
            Alert.last_seen_at >= cutoff,
        ]
        if source_ip:
            conditions.append(Alert.source_ip == source_ip)
        if destination_ip:
            conditions.append(Alert.destination_ip == destination_ip)

        result = await self.db.execute(
            select(Alert)
            .where(and_(*conditions))
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def transition_status(
        self,
        alert: Alert,
        new_status: AlertStatus,
        actor: Optional[User],
        comment: Optional[str] = None,
    ) -> Alert:
        """Move alert through its lifecycle state machine."""
        from_status = alert.status

        now = datetime.now(timezone.utc)
        alert.status = new_status
        alert.updated_at = now

        if new_status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = now
        elif new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = now

        if actor:
            alert.assigned_to_id = actor.id

        alert_event = AlertEvent(
            alert_id=alert.id,
            actor_id=actor.id if actor else None,
            action=f"STATUS_CHANGED",
            from_status=from_status.value,
            to_status=new_status.value,
            comment=comment,
        )
        self.db.add(alert_event)
        await self.db.flush()
        return alert

    @staticmethod
    def _generate_title(detection: Detection) -> str:
        parts = [detection.predicted_class]
        if detection.source_ip:
            parts.append(f"from {detection.source_ip}")
        if detection.destination_ip:
            parts.append(f"→ {detection.destination_ip}")
        return " ".join(parts)

    @staticmethod
    def _severity_value(s: DetectionSeverity) -> int:
        return {
            DetectionSeverity.INFO: 0,
            DetectionSeverity.LOW: 1,
            DetectionSeverity.MEDIUM: 2,
            DetectionSeverity.HIGH: 3,
            DetectionSeverity.CRITICAL: 4,
        }.get(s, 0)
