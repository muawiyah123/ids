"""
backend/app/utils/severity.py

Application-level severity mapping for ML predictions.

IMPORTANT: Severity is NOT a direct ML output.
It is computed by this module based on predicted class, confidence,
and configurable thresholds. This is documented behaviour.
"""
from __future__ import annotations

from app.models.detection import DetectionSeverity


# ---------------------------------------------------------------------------
# Class → base severity mapping
# ---------------------------------------------------------------------------
# These are defaults based on known attack impact ratings.
# Administrators can override thresholds via Settings.

CLASS_SEVERITY_MAP: dict[str, DetectionSeverity] = {
    "BENIGN": DetectionSeverity.INFO,
    "Bot": DetectionSeverity.CRITICAL,
    "DDoS": DetectionSeverity.CRITICAL,
    "DoS": DetectionSeverity.HIGH,
    "DoS GoldenEye": DetectionSeverity.HIGH,
    "DoS Hulk": DetectionSeverity.HIGH,
    "DoS Slowhttptest": DetectionSeverity.HIGH,
    "DoS slowloris": DetectionSeverity.HIGH,
    "FTP-Patator": DetectionSeverity.MEDIUM,
    "Heartbleed": DetectionSeverity.CRITICAL,
    "Infiltration": DetectionSeverity.CRITICAL,
    "PortScan": DetectionSeverity.MEDIUM,
    "SSH-Patator": DetectionSeverity.MEDIUM,
    "Web Attack - Brute Force": DetectionSeverity.HIGH,
    "Web Attack - Sql Injection": DetectionSeverity.HIGH,
    "Web Attack - XSS": DetectionSeverity.HIGH,
}

# Confidence thresholds
HIGH_CONFIDENCE_THRESHOLD = 0.85
LOW_CONFIDENCE_THRESHOLD = 0.60


def compute_severity(
    predicted_class: str,
    confidence: float,
) -> DetectionSeverity:
    """
    Compute application-level severity from ML prediction + confidence.

    Logic:
    - BENIGN is always INFO regardless of confidence
    - Low confidence (<LOW_CONFIDENCE_THRESHOLD) on any threat → LOW
    - High confidence on known critical classes → CRITICAL
    - Otherwise use class default, optionally downgraded by confidence
    """
    if predicted_class == "BENIGN":
        return DetectionSeverity.INFO

    base_severity = CLASS_SEVERITY_MAP.get(predicted_class, DetectionSeverity.MEDIUM)

    # Low confidence → downgrade to LOW (uncertain classification)
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return DetectionSeverity.LOW

    # Medium confidence → downgrade CRITICAL to HIGH
    if confidence < HIGH_CONFIDENCE_THRESHOLD:
        if base_severity == DetectionSeverity.CRITICAL:
            return DetectionSeverity.HIGH

    return base_severity


def should_create_alert(
    predicted_class: str,
    confidence: float,
    threshold: float = 0.60,
) -> bool:
    """Return True if this detection should generate an alert."""
    if predicted_class == "BENIGN":
        return False
    return confidence >= threshold


SEVERITY_ORDER = {
    DetectionSeverity.INFO: 0,
    DetectionSeverity.LOW: 1,
    DetectionSeverity.MEDIUM: 2,
    DetectionSeverity.HIGH: 3,
    DetectionSeverity.CRITICAL: 4,
}


def severity_value(s: DetectionSeverity) -> int:
    """Numeric value for sorting/comparison."""
    return SEVERITY_ORDER.get(s, 0)
