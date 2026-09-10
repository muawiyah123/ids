"""
backend/tests/test_severity.py — Severity mapping unit tests.
"""
from app.models.detection import DetectionSeverity
from app.utils.severity import compute_severity, should_create_alert


def test_benign_is_always_info():
    assert compute_severity("BENIGN", 0.99) == DetectionSeverity.INFO


def test_benign_no_alert():
    assert should_create_alert("BENIGN", 0.99) is False


def test_low_confidence_is_low():
    assert compute_severity("DDoS", 0.50) == DetectionSeverity.LOW


def test_ddos_high_confidence_is_critical():
    assert compute_severity("DDoS", 0.95) == DetectionSeverity.CRITICAL


def test_portscan_is_medium():
    assert compute_severity("PortScan", 0.90) == DetectionSeverity.MEDIUM


def test_bot_is_critical():
    assert compute_severity("Bot", 0.90) == DetectionSeverity.CRITICAL


def test_web_attack_brute_force_is_high():
    assert compute_severity("Web Attack - Brute Force", 0.90) == DetectionSeverity.HIGH


def test_alert_created_above_threshold():
    assert should_create_alert("DDoS", 0.70) is True


def test_alert_not_created_below_threshold():
    assert should_create_alert("DDoS", 0.50) is False
