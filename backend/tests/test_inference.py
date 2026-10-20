"""
backend/tests/test_inference.py

ML inference regression tests against the real model artifact.
These tests verify the existing XGBoost pipeline continues to work
correctly with the new inference service layer.
"""
from __future__ import annotations

import os
import pytest

# Skip if model artifact not present
MODEL_DIR = os.environ.get("MODEL_DIR", "../model/artifacts")
PIPELINE_EXISTS = os.path.exists(os.path.join(MODEL_DIR, "ids_pipeline.pkl"))

pytestmark = pytest.mark.skipif(
    not PIPELINE_EXISTS,
    reason="Model artifacts not found — skipping ML regression tests"
)


@pytest.fixture(scope="module")
def manager():
    """Load the real model manager once for all tests in this module."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../backend/app/ml"))
    from app.ml.model_manager import ModelManager
    from pathlib import Path
    
    mgr = ModelManager()
    mgr.load(
        pipeline_path=Path(MODEL_DIR) / "ids_pipeline.pkl",
        encoder_path=Path(MODEL_DIR) / "label_encoder.pkl",
        metadata_path=Path(MODEL_DIR) / "metadata.json",
    )
    return mgr


def test_model_loads(manager):
    """Model loads successfully and reports ready."""
    assert manager.is_ready
    assert manager.is_ready


def test_feature_count(manager):
    """Model expects exactly 47 features."""
    assert len(manager.feature_names) == 47


def test_class_count(manager):
    """Model supports 15 classes."""
    assert len(manager.classes) == 15


def test_class_names_include_benign(manager):
    """BENIGN class is present."""
    assert "BENIGN" in manager.classes


def test_class_names_no_unicode_replacement(manager):
    """Display class names must not contain Unicode replacement chars."""
    for cls in manager.classes:
        assert "\ufffd" not in cls, f"Class '{cls}' contains replacement char"


def test_prediction_returns_dict(manager):
    """Prediction returns a dict with expected keys."""
    features = {f: 0.0 for f in manager.feature_names}
    result = manager.predict(features)
    assert "prediction" in result
    assert "confidence" in result
    assert "probabilities" in result
    assert "inference_ms" in result


def test_prediction_confidence_range(manager):
    """Confidence must be between 0 and 1."""
    features = {f: 0.0 for f in manager.feature_names}
    result = manager.predict(features)
    assert 0.0 <= result["confidence"] <= 1.0


def test_probabilities_sum_to_one(manager):
    """Probabilities must sum to approximately 1.0."""
    features = {f: 0.0 for f in manager.feature_names}
    result = manager.predict(features)
    total = sum(result["probabilities"].values())
    assert abs(total - 1.0) < 1e-4


def test_nan_features_handled(manager):
    """Features with NaN values should not raise — pipeline handles them."""
    import math
    features = {f: float("nan") for f in manager.feature_names}
    # Should not raise
    result = manager.predict(features)
    assert result["prediction"] in manager.classes


def test_high_fwd_packets_portscan(manager):
    """
    Synthetic PortScan-like flow should classify as PortScan or threat.
    This is NOT a ground-truth assertion — it validates that the model
    produces a valid class for a representative threat-like input.
    """
    features = {f: 0.0 for f in manager.feature_names}
    # PortScan characteristics: many short packets, low duration
    features["Total Fwd Packets"] = 500
    features["Flow Duration"] = 1000000  # 1s in microseconds
    features["Destination Port"] = 22
    features["Flow Packets/s"] = 500.0

    result = manager.predict(features)
    # Just validate structure — model output is valid
    assert result["prediction"] in manager.classes
    assert result["confidence"] > 0


def test_inference_service_validates_features():
    """InferenceService handles missing features gracefully."""
    from app.ml.inference import InferenceService
    svc = InferenceService()
    
    if not svc.is_ready:
        pytest.skip("Model not loaded")
    
    # Empty dict should not crash — missing features become NaN
    result = svc.validate_and_predict({})
    assert "prediction" in result
