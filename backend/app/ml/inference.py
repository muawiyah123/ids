"""
backend/app/ml/inference.py

InferenceService — thin wrapper around ModelManager that validates
incoming feature dicts and returns structured prediction results.

This is the layer called by the DetectionService.
"""
from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

from app.ml.model_manager import model_manager

logger = logging.getLogger(__name__)

# Features the model expects (populated from ModelManager after load)
# This is referenced at inference time to validate inputs.


class FeatureValidationError(ValueError):
    """Raised when the feature dict does not meet model requirements."""


class InferenceService:
    """
    Stateless service that delegates to the global model_manager singleton.
    Performs input validation and sanitisation before calling the model.
    """

    def validate_and_predict(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate, sanitise, and predict from a raw feature dict.

        Accepts extra features (agent sends full CICFlowMeter output).
        Only the 47 expected features are used; extras are ignored.
        Missing required features default to NaN (the pipeline handles NaN).

        Args:
            raw_features: Any dict from the agent payload.

        Returns:
            Prediction dict as returned by ModelManager.predict()

        Raises:
            FeatureValidationError: if input is fundamentally invalid.
            RuntimeError: if model is not ready.
        """
        if not raw_features or not isinstance(raw_features, dict):
            raise FeatureValidationError("features must be a non-empty dict")

        expected = model_manager.feature_names
        if not expected:
            raise RuntimeError("Model not loaded — feature list is empty")

        # Extract and sanitise the relevant features
        cleaned: Dict[str, float] = {}
        for name in expected:
            val = raw_features.get(name)
            cleaned[name] = self._sanitise_value(name, val)

        result = model_manager.predict(cleaned)
        return result

    @staticmethod
    def _sanitise_value(name: str, val: Any) -> float:
        """
        Convert a raw value to a clean float suitable for the model.

        - None → NaN (pipeline's InfinityAndOutlierSanitizer handles NaN)
        - Inf → NaN (pipeline replaces Inf with NaN internally too,
                     but we do it here to be explicit)
        - non-numeric strings → NaN
        - valid numbers → float
        """
        if val is None:
            return float("nan")
        try:
            f = float(val)
        except (TypeError, ValueError):
            return float("nan")
        if math.isinf(f):
            return float("nan")
        return f

    @property
    def is_ready(self) -> bool:
        return model_manager.is_ready

    @property
    def model_version(self) -> str:
        return model_manager.version

    def status(self) -> Dict[str, Any]:
        return model_manager.status_dict()


# Global singleton
inference_service = InferenceService()
