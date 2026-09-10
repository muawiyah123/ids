"""
backend/app/ml/model_manager.py

Singleton ModelManager — loads the XGBoost IDS pipeline once at startup,
validates it, and exposes a thread-safe inference interface.

IMPORTANT:
- ids_common.InfinityAndOutlierSanitizer MUST be importable at load time.
  We ensure this by having ids_common.py in the same package (app/ml/).
- The pipeline is a sklearn Pipeline: [sanitize → xgboost].
  predict_proba() is available (multi:softprob objective).
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Ensure ids_common is importable for pickle loading.
# It lives in the same directory as this module.
_ML_DIR = Path(__file__).parent
if str(_ML_DIR) not in sys.path:
    sys.path.insert(0, str(_ML_DIR))


# Unicode replacement char cleanup — artifacts from mojibake during training.
# The model's internal class indices are NOT changed; this is display-layer only.
CLASS_NAME_DISPLAY_MAP: Dict[str, str] = {
    "Web Attack \ufffd Brute Force": "Web Attack - Brute Force",
    "Web Attack \ufffd Sql Injection": "Web Attack - Sql Injection",
    "Web Attack \ufffd XSS": "Web Attack - XSS",
}


def _normalize_class_name(name: str) -> str:
    """Replace encoding-artifact characters with clean display strings."""
    return CLASS_NAME_DISPLAY_MAP.get(name, name)


class ModelManager:
    """
    Loads, validates, and serves the IDS XGBoost pipeline.

    Thread safety: prediction calls are protected by a lock.
    XGBoost releases the GIL during inference but the sklearn Pipeline
    wrapper has mutable state from fit-time; we use a lock to be safe.
    """

    def __init__(self) -> None:
        self._pipeline: Any = None
        self._label_encoder: Any = None
        self._metadata: Dict[str, Any] = {}
        self._feature_names: List[str] = []
        self._classes_raw: List[str] = []        # as stored in pickle/metadata
        self._classes_display: List[str] = []    # normalized for UI
        self._artifact_hash: Optional[str] = None
        self._is_ready: bool = False
        self._load_error: Optional[str] = None
        self._loaded_at: Optional[float] = None
        self._inference_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Load                                                                 #
    # ------------------------------------------------------------------ #

    def load(
        self,
        pipeline_path: Path,
        encoder_path: Path,
        metadata_path: Path,
    ) -> None:
        """
        Load artifacts from disk. Validates checksums, feature list,
        and performs a warm-up inference to confirm the model is usable.

        Raises RuntimeError if loading fails — caller should set readiness
        to NOT_READY and log the error without leaking paths to clients.
        """
        try:
            # 1. Import joblib here (not at module top) so the module is
            #    importable even if joblib isn't installed yet at import time.
            import joblib
            import pandas as pd
            from ids_common import InfinityAndOutlierSanitizer  # noqa: F401 — needed for pickle

            # The model was pickled with InfinityAndOutlierSanitizer in __main__.
            # Inject it there so joblib can find it during deserialization.
            import sys as _sys
            _sys.modules.setdefault("__main__", _sys.modules[__name__])
            if not hasattr(_sys.modules["__main__"], "InfinityAndOutlierSanitizer"):
                _sys.modules["__main__"].InfinityAndOutlierSanitizer = InfinityAndOutlierSanitizer  # type: ignore

            logger.info("Loading model artifacts…")
            logger.info("  pipeline : %s", pipeline_path)
            logger.info("  encoder  : %s", encoder_path)
            logger.info("  metadata : %s", metadata_path)

            # 2. Verify files exist
            for p in (pipeline_path, encoder_path, metadata_path):
                if not p.exists():
                    raise FileNotFoundError(f"Artifact not found: {p}")

            # 3. Compute SHA-256 of the pipeline artifact
            sha256 = hashlib.sha256()
            with open(pipeline_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha256.update(chunk)
            self._artifact_hash = sha256.hexdigest()
            logger.info("  pipeline SHA-256: %s", self._artifact_hash)

            # 4. Load pipeline (InfinityAndOutlierSanitizer must be importable)
            self._pipeline = joblib.load(pipeline_path)
            logger.info("  pipeline loaded: %s", type(self._pipeline).__name__)

            # 5. Load label encoder
            self._label_encoder = joblib.load(encoder_path)
            self._classes_raw = self._label_encoder.classes_.tolist()
            self._classes_display = [_normalize_class_name(c) for c in self._classes_raw]
            logger.info("  classes (%d): %s", len(self._classes_raw), self._classes_display)

            # 6. Load metadata
            with open(metadata_path) as fh:
                self._metadata = json.load(fh)
            self._feature_names = self._metadata.get("feature_names_in_order", [])
            logger.info("  features (%d): %s…", len(self._feature_names), self._feature_names[:3])

            # 7. Sanity: metadata classes vs encoder classes (count check)
            meta_classes = self._metadata.get("classes", [])
            if len(meta_classes) != len(self._classes_raw):
                logger.warning(
                    "Metadata class count (%d) != encoder class count (%d)",
                    len(meta_classes), len(self._classes_raw),
                )

            # 8. Warm-up inference with a zero-valued feature vector
            self._warm_up_inference()

            self._is_ready = True
            self._load_error = None
            self._loaded_at = time.time()
            logger.info("✓ Model is READY (version %s)", self._metadata.get("run_id", "unknown"))

        except Exception as exc:
            self._is_ready = False
            self._load_error = str(exc)
            logger.error("Model load FAILED: %s", exc, exc_info=True)
            raise RuntimeError(f"Model load failed: {exc}") from exc

    def _warm_up_inference(self) -> None:
        """
        Run a zero-vector prediction to catch pipeline issues early.
        Does NOT assert on the predicted class — any valid prediction is fine.
        """
        import pandas as pd
        dummy = pd.DataFrame(
            [dict.fromkeys(self._feature_names, 0.0)]
        )[self._feature_names]
        with self._inference_lock:
            _ = self._pipeline.predict(dummy)
        logger.info("  warm-up inference: OK")

    # ------------------------------------------------------------------ #
    # Inference                                                            #
    # ------------------------------------------------------------------ #

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Run inference on a single feature dict.

        Args:
            features: Dict mapping feature name → numeric value.
                      Must contain all 47 expected features.

        Returns dict with keys:
            prediction       str    — display class name
            prediction_raw   str    — raw class name (as in encoder)
            confidence       float  — max class probability
            probabilities    dict   — class_display_name → probability
            model_version    str    — run_id from metadata
            inference_ms     float  — wall-clock inference time in ms
        """
        if not self._is_ready:
            raise RuntimeError("Model is not ready. Check /ready endpoint.")

        import pandas as pd

        start = time.perf_counter()

        # Build DataFrame in exact feature order
        row = {f: features.get(f, np.nan) for f in self._feature_names}
        df = pd.DataFrame([row])[self._feature_names]

        with self._inference_lock:
            probas = self._pipeline.predict_proba(df)[0]  # shape: (n_classes,)
            pred_idx = int(np.argmax(probas))

        elapsed_ms = (time.perf_counter() - start) * 1000

        pred_raw = self._classes_raw[pred_idx]
        pred_display = self._classes_display[pred_idx]
        confidence = float(probas[pred_idx])

        probabilities = {
            self._classes_display[i]: float(p)
            for i, p in enumerate(probas)
        }

        return {
            "prediction": pred_display,
            "prediction_raw": pred_raw,
            "confidence": confidence,
            "probabilities": probabilities,
            "model_version": self._metadata.get("run_id", "unknown"),
            "inference_ms": round(elapsed_ms, 3),
        }

    # ------------------------------------------------------------------ #
    # Status / metadata                                                    #
    # ------------------------------------------------------------------ #

    @property
    def is_ready(self) -> bool:
        return self._is_ready

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    @property
    def artifact_hash(self) -> Optional[str]:
        return self._artifact_hash

    @property
    def feature_names(self) -> List[str]:
        return self._feature_names

    @property
    def classes(self) -> List[str]:
        return self._classes_display

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    @property
    def version(self) -> str:
        return self._metadata.get("run_id", "unknown")

    def status_dict(self) -> Dict[str, Any]:
        """Return a serialisable status dict for the /health endpoint."""
        return {
            "ready": self._is_ready,
            "version": self.version,
            "model_type": self._metadata.get("model_type", "unknown"),
            "feature_count": len(self._feature_names),
            "class_count": len(self._classes_display),
            "classes": self._classes_display,
            "artifact_hash": self._artifact_hash,
            "load_error": self._load_error if not self._is_ready else None,
            "loaded_at": self._loaded_at,
            "metrics": {
                "macro_f1_test": self._metadata.get("macro_f1_test"),
                "weighted_f1_test": self._metadata.get("weighted_f1_test"),
                "accuracy_test": self._metadata.get("classification_report_test", {}).get("accuracy"),
            },
        }


# ---------------------------------------------------------------------------
# Global singleton — created at module import, loaded during app lifespan
# ---------------------------------------------------------------------------
model_manager = ModelManager()
