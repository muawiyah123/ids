"""
backend/app/api/models_api.py — ML model information endpoints.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.ml.model_manager import model_manager
from app.models.user import User
from app.security.dependencies import get_current_active_user

router = APIRouter(prefix="/models", tags=["Models"])


@router.get("/current")
async def get_current_model(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """Return current model status and metadata."""
    return model_manager.status_dict()


@router.get("/current/features")
async def get_model_features(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """Return the expected feature list in order."""
    if not model_manager.is_ready:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {
        "feature_count": len(model_manager.feature_names),
        "features": model_manager.feature_names,
    }


@router.get("/current/importance")
async def get_feature_importance(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Return global feature importance from the XGBoost model.
    Only available if the underlying model supports feature_importances_.
    """
    if not model_manager.is_ready:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        # Access the XGBoost model inside the sklearn pipeline
        xgb_model = model_manager._pipeline.named_steps.get("model")
        if xgb_model is None or not hasattr(xgb_model, "feature_importances_"):
            return {
                "available": False,
                "message": "Feature importance not available for this model type",
            }

        importances = xgb_model.feature_importances_
        features = model_manager.feature_names

        ranked = sorted(
            [{"feature": f, "importance": float(i), "rank": 0}
             for f, i in zip(features, importances)],
            key=lambda x: x["importance"],
            reverse=True,
        )
        for idx, item in enumerate(ranked):
            item["rank"] = idx + 1

        return {"available": True, "features": ranked}
    except Exception as e:
        return {"available": False, "message": str(e)}
