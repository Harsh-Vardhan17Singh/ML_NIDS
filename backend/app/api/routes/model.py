"""
Active ML Model Metadata & Health API.
"""

from fastapi import APIRouter
from backend.app.services.inference import InferenceService

router = APIRouter(prefix="/api/v1/model", tags=["Model"])


@router.get("")
def get_active_model_metadata():
    """Retrieve metadata, parameters, and held-out performance metrics of the active model."""
    infer_service = InferenceService.get_instance()
    artifact = infer_service.model_artifact or {}

    return {
        "model_version": infer_service.model_version,
        "loaded": infer_service.model_loaded,
        "algorithm": artifact.get("algorithm", "HistGradientBoostingClassifier"),
        "optimal_threshold": infer_service.optimal_threshold,
        "feature_count": len(infer_service.feature_names),
        "features": infer_service.feature_names,
        "metrics": artifact.get("metrics", {}),
        "per_category_performance": artifact.get("per_category_performance", {}),
        "created_at": artifact.get("created_at")
    }

