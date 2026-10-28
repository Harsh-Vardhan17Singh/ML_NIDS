"""
Health & Readiness Check Endpoints.
"""

from fastapi import APIRouter, Depends, status, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.app.db.session import get_db
from backend.app.services.inference import InferenceService

router = APIRouter(tags=["Health"])


@router.get("/health/live", status_code=status.HTTP_200_OK)
def liveness():
    """Returns 200 if backend web process is running."""
    return {"status": "alive", "service": "sentinelnids-backend"}


@router.get("/health/ready")
def readiness(response: Response, db: Session = Depends(get_db)):
    """Checks database connectivity and ML model availability."""
    checks = {
        "database": False,
        "ml_inference": False
    }

    # DB probe
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        checks["database_error"] = str(e)

    # ML probe
    infer_service = InferenceService.get_instance()
    checks["ml_inference"] = infer_service.model_loaded
    checks["model_version"] = infer_service.model_version

    all_ready = checks["database"]
    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "checks": checks}

    return {"status": "ready", "checks": checks}

