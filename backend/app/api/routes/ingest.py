"""
Sensor Telemetry Flow Ingestion Endpoint.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.core.config import settings
from backend.app.schemas.ingest import IngestBatchRequest, IngestBatchResponse
from backend.app.services.ingestion import IngestionService

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])
ingestion_service = IngestionService()


def verify_sensor_token(x_sensor_token: str = Header(..., alias="X-Sensor-Token")):
    """Validates scoped sensor API credentials."""
    if x_sensor_token != settings.INGESTION_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized sensor token"
        )
    return x_sensor_token


@router.post("/flows", response_model=IngestBatchResponse, status_code=status.HTTP_200_OK)
def ingest_flows(
    batch: IngestBatchRequest,
    db: Session = Depends(get_db),
    _token: str = Depends(verify_sensor_token)
):
    """
    Ingest a batch of normalized CanonicalFlow events from an authorized sensor.
    Evaluates ML detection, deterministic rules, persists flow records,
    and returns an explicit batch acceptance status.
    """
    if len(batch.flows) > settings.MAX_INGEST_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch size {len(batch.flows)} exceeds limit of {settings.MAX_INGEST_BATCH_SIZE}"
        )

    response = ingestion_service.process_batch(db=db, batch=batch)
    return response

