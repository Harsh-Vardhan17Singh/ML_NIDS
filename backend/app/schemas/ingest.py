"""
Pydantic API contracts for telemetry flow ingestion.
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from sensor.schemas import CanonicalFlow


class IngestBatchRequest(BaseModel):
    """Batch payload sent by sensor or forwarder."""
    sensor_id: str = Field(..., min_length=1, max_length=64)
    flows: List[CanonicalFlow] = Field(..., min_length=1, max_length=1000)


class IngestErrorDetail(BaseModel):
    index: int
    event_id: Optional[str] = None
    error_code: str
    message: str


class IngestBatchResponse(BaseModel):
    sensor_id: str
    total_received: int
    accepted: int
    rejected: int
    duplicates: int
    alerts_generated: int
    errors: List[IngestErrorDetail] = Field(default_factory=list)

