"""
Pydantic schemas for Alert retrieval, filtering, and review workflows.
"""

from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


class AlertItem(BaseModel):
    alert_id: str
    dedup_key: str
    severity: str
    status: str
    decision: str
    summary: str
    reason: str
    matched_rules: List[str] = Field(default_factory=list)
    model_score: Optional[float] = None
    model_version: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AlertItem]


class FeedbackItem(BaseModel):
    id: int
    analyst_email: str
    disposition: str
    note: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FlowEvidence(BaseModel):
    id: int
    sensor_id: str
    event_id: str
    observed_at: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    duration_ms: float
    packets_out: int
    packets_in: int
    bytes_out: int
    bytes_in: int

    class Config:
        from_attributes = True


class AlertDetailResponse(BaseModel):
    alert_id: str
    dedup_key: str
    severity: str
    status: str
    decision: str
    summary: str
    reason: str
    matched_rules: List[str] = Field(default_factory=list)
    model_score: Optional[float] = None
    model_version: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    created_at: datetime
    updated_at: datetime
    feedbacks: List[FeedbackItem] = Field(default_factory=list)
    sample_flows: List[FlowEvidence] = Field(default_factory=list)

    class Config:
        from_attributes = True


class AlertUpdateRequest(BaseModel):
    status: str = Field(..., description="Target status: new, investigating, true_positive, false_positive, resolved")
    note: Optional[str] = Field(default=None, description="Analyst review notes / disposition explanation")
    analyst_email: Optional[str] = Field(default="analyst@sentinelnids.local")

