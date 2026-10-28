"""
Pydantic schemas for Dashboard summary, metrics, and sensor statuses.
"""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SeverityDistribution(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class StatusDistribution(BaseModel):
    new: int = 0
    investigating: int = 0
    true_positive: int = 0
    false_positive: int = 0
    resolved: int = 0


class SensorStatusItem(BaseModel):
    sensor_id: str
    name: str
    enabled: bool
    last_seen_at: datetime
    is_online: bool
    flow_count: int


class ModelStatusInfo(BaseModel):
    model_version: str
    algorithm: str
    optimal_threshold: float
    test_accuracy: float
    test_f1: float
    test_precision: float
    test_recall: float
    false_positive_rate: float
    throughput_flows_per_sec: float
    status: str = "active"


class DashboardSummaryResponse(BaseModel):
    total_flows: int
    total_alerts: int
    active_alerts: int
    resolved_alerts: int
    severity_distribution: SeverityDistribution
    status_distribution: StatusDistribution
    active_sensors_count: int
    sensors: List[SensorStatusItem]
    model_info: ModelStatusInfo
    last_ingestion_time: Optional[datetime] = None

