"""
Dashboard Aggregated Summary Metrics Endpoint.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.db.session import get_db
from backend.app.db.models import Alert, Flow, Sensor
from backend.app.schemas.dashboard import (
    DashboardSummaryResponse, SeverityDistribution,
    StatusDistribution, SensorStatusItem, ModelStatusInfo
)
from backend.app.services.inference import InferenceService

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Provides high-level dashboard metrics, distributions, sensor health, and model status."""
    total_flows = db.query(func.count(Flow.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    active_alerts = db.query(func.count(Alert.id)).filter(Alert.status.in_(["new", "investigating"])).scalar() or 0
    resolved_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "resolved").scalar() or 0

    # Severity distribution
    sev_counts = dict(
        db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    )
    severity_dist = SeverityDistribution(
        low=sev_counts.get("low", 0),
        medium=sev_counts.get("medium", 0),
        high=sev_counts.get("high", 0),
        critical=sev_counts.get("critical", 0)
    )

    # Status distribution
    stat_counts = dict(
        db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    )
    status_dist = StatusDistribution(
        new=stat_counts.get("new", 0),
        investigating=stat_counts.get("investigating", 0),
        true_positive=stat_counts.get("true_positive", 0),
        false_positive=stat_counts.get("false_positive", 0),
        resolved=stat_counts.get("resolved", 0)
    )

    # Sensor statuses
    now_utc = datetime.now(timezone.utc)
    stale_thresh = now_utc - timedelta(minutes=5)
    sensors_orm = db.query(Sensor).all()
    sensor_items: List[SensorStatusItem] = []
    active_sensors_count = 0

    for s in sensors_orm:
        flow_cnt = db.query(func.count(Flow.id)).filter(Flow.sensor_id == s.id).scalar() or 0
        # Aware datetime comparison
        last_seen = s.last_seen_at if s.last_seen_at.tzinfo else s.last_seen_at.replace(tzinfo=timezone.utc)
        is_online = s.enabled and (last_seen >= stale_thresh)
        if is_online:
            active_sensors_count += 1

        sensor_items.append(
            SensorStatusItem(
                sensor_id=s.id,
                name=s.name,
                enabled=s.enabled,
                last_seen_at=last_seen,
                is_online=is_online,
                flow_count=flow_cnt
            )
        )

    # Last flow ingestion time
    last_flow = db.query(Flow.received_at).order_by(Flow.received_at.desc()).first()
    last_ingestion_time = last_flow[0] if last_flow else None

    # Model info
    infer_service = InferenceService.get_instance()
    artifact = infer_service.model_artifact or {}
    metrics = artifact.get("metrics", {})

    model_info = ModelStatusInfo(
        model_version=infer_service.model_version,
        algorithm=artifact.get("algorithm", "HistGradientBoostingClassifier"),
        optimal_threshold=infer_service.optimal_threshold,
        test_accuracy=metrics.get("test_accuracy", 0.0),
        test_f1=metrics.get("test_f1", 0.0),
        test_precision=metrics.get("test_precision", 0.0),
        test_recall=metrics.get("test_recall", 0.0),
        false_positive_rate=metrics.get("false_positive_rate", 0.0),
        throughput_flows_per_sec=metrics.get("throughput_flows_per_sec", 0.0),
        status="active" if infer_service.model_loaded else "unloaded"
    )

    return DashboardSummaryResponse(
        total_flows=total_flows,
        total_alerts=total_alerts,
        active_alerts=active_alerts,
        resolved_alerts=resolved_alerts,
        severity_distribution=severity_dist,
        status_distribution=status_dist,
        active_sensors_count=active_sensors_count,
        sensors=sensor_items,
        model_info=model_info,
        last_ingestion_time=last_ingestion_time
    )

