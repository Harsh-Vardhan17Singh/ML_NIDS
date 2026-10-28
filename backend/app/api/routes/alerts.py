"""
Alert Management, Retrieval, and Review Endpoints.
"""

import json
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.db.session import get_db
from backend.app.db.models import Alert, AlertEvent, Flow, AnalystFeedback
from backend.app.schemas.alerts import (
    AlertListResponse, AlertItem, AlertDetailResponse,
    AlertUpdateRequest, FlowEvidence, FeedbackItem
)
from backend.app.services.alert_manager import AlertManager

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    sensor_id: Optional[str] = Query(default=None)
):
    """List paginated alerts with filtering by severity, status, or sensor."""
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if status:
        query = query.filter(Alert.status == status.lower())
    if sensor_id:
        # Filter alerts that contain events from this sensor
        query = query.join(AlertEvent, Alert.alert_id == AlertEvent.alert_id)\
                     .join(Flow, AlertEvent.flow_id == Flow.id)\
                     .filter(Flow.sensor_id == sensor_id)

    total = query.count()
    offset = (page - 1) * page_size
    alerts_orm = query.order_by(desc(Alert.last_seen_at)).offset(offset).limit(page_size).all()

    items: List[AlertItem] = []
    for a in alerts_orm:
        rules_list = json.loads(a.matched_rules) if a.matched_rules else []
        items.append(
            AlertItem(
                alert_id=a.alert_id,
                dedup_key=a.dedup_key,
                severity=a.severity,
                status=a.status,
                decision=a.decision,
                summary=a.summary,
                reason=a.reason,
                matched_rules=rules_list,
                model_score=a.model_score,
                model_version=a.model_version,
                first_seen_at=a.first_seen_at,
                last_seen_at=a.last_seen_at,
                event_count=a.event_count
            )
        )

    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items
    )


@router.get("/{alert_id}", response_model=AlertDetailResponse)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """Retrieve full alert detail including related flow evidence and review history."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    # Fetch associated flow evidence
    flow_ids = [r[0] for r in db.query(AlertEvent.flow_id).filter(AlertEvent.alert_id == alert_id).limit(25).all()]
    flows = db.query(Flow).filter(Flow.id.in_(flow_ids)).all() if flow_ids else []

    evidence: List[FlowEvidence] = [
        FlowEvidence(
            id=f.id,
            sensor_id=f.sensor_id,
            event_id=f.event_id,
            observed_at=f.observed_at,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            src_port=f.src_port,
            dst_port=f.dst_port,
            protocol=f.protocol,
            duration_ms=f.duration_ms,
            packets_out=f.packets_out,
            packets_in=f.packets_in,
            bytes_out=f.bytes_out,
            bytes_in=f.bytes_in
        )
        for f in flows
    ]

    # Fetch feedback history
    feedbacks_orm = db.query(AnalystFeedback).filter(AnalystFeedback.alert_id == alert_id).all()
    feedbacks = [
        FeedbackItem(
            id=fb.id,
            analyst_email=fb.analyst_email,
            disposition=fb.disposition,
            note=fb.note,
            created_at=fb.created_at
        )
        for fb in feedbacks_orm
    ]

    rules_list = json.loads(alert.matched_rules) if alert.matched_rules else []

    return AlertDetailResponse(
        alert_id=alert.alert_id,
        dedup_key=alert.dedup_key,
        severity=alert.severity,
        status=alert.status,
        decision=alert.decision,
        summary=alert.summary,
        reason=alert.reason,
        matched_rules=rules_list,
        model_score=alert.model_score,
        model_version=alert.model_version,
        first_seen_at=alert.first_seen_at,
        last_seen_at=alert.last_seen_at,
        event_count=alert.event_count,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        feedbacks=feedbacks,
        sample_flows=evidence
    )


@router.patch("/{alert_id}", response_model=AlertDetailResponse)
def update_alert(
    alert_id: str,
    update_data: AlertUpdateRequest,
    db: Session = Depends(get_db)
):
    """Update alert review status and record disposition feedback with audit logging."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    try:
        updated = AlertManager.update_alert_status(
            db=db,
            alert=alert,
            new_status=update_data.status,
            analyst_email=update_data.analyst_email or "analyst@sentinelnids.local",
            note=update_data.note
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return get_alert_detail(alert_id=alert_id, db=db)

