"""
Sensors Listing and Registration API.
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta

from backend.app.db.session import get_db
from backend.app.db.models import Sensor, Flow
from backend.app.schemas.dashboard import SensorStatusItem

router = APIRouter(prefix="/api/v1/sensors", tags=["Sensors"])


@router.get("", response_model=List[SensorStatusItem])
def list_sensors(db: Session = Depends(get_db)):
    """List all registered sensors and their current connectivity status."""
    sensors_orm = db.query(Sensor).all()
    now_utc = datetime.now(timezone.utc)
    stale_thresh = now_utc - timedelta(minutes=5)
    items: List[SensorStatusItem] = []

    for s in sensors_orm:
        flow_cnt = db.query(func.count(Flow.id)).filter(Flow.sensor_id == s.id).scalar() or 0
        last_seen = s.last_seen_at if s.last_seen_at.tzinfo else s.last_seen_at.replace(tzinfo=timezone.utc)
        items.append(
            SensorStatusItem(
                sensor_id=s.id,
                name=s.name,
                enabled=s.enabled,
                last_seen_at=last_seen,
                is_online=s.enabled and (last_seen >= stale_thresh),
                flow_count=flow_cnt
            )
        )
    return items

