"""
Flow Ingestion Service.
Validates authenticated batches, enforces idempotency, persists flows/predictions,
invokes detection engine, and emits alert records.
"""

from datetime import datetime, timezone
import json
import logging
from typing import List, Tuple
from sqlalchemy.orm import Session

from backend.app.db.models import Sensor, Flow, Prediction
from backend.app.schemas.ingest import IngestBatchRequest, IngestBatchResponse, IngestErrorDetail
from backend.app.services.rules import DeterministicRuleEngine
from backend.app.services.inference import InferenceService
from backend.app.services.alert_manager import AlertManager
from sensor.schemas import CanonicalFlow

logger = logging.getLogger("sentinelnids.services.ingestion")


class IngestionService:

    def __init__(self):
        self.rule_engine = DeterministicRuleEngine()
        self.inference_service = InferenceService.get_instance()

    def process_batch(
        self,
        db: Session,
        batch: IngestBatchRequest
    ) -> IngestBatchResponse:
        sensor_id = batch.sensor_id

        # Update or register sensor last_seen_at
        sensor = db.query(Sensor).filter(Sensor.id == sensor_id).first()
        now_utc = datetime.now(timezone.utc)
        if not sensor:
            sensor = Sensor(
                id=sensor_id,
                name=f"Sensor {sensor_id}",
                token_hash="default_hash",
                enabled=True,
                last_seen_at=now_utc
            )
            db.add(sensor)
        else:
            sensor.last_seen_at = now_utc

        accepted = 0
        rejected = 0
        duplicates = 0
        alerts_generated = 0
        errors: List[IngestErrorDetail] = []

        # Find existing event_ids in this sensor to enforce idempotency
        incoming_event_ids = [f.event_id for f in batch.flows]
        existing_event_ids = set(
            row[0] for row in db.query(Flow.event_id)
            .filter(Flow.sensor_id == sensor_id, Flow.event_id.in_(incoming_event_ids))
            .all()
        )

        for idx, flow_schema in enumerate(batch.flows):
            # Check duplicate
            if flow_schema.event_id in existing_event_ids:
                duplicates += 1
                continue

            try:
                # 1. Create Flow record
                flow_orm = Flow(
                    sensor_id=sensor_id,
                    event_id=flow_schema.event_id,
                    observed_at=flow_schema.observed_at,
                    received_at=now_utc,
                    src_ip=flow_schema.src_ip,
                    dst_ip=flow_schema.dst_ip,
                    src_port=flow_schema.src_port,
                    dst_port=flow_schema.dst_port,
                    protocol=flow_schema.protocol,
                    duration_ms=flow_schema.duration_ms,
                    packets_out=flow_schema.packets_out,
                    packets_in=flow_schema.packets_in,
                    bytes_out=flow_schema.bytes_out,
                    bytes_in=flow_schema.bytes_in,
                    parse_warnings=json.dumps(flow_schema.parse_warnings)
                )
                db.add(flow_orm)
                db.flush()  # assign flow_orm.id

                # 2. ML Inference
                score, decision, latency_ms = self.inference_service.predict_flow(flow_schema)
                pred_orm = Prediction(
                    flow_id=flow_orm.id,
                    model_version=self.inference_service.model_version,
                    score=score,
                    decision=decision,
                    latency_ms=latency_ms
                )
                db.add(pred_orm)

                # 3. Deterministic Rules
                rule_hits = self.rule_engine.evaluate_flow(flow_schema)

                # 4. Alert Processing
                alert = AlertManager.process_detection(
                    db=db,
                    flow=flow_orm,
                    matched_rules=rule_hits,
                    model_score=score,
                    model_decision=decision,
                    model_version=self.inference_service.model_version
                )
                if alert is not None:
                    alerts_generated += 1

                accepted += 1
                existing_event_ids.add(flow_schema.event_id)

            except Exception as e:
                rejected += 1
                errors.append(
                    IngestErrorDetail(
                        index=idx,
                        event_id=flow_schema.event_id,
                        error_code="PERSISTENCE_FAILED",
                        message=str(e)
                    )
                )

        db.commit()

        return IngestBatchResponse(
            sensor_id=sensor_id,
            total_received=len(batch.flows),
            accepted=accepted,
            rejected=rejected,
            duplicates=duplicates,
            alerts_generated=alerts_generated,
            errors=errors
        )

