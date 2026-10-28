"""
Comprehensive Test Suite for Phase 3:
Backend Persistence, Rule Engine, ML Inference, Ingestion, and Alert Lifecycle.
"""

import unittest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.session import Base
from backend.app.db.models import Sensor, Flow, Prediction, Alert, AlertEvent, AnalystFeedback, AuditLog
from backend.app.services.rules import DeterministicRuleEngine, DetectionRuleResult
from backend.app.services.inference import InferenceService
from backend.app.services.alert_manager import AlertManager
from backend.app.services.ingestion import IngestionService
from backend.app.schemas.ingest import IngestBatchRequest
from backend.app.schemas.alerts import AlertUpdateRequest
from backend.app.api.routes import health, ingest, alerts, dashboard, sensors, model
from sensor.schemas import CanonicalFlow


class TestBackendAndDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database for test isolation
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

        # Load inference service
        cls.infer_service = InferenceService.get_instance()

    def setUp(self):
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_database_models_creation(self):
        sensor = Sensor(
            id="test-sensor-01",
            name="Test Sensor",
            token_hash="hash123",
            enabled=True
        )
        self.db.add(sensor)
        self.db.commit()

        queried = self.db.query(Sensor).filter(Sensor.id == "test-sensor-01").first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.name, "Test Sensor")

    def test_deterministic_rules_port_scan(self):
        rule_engine = DeterministicRuleEngine()
        # Reset state
        rule_engine._history.clear()

        # Generate 25 flows from same src_ip to distinct destination ports within 10 seconds
        src_ip = "10.100.1.5"
        base_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
        
        results = []
        for port in range(1, 26):
            flow = CanonicalFlow(
                schema_version="1.0",
                event_id=str(uuid.uuid4()),
                sensor_id="test-sensor-01",
                observed_at=base_time,
                src_ip=src_ip,
                dst_ip="192.168.1.10",
                src_port=50000 + port,
                dst_port=port,
                protocol="tcp",
                duration_ms=10.0,
                packets_out=1,
                packets_in=0,
                bytes_out=60,
                bytes_in=0
            )
            hits = rule_engine.evaluate_flow(flow)
            if hits:
                results.extend(hits)

        # Port scan should trigger once threshold (20 distinct ports) is exceeded
        rule_ids = [r.rule_id for r in results]
        self.assertIn("PORT_SCAN_DETECTED", rule_ids)

    def test_deterministic_rules_sensitive_port_probe(self):
        rule_engine = DeterministicRuleEngine()
        rule_engine._history.clear()

        # Inbound probe to SSH (port 22)
        flow = CanonicalFlow(
            schema_version="1.0",
            event_id=str(uuid.uuid4()),
            sensor_id="test-sensor-01",
            observed_at=datetime.now(timezone.utc),
            src_ip="203.0.113.5",
            dst_ip="192.168.1.50",
            src_port=41234,
            dst_port=22,
            protocol="tcp",
            duration_ms=5.0,
            packets_out=1,
            packets_in=0,
            bytes_out=64,
            bytes_in=0
        )
        hits = rule_engine.evaluate_flow(flow)
        rule_ids = [r.rule_id for r in hits]
        self.assertIn("SENSITIVE_PORT_PROBE", rule_ids)

    def test_ml_inference_service(self):
        self.assertTrue(self.infer_service.model_loaded, "Trained model sentinel_model_v1.joblib should be loaded")
        
        # Test normal flow
        flow_benign = CanonicalFlow(
            schema_version="1.0",
            event_id="test-benign-01",
            sensor_id="test-sensor-01",
            observed_at=datetime.now(timezone.utc),
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="udp",
            duration_ms=15.0,
            packets_out=1,
            packets_in=1,
            bytes_out=68,
            bytes_in=124
        )
        score, decision, latency = self.infer_service.predict_flow(flow_benign)
        self.assertIsInstance(score, float)
        self.assertIn(decision, ["normal", "review"])
        self.assertGreater(latency, 0.0)

    def test_ingestion_and_idempotency(self):
        ingestion_service = IngestionService()

        # Prepare batch with 2 unique flows + 1 duplicate
        e1 = str(uuid.uuid4())
        e2 = str(uuid.uuid4())

        f1 = CanonicalFlow(
            schema_version="1.0",
            event_id=e1,
            sensor_id="test-sensor-01",
            observed_at=datetime.now(timezone.utc),
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",
            src_port=50123,
            dst_port=80,
            protocol="tcp",
            duration_ms=100.0,
            packets_out=5,
            packets_in=5,
            bytes_out=400,
            bytes_in=1200
        )
        f2 = CanonicalFlow(
            schema_version="1.0",
            event_id=e2,
            sensor_id="test-sensor-01",
            observed_at=datetime.now(timezone.utc),
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",
            src_port=50124,
            dst_port=80,
            protocol="tcp",
            duration_ms=100.0,
            packets_out=5,
            packets_in=5,
            bytes_out=400,
            bytes_in=1200
        )

        batch = IngestBatchRequest(sensor_id="test-sensor-01", flows=[f1, f2])
        resp1 = ingestion_service.process_batch(self.db, batch)

        self.assertEqual(resp1.accepted, 2)
        self.assertEqual(resp1.duplicates, 0)

        # Ingest same batch again -> must be recognized as duplicate without error
        resp2 = ingestion_service.process_batch(self.db, batch)
        self.assertEqual(resp2.accepted, 0)
        self.assertEqual(resp2.duplicates, 2)

    def test_alert_lifecycle_and_review(self):
        # Create flow causing sensitive port alert
        flow = Flow(
            sensor_id="test-sensor-01",
            event_id="alert-trigger-flow-01",
            observed_at=datetime.now(timezone.utc),
            src_ip="198.51.100.77",
            dst_ip="192.168.1.20",
            src_port=44123,
            dst_port=22,
            protocol="tcp"
        )
        self.db.add(flow)
        self.db.commit()

        # Process detection via AlertManager
        alert = AlertManager.process_detection(
            db=self.db,
            flow=flow,
            matched_rules=[
                DetectionRuleResult(rule_id="SENSITIVE_PORT_PROBE", severity="low", message="Probing port 22")
            ],
            model_score=0.92,
            model_decision="review",
            model_version="flow-v1.0.0"
        )
        self.db.commit()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.status, "new")

        # Update alert review state
        updated = AlertManager.update_alert_status(
            db=self.db,
            alert=alert,
            new_status="true_positive",
            analyst_email="lead_analyst@sentinelnids.local",
            note="Confirmed unauthorized external scan on port 22."
        )
        self.assertEqual(updated.status, "true_positive")

        # Verify audit log and analyst feedback
        fb = self.db.query(AnalystFeedback).filter(AnalystFeedback.alert_id == alert.alert_id).first()
        self.assertIsNotNone(fb)
        self.assertEqual(fb.disposition, "true_positive")

        audit = self.db.query(AuditLog).filter(AuditLog.resource == f"alert:{alert.alert_id}").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.action, "UPDATE_ALERT_STATUS")

    def test_dashboard_and_health_routes(self):
        # Health probes
        live = health.liveness()
        self.assertEqual(live["status"], "alive")

        # Model route
        model_meta = model.get_active_model_metadata()
        self.assertTrue(model_meta["loaded"])
        self.assertEqual(model_meta["model_version"], "flow-v1.0.0")

        # Sensors route
        sensor_list = sensors.list_sensors(self.db)
        self.assertIsInstance(sensor_list, list)

        # Dashboard summary
        summary = dashboard.get_dashboard_summary(self.db)
        self.assertGreaterEqual(summary.total_flows, 0)
        self.assertGreaterEqual(summary.total_alerts, 0)


if __name__ == "__main__":
    unittest.main()
