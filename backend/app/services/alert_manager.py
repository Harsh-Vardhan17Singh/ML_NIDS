"""
Alert Lifecycle and Deduplication Manager.
Aggregates security findings into deduplicated, explainable Alert records,
and manages analyst review transitions and audit trails.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from backend.app.db.models import Alert, AlertEvent, AnalystFeedback, AuditLog, Flow
from backend.app.services.rules import DetectionRuleResult

logger = logging.getLogger("sentinelnids.services.alert_manager")


class AlertManager:

    @staticmethod
    def process_detection(
        db: Session,
        flow: Flow,
        matched_rules: List[DetectionRuleResult],
        model_score: float,
        model_decision: str,
        model_version: str
    ) -> Optional[Alert]:
        """
        Determines if an Alert should be created or updated for a flow.
        Applies deduplication key based on attack type/rule and endpoints.
        """
        is_rule_alert = len(matched_rules) > 0
        is_model_alert = model_decision == "review"

        if not is_rule_alert and not is_model_alert:
            return None  # Benign flow, no alert

        # Compute severity
        severity = "low"
        rule_ids = [r.rule_id for r in matched_rules]
        reasons = [r.message for r in matched_rules]

        if any(r.severity == "critical" for r in matched_rules):
            severity = "critical"
        elif any(r.severity == "high" for r in matched_rules):
            severity = "high"
        elif any(r.severity == "medium" for r in matched_rules) or model_score >= 0.85:
            severity = "medium"

        if is_model_alert:
            reasons.append(f"ML Model ({model_version}) scored flow {model_score:.3f} >= threshold")

        # Stable deduplication key: source IP + primary reason/rule ID
        primary_indicator = rule_ids[0] if rule_ids else "ML_ANOMALY"
        dedup_key = f"{flow.src_ip}_{primary_indicator}_{flow.dst_port or 0}"

        # Check for existing alert in deduplication window (last 10 minutes)
        window_start = flow.observed_at - timedelta(minutes=10)
        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.dedup_key == dedup_key,
                Alert.status.in_(["new", "investigating"]),
                Alert.last_seen_at >= window_start
            )
            .order_by(Alert.last_seen_at.desc())
            .first()
        )

        if existing_alert:
            existing_alert.event_count += 1
            existing_alert.last_seen_at = flow.observed_at
            if model_score > (existing_alert.model_score or 0.0):
                existing_alert.model_score = model_score

            # Link event
            db.add(AlertEvent(alert_id=existing_alert.alert_id, flow_id=flow.id))
            return existing_alert

        # Create new Alert
        summary = (
            f"Suspicious activity from {flow.src_ip} targeting port {flow.dst_port}"
            if flow.dst_port
            else f"Suspicious activity from {flow.src_ip}"
        )
        new_alert = Alert(
            dedup_key=dedup_key,
            severity=severity,
            status="new",
            decision="review",
            summary=summary,
            reason="\n".join(reasons),
            matched_rules=json.dumps(rule_ids),
            model_score=model_score if is_model_alert else None,
            model_version=model_version if is_model_alert else None,
            first_seen_at=flow.observed_at,
            last_seen_at=flow.observed_at,
            event_count=1
        )
        db.add(new_alert)
        db.flush()

        db.add(AlertEvent(alert_id=new_alert.alert_id, flow_id=flow.id))
        return new_alert

    @staticmethod
    def update_alert_status(
        db: Session,
        alert: Alert,
        new_status: str,
        analyst_email: str,
        note: Optional[str] = None
    ) -> Alert:
        """Transitions alert review status and records audit & feedback records."""
        valid_statuses = {"new", "investigating", "true_positive", "false_positive", "resolved"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid alert status '{new_status}'. Allowed: {valid_statuses}")

        old_status = alert.status
        alert.status = new_status
        alert.updated_at = datetime.now(timezone.utc)

        # Record feedback
        feedback = AnalystFeedback(
            alert_id=alert.alert_id,
            analyst_email=analyst_email,
            disposition=new_status,
            note=note
        )
        db.add(feedback)

        # Record audit log
        audit = AuditLog(
            actor=analyst_email,
            action="UPDATE_ALERT_STATUS",
            resource=f"alert:{alert.alert_id}",
            details=f"Status changed from {old_status} to {new_status}. Note: {note or 'None'}"
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)
        return alert

