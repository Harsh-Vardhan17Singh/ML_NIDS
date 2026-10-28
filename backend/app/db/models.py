"""
SQLAlchemy ORM Entities for SentinelNIDS persistence layer.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Text, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from backend.app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst", nullable=False)  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Sensor(Base):
    __tablename__ = "sensors"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    token_hash = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow)
    schema_version = Column(String(16), default="1.0")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    flows = relationship("Flow", back_populates="sensor", cascade="all, delete-orphan")


class Flow(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, index=True)
    sensor_id = Column(String(64), ForeignKey("sensors.id"), nullable=False, index=True)
    event_id = Column(String(128), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    received_at = Column(DateTime(timezone=True), default=utcnow)
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(16), nullable=False)
    duration_ms = Column(Float, default=0.0)
    packets_out = Column(Integer, default=0)
    packets_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    bytes_in = Column(Integer, default=0)
    parse_warnings = Column(Text, default="[]")

    __table_args__ = (
        UniqueConstraint("sensor_id", "event_id", name="uq_sensor_event"),
        Index("ix_flow_sensor_observed", "sensor_id", "observed_at"),
    )

    sensor = relationship("Sensor", back_populates="flows")
    prediction = relationship("Prediction", back_populates="flow", uselist=False, cascade="all, delete-orphan")


class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(Integer, ForeignKey("flows.id"), unique=True, nullable=False)
    model_version = Column(String(64), nullable=False)
    score = Column(Float, nullable=False)
    decision = Column(String(32), nullable=False)  # normal, review
    latency_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    flow = relationship("Flow", back_populates="prediction")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, default=lambda: f"ALT-{uuid.uuid4().hex[:12].upper()}")
    dedup_key = Column(String(255), index=True, nullable=False)
    severity = Column(String(16), nullable=False, index=True)  # low, medium, high, critical
    status = Column(String(32), default="new", index=True)  # new, investigating, true_positive, false_positive, resolved
    decision = Column(String(32), default="review")
    summary = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    matched_rules = Column(Text, default="[]")
    model_score = Column(Float, nullable=True)
    model_version = Column(String(64), nullable=True)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow)
    event_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    feedbacks = relationship("AnalystFeedback", back_populates="alert", cascade="all, delete-orphan")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), nullable=False, index=True)
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=False, index=True)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), nullable=False, index=True)
    analyst_email = Column(String(255), nullable=False)
    disposition = Column(String(32), nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    alert = relationship("Alert", back_populates="feedbacks")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(255), nullable=False)
    action = Column(String(64), nullable=False)
    resource = Column(String(128), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow)

