"""
Pydantic contracts for Canonical Flow Schema v1.0 and parsing summaries.
"""

from __future__ import annotations
import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, field_validator, model_validator


VALID_PROTOCOLS = {"tcp", "udp", "icmp", "other"}
SENSOR_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


class CanonicalFlow(BaseModel):
    """
    Canonical network flow event contract (Schema version 1.0).
    Guarantees consistent data representation across ingestion, rules,
    ML feature pipelines, and PostgreSQL persistence.
    """
    schema_version: str = Field(default="1.0", description="Canonical schema version")
    event_id: str = Field(..., min_length=1, max_length=128, description="Unique idempotency identifier")
    sensor_id: str = Field(..., min_length=1, max_length=64, description="Sensor/collector identifier")
    observed_at: datetime = Field(..., description="Flow observation timestamp (UTC)")
    received_at: Optional[datetime] = Field(default=None, description="Ingestion timestamp at backend (UTC)")
    src_ip: str = Field(..., description="Source IPv4 or IPv6 address")
    dst_ip: str = Field(..., description="Destination IPv4 or IPv6 address")
    src_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Source port (0-65535)")
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Destination port (0-65535)")
    protocol: str = Field(..., description="Normalized transport protocol (tcp, udp, icmp, other)")
    duration_ms: float = Field(default=0.0, ge=0.0, description="Flow duration in milliseconds")
    packets_out: int = Field(default=0, ge=0, description="Packets sent from source to destination")
    packets_in: int = Field(default=0, ge=0, description="Packets sent from destination to source")
    bytes_out: int = Field(default=0, ge=0, description="Bytes sent from source to destination")
    bytes_in: int = Field(default=0, ge=0, description="Bytes sent from destination to source")
    parse_warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings recorded during normalization")

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"Unsupported schema_version '{v}'. Expected '1.0'.")
        return v

    @field_validator("sensor_id")
    @classmethod
    def validate_sensor_id(cls, v: str) -> str:
        if not SENSOR_ID_PATTERN.match(v):
            raise ValueError(f"Invalid sensor_id '{v}'. Must be 1-64 alphanumeric, dash, period, or underscore chars.")
        return v

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v}'")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in VALID_PROTOCOLS:
            # Map known protocol aliases
            if cleaned in {"ipv6-icmp", "icmp6"}:
                return "icmp"
            return "other"
        return cleaned

    @field_validator("observed_at", "received_at")
    @classmethod
    def ensure_utc_timezone(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return None
        if v.tzinfo is None:
            # Assume UTC if naive, but enforce UTC timezone
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_flow_coherence(self) -> CanonicalFlow:
        # Check ICMP port semantics
        if self.protocol == "icmp":
            # For ICMP, ports are optional or null
            pass
        # Check packet and byte coherence
        if self.packets_out == 0 and self.bytes_out > 0:
            self.parse_warnings.append("bytes_out > 0 with 0 packets_out; adjusted packets_out to 1")
            self.packets_out = 1
        if self.packets_in == 0 and self.bytes_in > 0:
            self.parse_warnings.append("bytes_in > 0 with 0 packets_in; adjusted packets_in to 1")
            self.packets_in = 1
        return self


class RawFlowRecord(BaseModel):
    """Loose raw record container prior to normalization."""
    raw_data: Dict[str, Any]
    source_type: str = "unknown"
    record_index: Optional[int] = None


class ParsingErrorDetail(BaseModel):
    """Structured error detail for rejected telemetry records."""
    index: int
    error_code: str
    message: str
    raw_preview: Optional[str] = None


class ParsingSummary(BaseModel):
    """Metrics summary of a parsing or batch ingestion run."""
    total_records: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    duplicate_records: int = 0
    errors: List[ParsingErrorDetail] = Field(default_factory=list)

    @property
    def acceptance_rate(self) -> float:
        if self.total_records == 0:
            return 1.0
        return self.accepted_records / self.total_records
