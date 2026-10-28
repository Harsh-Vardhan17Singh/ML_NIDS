"""
Normalization pipeline for mapping source telemetry records (Zeek conn.log,
NetFlow/IPFIX, raw JSON/CSV) to CanonicalFlow v1.0.
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List
from .schemas import CanonicalFlow


def _clean_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    if s in {"-", "(empty)", "null", "None", ""}:
        return None
    return s


def _parse_timestamp(val: Any) -> datetime:
    """Parse various timestamp representations into a timezone-aware UTC datetime."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    if isinstance(val, (int, float)):
        # Epoch timestamp
        return datetime.fromtimestamp(float(val), tz=timezone.utc)

    if isinstance(val, str):
        cleaned = val.strip()
        # Check if numeric epoch string
        try:
            epoch = float(cleaned)
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        except ValueError:
            pass
        # Handle ISO-8601 string
        # Replace trailing 'Z' if needed for fromisoformat compatibility in older python
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    raise ValueError(f"Cannot parse timestamp from value: {val!r}")


def _parse_port(val: Any) -> Optional[int]:
    cleaned = _clean_str(val)
    if cleaned is None:
        return None
    try:
        p = int(float(cleaned))
        if 0 <= p <= 65535:
            return p
        raise ValueError(f"Port number {p} out of valid range (0-65535)")
    except ValueError as e:
        raise ValueError(f"Invalid port: {val!r}") from e


def _parse_non_negative_int(val: Any, default: int = 0) -> int:
    cleaned = _clean_str(val)
    if cleaned is None:
        return default
    try:
        num = int(float(cleaned))
        return max(0, num)
    except (ValueError, TypeError):
        return default


def _parse_duration_ms(val: Any, is_seconds: bool = False) -> float:
    cleaned = _clean_str(val)
    if cleaned is None:
        return 0.0
    try:
        num = float(cleaned)
        if num < 0.0:
            return 0.0
        return num * 1000.0 if is_seconds else num
    except (ValueError, TypeError):
        return 0.0


def normalize_zeek_record(row: Dict[str, Any], default_sensor_id: str = "lab-sensor-01") -> CanonicalFlow:
    """
    Normalizes a Zeek conn.log dictionary (TSV or JSON) to a CanonicalFlow.
    """
    # 1. Event ID / UID
    uid = _clean_str(row.get("uid"))
    event_id = uid if uid else str(uuid.uuid4())

    # 2. Timestamp
    ts_raw = row.get("ts")
    if ts_raw is None:
        raise ValueError("Zeek record missing required 'ts' timestamp field")
    observed_at = _parse_timestamp(ts_raw)

    # 3. IP endpoints
    src_ip = _clean_str(row.get("id.orig_h") or row.get("orig_h") or row.get("id_orig_h"))
    dst_ip = _clean_str(row.get("id.resp_h") or row.get("resp_h") or row.get("id_resp_h"))
    if not src_ip or not dst_ip:
        raise ValueError(f"Zeek record missing IP endpoint(s): src_ip={src_ip!r}, dst_ip={dst_ip!r}")

    # 4. Ports
    src_port = _parse_port(row.get("id.orig_p") or row.get("orig_p") or row.get("id_orig_p"))
    dst_port = _parse_port(row.get("id.resp_p") or row.get("resp_p") or row.get("id_resp_p"))

    # 5. Protocol
    proto = _clean_str(row.get("proto")) or "other"

    # 6. Duration (Zeek conn.log reports duration in seconds)
    duration_val = row.get("duration")
    duration_ms = _parse_duration_ms(duration_val, is_seconds=True)

    # 7. Counters
    bytes_out = _parse_non_negative_int(row.get("orig_bytes") or row.get("orig_ip_bytes"))
    bytes_in = _parse_non_negative_int(row.get("resp_bytes") or row.get("resp_ip_bytes"))
    pkts_out = _parse_non_negative_int(row.get("orig_pkts"))
    pkts_in = _parse_non_negative_int(row.get("resp_pkts"))

    warnings: List[str] = []
    conn_state = _clean_str(row.get("conn_state"))
    if conn_state:
        warnings.append(f"zeek_state:{conn_state}")

    return CanonicalFlow(
        schema_version="1.0",
        event_id=event_id,
        sensor_id=default_sensor_id,
        observed_at=observed_at,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        duration_ms=duration_ms,
        packets_out=pkts_out,
        packets_in=pkts_in,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        parse_warnings=warnings,
    )


def normalize_flow_record(
    record: Dict[str, Any],
    default_sensor_id: str = "lab-sensor-01",
    assume_duration_seconds: bool = False
) -> CanonicalFlow:
    """
    General normalizer handling diverse flow formats (NetFlow, custom JSON, canonical subsets).
    """
    # Check if already has canonical field names
    if "schema_version" in record and record["schema_version"] == "1.0":
        # Fast path with schema validation
        return CanonicalFlow.model_validate(record)

    # Check if Zeek style
    if "id.orig_h" in record or "id_orig_h" in record or "conn_state" in record:
        return normalize_zeek_record(record, default_sensor_id=default_sensor_id)

    # Generic extraction
    event_id = _clean_str(record.get("event_id") or record.get("id") or record.get("flow_id")) or str(uuid.uuid4())
    sensor_id = _clean_str(record.get("sensor_id")) or default_sensor_id

    # Timestamp
    ts_val = record.get("observed_at") or record.get("timestamp") or record.get("time") or record.get("ts")
    if ts_val is None:
        observed_at = datetime.now(timezone.utc)
    else:
        observed_at = _parse_timestamp(ts_val)

    # Endpoints
    src_ip = _clean_str(record.get("src_ip") or record.get("source_ip") or record.get("srcaddr") or record.get("src"))
    dst_ip = _clean_str(record.get("dst_ip") or record.get("dest_ip") or record.get("dstaddr") or record.get("dst"))
    if not src_ip or not dst_ip:
        raise ValueError(f"Record missing src_ip or dst_ip: src={src_ip!r}, dst={dst_ip!r}")

    src_port = _parse_port(record.get("src_port") or record.get("source_port") or record.get("srcport") or record.get("sport"))
    dst_port = _parse_port(record.get("dst_port") or record.get("dest_port") or record.get("dstport") or record.get("dport"))

    proto = _clean_str(record.get("protocol") or record.get("proto") or record.get("protocol_name")) or "other"

    dur_val = record.get("duration_ms")
    if dur_val is not None:
        duration_ms = _parse_duration_ms(dur_val, is_seconds=False)
    else:
        duration_ms = _parse_duration_ms(record.get("duration"), is_seconds=assume_duration_seconds)

    pkts_out = _parse_non_negative_int(record.get("packets_out") or record.get("out_packets") or record.get("pkts_out") or record.get("packets"))
    pkts_in = _parse_non_negative_int(record.get("packets_in") or record.get("in_packets") or record.get("pkts_in"))
    bytes_out = _parse_non_negative_int(record.get("bytes_out") or record.get("out_bytes") or record.get("bytes"))
    bytes_in = _parse_non_negative_int(record.get("bytes_in") or record.get("in_bytes"))

    return CanonicalFlow(
        schema_version="1.0",
        event_id=event_id,
        sensor_id=sensor_id,
        observed_at=observed_at,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        duration_ms=duration_ms,
        packets_out=pkts_out,
        packets_in=pkts_in,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        parse_warnings=[],
    )

