# SentinelNIDS — Data Dictionary & Canonical Flow Schema

> **Document:** `data-dictionary.md`  
> **Schema Version:** `1.0`  
> **Status:** Canonical Contract

---

## 1. Overview

The **Canonical Flow Schema** defines the unified contract across all SentinelNIDS modules:
- Telemetry ingestion from sensors or PCAP parsers
- Defensive normalization and validation
- Deterministic rule detection (connection rate, port scanning)
- ML feature transformation and inference
- PostgreSQL persistence and API reporting

Every flow event ingested into SentinelNIDS must adhere to or be normalized into this schema.

---

## 2. Canonical Flow Field Specification

| Field Name | Type | Required? | Nullable? | Description & Constraints | Example |
|---|---|---|---|---|---|
| `schema_version` | String | Yes | No | Version of the canonical schema. Must match `"1.0"`. | `"1.0"` |
| `event_id` | String / UUID | Yes | No | Stable, globally unique identifier (UUIDv4) or deterministic hash serving as an idempotency key. | `"c9b2f3a4-82a1-432a-bc91-383bc1234567"` |
| `sensor_id` | String | Yes | No | Identifier of the registered sensor/collector capturing the flow. ASCII alphanumeric and hyphens/underscores (1–64 chars). | `"lab-sensor-01"` |
| `observed_at` | Datetime (UTC) | Yes | No | Timestamp of flow observation by the sensor. Must be ISO 8601 with explicit UTC timezone (`Z` or `+00:00`). | `"2026-10-28T14:30:00.125000Z"` |
| `received_at` | Datetime (UTC) | No | Yes | Timestamp when the ingestion service received the event. Populated by the backend. | `"2026-10-28T14:30:00.850000Z"` |
| `src_ip` | String (IPv4/IPv6) | Yes | No | Source IP address. Must be a valid IPv4 or IPv6 address. | `"192.168.1.105"` |
| `dst_ip` | String (IPv4/IPv6) | Yes | No | Destination IP address. Must be a valid IPv4 or IPv6 address. | `"10.0.0.5"` |
| `src_port` | Integer | No | Yes | Source transport port. Valid range `0` to `65535`. Null for protocols without ports (e.g., ICMP). | `54321` |
| `dst_port` | Integer | No | Yes | Destination transport port. Valid range `0` to `65535`. Null for protocols without ports. | `443` |
| `protocol` | String | Yes | No | Normalized transport/network protocol in lower case (`"tcp"`, `"udp"`, `"icmp"`, or `"other"`). | `"tcp"` |
| `duration_ms` | Float | Yes | No | Total elapsed flow duration in milliseconds. Must be non-negative ($\ge 0.0$). Single-packet flows have `0.0`. | `125.4` |
| `packets_out` | Integer | Yes | No | Number of packets sent from source to destination. Integer $\ge 0$. | `15` |
| `packets_in` | Integer | Yes | No | Number of packets sent from destination to source. Integer $\ge 0$. | `22` |
| `bytes_out` | Integer | Yes | No | Total byte payload/volume from source to destination. Integer $\ge 0$. | `1420` |
| `bytes_in` | Integer | Yes | No | Total byte payload/volume from destination to source. Integer $\ge 0$. | `8950` |
| `parse_warnings` | Array of Strings | No | No | Safe warning codes or non-fatal anomalies detected during normalization. | `[]` |

---

## 3. Missing Value & Boundary Rules

1. **Zero vs. Null Distinction**:
   - `duration_ms = 0.0` means an instantaneous packet or micro-flow.
   - `src_port = null` means the underlying protocol does not support transport ports (e.g. ICMP), whereas `0` represents a reserved port.
   - Never replace unknown or missing fields with arbitrary zeros.
2. **Timestamp Bounds**:
   - `observed_at` must not be in the future (allowing up to a 60-second clock skew tolerance).
   - Ingestion rejects events older than the configured ingestion window (default 24 hours in real-time mode).
3. **Counter Integrity**:
   - If `packets_out == 0`, `bytes_out` must also be `0`.
   - Any negative count for packets, bytes, or durations is strictly invalid and rejected.
4. **Idempotency**:
   - `(sensor_id, event_id)` forms a unique tuple in the persistent database to guarantee duplicate-free ingestion.

---

## 4. Canonical JSON Example

```json
{
  "schema_version": "1.0",
  "event_id": "c9b2f3a4-82a1-432a-bc91-383bc1234567",
  "sensor_id": "lab-sensor-01",
  "observed_at": "2026-10-28T14:30:00.125000Z",
  "received_at": "2026-10-28T14:30:00.850000Z",
  "src_ip": "192.168.1.105",
  "dst_ip": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "tcp",
  "duration_ms": 125.4,
  "packets_out": 15,
  "packets_in": 22,
  "bytes_out": 1420,
  "bytes_in": 8950,
  "parse_warnings": []
}
```
