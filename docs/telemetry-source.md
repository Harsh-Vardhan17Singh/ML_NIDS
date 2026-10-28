# SentinelNIDS — Telemetry Sources & Mapping Specification

> **Document:** `telemetry-source.md`  
> **Target Version:** `1.0`  
> **Purpose:** Document source flow formats, sensor integration, and translation into the canonical flow schema.

---

## 1. Supported Telemetry Sources

SentinelNIDS supports three primary telemetry input sources:
1. **Zeek `conn.log` (JSON or TSV format)**: Preferred for production and lab network monitoring on authorized sensor hosts.
2. **Offline PCAP Captures (`.pcap` / `.pcapng`)**: For controlled replay, baseline tests, and authorized security assessments.
3. **Structured Flow Ingestion API (`POST /api/v1/ingest/flows`)**: JSON batches transmitted from lightweight forwarder agents.

---

## 2. Field Mapping Table: Zeek `conn.log` to Canonical Flow

| Zeek `conn.log` Field | Canonical Field | Transform / Translation Logic |
|---|---|---|
| `uid` | `event_id` | Mapped directly, or hashed to UUID if strict UUID format is required |
| `ts` | `observed_at` | Unix epoch float converted to UTC ISO 8601 string (`...Z`) |
| `id.orig_h` | `src_ip` | Validated IPv4/IPv6 string |
| `id.resp_h` | `dst_ip` | Validated IPv4/IPv6 string |
| `id.orig_p` | `src_port` | Integer $0–65535$, or `null` if unassigned |
| `id.resp_p` | `dst_port` | Integer $0–65535$, or `null` if unassigned |
| `proto` | `protocol` | Lowercase string (`"tcp"`, `"udp"`, `"icmp"`) |
| `duration` | `duration_ms` | Float seconds multiplied by 1000.0; if missing/`-`, defaults to `0.0` |
| `orig_pkts` | `packets_out` | Integer $\ge 0$; if missing/`-`, defaults to `0` |
| `resp_pkts` | `packets_in` | Integer $\ge 0$; if missing/`-`, defaults to `0` |
| `orig_bytes` | `bytes_out` | Integer $\ge 0$; if missing/`-`, defaults to `0` |
| `resp_bytes` | `bytes_in` | Integer $\ge 0$; if missing/`-`, defaults to `0` |

---

## 3. PCAP Extraction Strategy

When reading from authorized `.pcap` files:
1. Packets are grouped by 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)` within a sliding inactivity window (default 30 seconds).
2. For each flow:
   - `duration_ms`: Time difference between first packet and last packet in milliseconds.
   - `packets_out`: Count of packets traversing $A \to B$.
   - `packets_in`: Count of packets traversing $B \to A$.
   - `bytes_out`: Sum of packet lengths traversing $A \to B$.
   - `bytes_in`: Sum of packet lengths traversing $B \to A$.
3. Packet payloads are discarded immediately after header parsing to respect metadata-only privacy boundaries.

---

## 4. Sensor Coverage & Operational Boundaries

- **Sensor Placement**: Must be deployed at internal tap, SPAN/mirror port, or host interface with explicit written authorization.
- **Invisibility**: Traffic not traversing the sensor interface cannot be inspected or detected.
- **Dropped Packets**: Sensor forwarders must monitor packet drop indicators (`conn.log` history or OS ring buffer drops) and log warnings when buffer exhaustion occurs.

