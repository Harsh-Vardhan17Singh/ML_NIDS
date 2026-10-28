# SentinelNIDS Operational Runbook & SOC Playbook

This runbook provides actionable procedures for Site Reliability Engineers (SRE) and Security Operations Center (SOC) analysts maintaining **SentinelNIDS**.

---

## 1. Service Level Objectives (SLOs) & Alert Thresholds

| Metric | Target / SLO | Warning Threshold | Critical Incident Threshold |
|---|---|---|---|
| **API Availability** | $\ge 99.9\%$ uptime | $< 99.5\%$ over 1 hr | $< 99.0\%$ or backend unreachable |
| **Ingestion Latency (p95)** | $\le 25\text{ ms}$ / batch | $> 50\text{ ms}$ | $> 200\text{ ms}$ |
| **Model Inference Latency** | $\le 50\text{ \mu s}$ / flow | $> 100\text{ \mu s}$ | $> 500\text{ \mu s}$ or ML exception |
| **Sensor Heartbeat Age** | $\le 60\text{ s}$ | $> 120\text{ s}$ | $> 300\text{ s}$ (Sensor presumed offline) |
| **Ingestion Error Rate** | $\le 0.01\%$ | $> 1.0\%$ | $> 5.0\%$ of requests rejected |

---

## 2. Standard Operating Procedures (SOPs)

### SOP-01: Sensor Fleet Offline or Stale Heartbeat

#### Symptoms
- Sensor status badge shows `OFFLINE` or `STALE` in the Sentinel Dashboard (`/sensors`).
- Ingestion metrics report drop in incoming flow volume ($> 50\%$ drop).

#### Diagnostic Steps
1. Identify the specific sensor ID from `/api/v1/sensors`.
2. Verify network connectivity from the sensor host to the backend:
   ```bash
   # From sensor host:
   curl -I http://<sentinel-backend-host>:8000/api/v1/health
   ```
3. Check sensor logs (e.g. Zeek forwarder, daemon process):
   ```bash
   journalctl -u sentinel-sensor -n 100 --no-pager
   ```
4. Verify authentication token: Ensure `X-Sensor-Token` on sensor matches `SENSOR_API_KEY` on backend.

#### Mitigation
- If token rotated: Update `/etc/sentinel/sensor.conf` with new token and restart service.
- If network partition: Verify firewall rules allowing egress to backend port 8000/443.
- If daemon crashed: Restart sensor service: `systemctl restart sentinel-sensor`.

---

### SOP-02: Ingestion Rejection / Validation Spike

#### Symptoms
- Spike in HTTP 422 (Unprocessable Entity) or HTTP 400 responses on `POST /api/v1/ingest/flows`.
- Ingestion acknowledgement shows high `rejected` count.

#### Diagnostic Steps
1. Inspect the last 100 backend error logs:
   ```bash
   docker logs sentinel-backend --tail 100 | grep -E "ValidationError|HTTPException"
   ```
2. Verify payload schema: Common causes include:
   - Negative durations or packet counts emitted by uncalibrated sensors.
   - Malformed IPv4/IPv6 strings.
   - Unsupported `schema_version` (supported: `1.0`).

#### Mitigation
- Check if a new sensor agent was deployed with an updated schema without updating backend parser.
- Temporary workaround: Ensure sensors run `sensor.normalize.normalize_generic_flow()` prior to submission to clamp out-of-spec negative integers.

---

### SOP-03: Model Failure or Fallback Mode

#### Symptoms
- Health check returns `"ml_model_loaded": false`.
- Logs contain `[ERROR] Failed to load model artifact` or inference exceptions.

#### Behavior in Fallback Mode
SentinelNIDS is designed with **dual-engine redundancy**:
- If the ML model artifact fails to load or corrupts, the engine gracefully degrades to **Deterministic Rule Engine Only**.
- Rule-based alerts (Port Scan, SYN Flood bursts, Sensitive Port probes) continue triggering without interruption.

#### Mitigation
1. Verify model artifact existence and integrity:
   ```bash
   docker exec -it sentinel-backend ls -lh /app/ml/artifacts/sentinel_model_v1.joblib
   ```
2. If corrupted, restore the model artifact from version control or backup:
   ```bash
   docker cp ml/artifacts/sentinel_model_v1.joblib sentinel-backend:/app/ml/artifacts/
   ```
3. Restart the backend container:
   ```bash
   docker restart sentinel-backend
   ```
4. Confirm health check: `curl http://localhost:8000/api/v1/health`.

---

### SOP-04: False Positive Alert Storm

#### Symptoms
- Sudden influx of `HIGH` or `CRITICAL` alerts for benign business traffic (e.g., automated vulnerability scanner, backup replication).
- SOC alert queue overwhelmed.

#### Mitigation
1. **Identify the Traffic Vector**:
   - Open Sentinel Dashboard -> Sort Alerts by `CREATED` descending.
   - Review Alert Details: check `source_ip`, `destination_ip`, `destination_port`, and `matched_rules`.
2. **Dynamic Threshold Tuning**:
   - If the alert is purely ML-driven (`rule_id: None`, `score` hovering near `0.65`–`0.70`), increase the threshold in `.env`:
     ```env
     ALERT_SCORE_THRESHOLD=0.75
     ```
   - Restart the backend to apply immediately.
3. **Analyst Bulk Triage**:
   - In the Alert Detail modal, mark false alerts as `false_positive`.
   - Provide structured feedback notes: *"Known vulnerability scan by internal security team (10.0.0.85)."*
   - Feedback is saved to `analyst_feedback` table for future model retraining cycles.

---

### SOP-05: Database Outage / Connection Exhaustion

#### Symptoms
- Backend returns HTTP 500 on all query and write endpoints.
- Error logs show `OperationalError: could not connect to server` or `connection limit exceeded`.

#### Mitigation
1. Check PostgreSQL container status:
   ```bash
   docker ps -a | grep sentinel-postgres
   ```
2. If exited, review container exit code and logs:
   ```bash
   docker logs sentinel-postgres --tail 100
   ```
3. Check disk space on host: `df -h /var/lib/docker`. If disk full, prune unused images:
   ```bash
   docker system prune -f
   ```
4. Restart database and backend:
   ```bash
   docker restart sentinel-postgres
   sleep 5
   docker restart sentinel-backend
   ```
