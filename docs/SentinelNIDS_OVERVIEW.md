# SentinelNIDS — Production Deployment Overview

> **Project:** Machine Learning–Based Network Intrusion Detection System (ML-NIDS)  
> **Document:** `OVERVIEW.md`  
> **Status:** Implementation blueprint (not a claim that the system is already production-ready)  
> **Last updated:** 28 October 2026

## 1. Executive summary

**SentinelNIDS** is a deployable, defensive network monitoring platform that ingests authorized network-flow telemetry, scores flows with a versioned machine-learning model, generates explainable security alerts, and presents findings through a web dashboard. The initial release focuses on **flow-based intrusion detection**, not full packet inspection or automated attack blocking.

**Primary goal:** Turn an academic ML classifier into an operable, observable, secure service with reproducible training, realistic evaluation, monitored inference, and controlled deployment.

**Important distinction:** Deploying a dashboard to the public internet does **not** provide visibility into arbitrary internet traffic. A sensor must run on a network or host you own or are explicitly authorized to monitor, and forward telemetry to the backend. The cloud-hosted backend receives only what those sensors collect.

## 2. Product boundaries

### In scope for v1

- Collect **network flow metadata** from one authorized sensor, using a flow exporter or a controlled Zeek deployment.
- Normalize events into a documented schema; reject malformed, oversized, or stale events.
- Score events with a **trained and versioned** model; retain model version and prediction confidence/score.
- Generate alerts using model score **plus** basic deterministic rules, deduplication, and thresholds.
- Provide an authenticated dashboard for recent flows, alerts, severity, timestamps, sensor status, and model health.
- Provide secure APIs, structured logs, metrics, backups, and documented deployment/rollback.
- Keep the model in **shadow/observe-only mode** before enabling operational alerts.

### Explicitly out of scope for v1

- Autonomous blocking, firewall changes, packet injection, or active scanning.
- Deep packet inspection, payload capture, or TLS decryption.
- Claims of detecting every zero-day or every attack type.
- Multi-tenant enterprise billing, complex SOAR, or dozens of microservices.
- Storing full packet captures in the cloud by default.

## 3. Target users and real-world use cases

**Users:** a student/researcher demonstrating an end-to-end system, a small lab administrator, or an authorized security analyst.

**Use cases:**
1. A sensor observes a burst of unusual connections and forwards flow records.
2. The backend scores flows and flags a high-risk pattern for review.
3. An analyst filters alerts by sensor, source/destination, time, model version, and status.
4. The analyst marks a finding as true positive, false positive, or unresolved, feeding future evaluation.
5. Operators can detect a disconnected sensor or a degraded inference service.

## 4. Proposed architecture

```text
Authorized network / lab
  └── Sensor host (Zeek or flow exporter)
        └── Collector/forwarder (outbound TLS, authenticated)
              |
              v
Internet / private tunnel
              |
              v
Reverse proxy (TLS, rate limits)
              |
              v
FastAPI backend (ingestion + auth + inference + alert API)
  ├── Schema validation and deduplication
  ├── Feature pipeline (same transformations as training)
  ├── Versioned ML model (CPU inference)
  ├── Alert rules / thresholding
  └── PostgreSQL (flows, alerts, sensors, users, feedback)
              ^
              |
React dashboard (HTTPS; authenticated)

Operations: CI/CD → container images → staging → production
            logs + metrics + health checks + backups
```

**Architecture decision:** Start with one FastAPI application and PostgreSQL, rather than introducing Kafka, Kubernetes, Redis, or a separate model-serving cluster prematurely. Add a queue/worker only if measured ingest rates or inference latency demand it. For v1, keep ingestion bounded and implement backpressure; do not pretend a synchronous HTTP endpoint guarantees lossless high-volume capture.

## 5. Recommended technology stack

| Layer | Choice | Reason |
|---|---|---|
| Network telemetry | Zeek connection logs (`conn.log`) or a compatible flow exporter | Metadata-first collection on authorized networks |
| Sensor forwarder | Lightweight Python service or supported log shipper | Validate, batch, authenticate, retry, and buffer briefly |
| API / inference | Python 3.12 + FastAPI + Pydantic | Python ML ecosystem, schema validation, straightforward deployment |
| ML | scikit-learn baseline; optionally XGBoost after evaluation | Reproducible, fast CPU inference; avoid unnecessary deep learning |
| Training / experiments | pandas, scikit-learn, MLflow optional | Track datasets, preprocessing, thresholds, and model artifacts |
| Database | PostgreSQL | Reliable relational storage for events, alerts, users, audit records |
| Frontend | React + Vite + TypeScript | Dashboard and alert investigation |
| Packaging | Docker + Docker Compose | Repeatable single-host deployment |
| Reverse proxy / TLS | Caddy or Nginx | HTTPS termination and request limits |
| CI/CD | GitHub Actions | Tests, image builds, security checks, controlled deployments |
| Monitoring | Structured JSON logs + Prometheus-compatible metrics | Latency, throughput, failures, sensor freshness, drift indicators |

**Deployment target:** A modest Linux VPS/cloud VM for the backend and dashboard, with PostgreSQL on the same host only for an initial controlled deployment. For higher reliability, use a managed PostgreSQL service and private networking. Sensor software runs **separately** on the authorized monitored network.

## 6. Data strategy and model validity

### 6.1 Dataset selection

Use publicly documented intrusion-detection datasets (for example, CIC-IDS2017 or CSE-CIC-IDS2018) **only after verifying their licenses, label definitions, known artifacts, and feature availability**. Public benchmark performance does not establish real-world effectiveness. For a live demo, supplement with **consented, representative, locally collected benign flows** and carefully labeled, isolated lab exercises.

### 6.2 Critical feature compatibility

The live sensor must produce the **same feature definitions, units, missing-value conventions, and time windows** as the training pipeline. A model trained on CICFlowMeter-derived columns cannot simply be fed raw Zeek `conn.log` fields without a validated feature-mapping process. Choose one of these paths:

- **Preferred for first live deployment:** Train a model directly on a schema reproducible from the chosen live sensor; document exact field mappings and transformations.
- **Alternative:** Build and validate a compatible flow-feature extraction pipeline, with parity tests between offline and online features.

Do **not** silently fill unavailable features with zeros or claim that different tools' similarly named fields are interchangeable.

### 6.3 Training and evaluation protocol

1. Freeze raw dataset versions and record provenance/checksums.
2. Create **train/validation/test splits before fitting preprocessing**, ideally grouped by capture session, host, or time to reduce leakage.
3. Fit imputers, encoders, scalers, and classifier **only on training data**; serialize the full preprocessing-and-model pipeline.
4. Compare a simple baseline (e.g., logistic regression or random forest) with a stronger candidate only if justified.
5. Choose alert thresholds on validation data; evaluate once on the held-out test set.
6. Report precision, recall, F1, PR-AUC, confusion matrix, **false positives per hour/day**, detection latency, and per-attack-category results.
7. Evaluate on temporally distinct or locally collected traffic to estimate distribution shift.
8. Record artifact SHA-256, schema version, training code commit, training date, and evaluation report.

**Avoid accuracy-only claims:** At low attack prevalence, a model with apparently excellent accuracy can still overwhelm analysts with false alerts. Probability calibration and confidence estimates must be validated; a raw classifier score is not necessarily a probability.

### 6.4 Runtime inference contract

Input example (illustrative only; **not** a ready-made Zeek-to-model mapping):

```json
{
  "schema_version": "1.0",
  "sensor_id": "lab-sensor-01",
  "event_id": "d13c6c38-2f1e-4e0c-98db-c8f14790d842",
  "observed_at": "2026-10-28T10:00:00Z",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 51234,
  "dst_port": 443,
  "protocol": "tcp",
  "duration_ms": 125,
  "bytes_out": 820,
  "bytes_in": 2400
}
```

IP addresses shown above are documentation-only example ranges. Whether IPs are used as model features must be a deliberate, tested choice; typically they are retained as investigation metadata rather than identity shortcuts that cause leakage.

Response example:

```json
{
  "event_id": "d13c6c38-2f1e-4e0c-98db-c8f14790d842",
  "model_version": "flow-v1.0.0",
  "score": 0.87,
  "decision": "review",
  "alert_id": "alert-000123"
}
```

The `score` is a model-specific ranking value unless calibration has been verified. Thresholds and severity mapping are configured and tested, not inferred from the example value.

## 7. Core modules, implementation requirements, and deliverables

The system is organized by technical module and workflow—not by team-member assignment. The deliverables below define what must exist in the repository and how the modules fit together.

### 7.1 Authorized packet and flow capture

- Configure a controlled test environment and document the authorized interface or traffic source.
- Support reading approved PCAP files for offline testing and, where the deployment environment permits, capturing from an explicitly authorized test interface.
- Extract the supported fields needed by the selected flow schema, including source/destination IP addresses, source/destination ports, protocol, packet size or flow byte/packet counts, and timestamps.
- Handle truncated or malformed packets, missing fields, unsupported protocols, invalid timestamps, and parser exceptions without crashing the full pipeline.
- Prefer converting packets into normalized flow records before inference. Do not upload or retain raw packet payloads by default; PCAPs used for tests must be authorized and appropriately sanitized.

**Deliverables:** a capture/parser module (for example, `packet_capture.py`), a small set of authorized sample PCAP fixtures where redistribution is permitted, normalized sample events, parser tests, and a packet/flow extraction report documenting fields, units, missing-data behavior, and limitations.

### 7.2 Detection engine and rules

- Implement deterministic detections for suspicious connection rates and possible port-scanning patterns, using configurable windows, thresholds, exclusions, and severity levels.
- Produce a consistent result for every analyzed flow, including an event/flow ID, decision, severity where applicable, detection reason or rule IDs, timestamp, and model/rule version.
- Optionally add an anomaly-detection or supervised ML model only after the live feature schema is compatible with the training data and the model passes held-out evaluation.
- Keep rule-based findings distinguishable from ML predictions. A score is not a confirmed attack, and a model score must not be described as a probability unless calibration has been validated.
- Test boundary conditions, bursts, repeated events, benign high-volume services, missing fields, and threshold changes.

**Deliverables:** a detection module (for example, `detection_engine.py`), versioned rule/threshold configuration, unit tests and representative detection test cases, plus a report of rule behavior and model evaluation where applicable.

### 7.3 Event persistence and alert management

- Define stable event, flow, prediction, alert, and audit fields, including event IDs, observed/received timestamps in UTC, severity, detection reasons, source metadata, and model/rule versions.
- Persist events and alerts, handle storage failures explicitly, and prevent duplicate records/alerts where practical using unique event IDs and a documented deduplication window.
- Provide review states and record analyst disposition when the dashboard supports alert acknowledgment or feedback.
- **Production default:** use the PostgreSQL data model defined in this overview. SQLite may be used for local development or isolated tests; CSV is suitable for exports, fixtures, and evaluation reports—not as the production source of truth for concurrent live ingestion.
- Avoid logging credentials or unnecessary sensitive traffic metadata; apply access controls and retention rules.

**Deliverables:** an alert/event manager (for example, `alert_manager.py`), database migrations/schema, deduplication and storage-error tests, and sanitized sample event/alert logs.

### 7.4 Dashboard and reporting

- Display total flows/events, alert counts, severity distribution, protocol distribution, event timelines, sensor health, and model status.
- Support search and filtering by time range, source/destination IP where collected, protocol, alert type/rule, severity, and review status. Correct the duplicated “Add search and filtering” requirement into one unified filtering capability.
- Show alert evidence, timestamps with timezone, detection reasons, and model/rule version; distinguish unreviewed detections from confirmed incidents.
- **Production default:** use the React + TypeScript dashboard in the proposed architecture. Streamlit is optional for a lightweight local evaluation/demo dashboard only if explicitly chosen; do not build and maintain two dashboards without a clear need.
- Produce charts and screenshots for the final demonstration, accompanied by a concise report that explains what the charts measure and the limits of the test data.

**Deliverables:** dashboard implementation, search/filter behavior, summary charts, sanitized screenshots, and a dashboard/reporting summary.

### 7.5 Integration, testing, and evaluation

- Integrate capture, normalization, detection, persistence, API, and dashboard through one documented event contract; keep the repository and setup instructions reproducible.
- Create unit, integration, and end-to-end tests, including the path from an authorized PCAP or test flow through detection and persistence to a visible alert.
- Compare predictions with labeled held-out test data where labels are available. Report the confusion matrix, precision, recall, F1, PR-AUC where suitable, false positives/alerts per time window, and per-class results where relevant.
- Measure end-to-end detection latency, processing throughput (flows/events per second), rejected/malformed input counts, duplicate handling, and any observed event loss under a documented workload.
- Do not invent target accuracy or claim universal detection. Document dataset provenance, class distribution, split method, test environment, limitations, and reproducible commands.

**Deliverables:** application entry point or orchestration module (for example, `main.py`), test scripts, integration documentation, evaluation results, latency/throughput measurements, and a final demonstration/report package.

### 7.6 Cross-cutting operational requirements

| Module | Responsibilities |
|---|---|
| Sensor/forwarder | Capture permitted metadata; timestamp, normalize, and forward events; retry with bounded buffering |
| Ingestion | Authenticate sensors, validate schema, enforce size/rate limits, and deduplicate `event_id` |
| Feature engineering | Reproduce training transforms exactly and reject unsupported feature schemas |
| Inference | Load a pinned model, score supported flows, and record model version and latency |
| Alert engine | Apply configurable thresholds and rules; deduplicate and manage review status |
| API | Provide authenticated access to alerts, summaries, sensor health, and model metadata |
| Dashboard | Show overview, alerts, details, filters, sensor status, and model status |
| Operations | Provide structured logs, metrics, backups, deployment, incident response, and rollback procedures |

**Integration rule:** modules must exchange a documented normalized event/result schema. A packet parser, rule engine, database, and dashboard are not considered integrated merely because they run independently; an end-to-end test must prove that one test event can be traced through the entire pipeline.

## 8. API design (initial contract)

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/ingest/flows` | Sensor credential | Submit bounded batches of validated flow records |
| `GET` | `/api/v1/alerts` | Analyst | Paginated and filtered alerts |
| `GET` | `/api/v1/alerts/{id}` | Analyst | Alert details and evidence |
| `PATCH` | `/api/v1/alerts/{id}` | Analyst | Update review status and analyst feedback |
| `GET` | `/api/v1/dashboard/summary` | Analyst | Counts, rates, and recent trends |
| `GET` | `/api/v1/sensors` | Admin/analyst | Sensor status and last-seen time |
| `GET` | `/api/v1/model` | Analyst | Active model and feature-schema versions |
| `GET` | `/health/live` | Internal / probe | Process liveness |
| `GET` | `/health/ready` | Internal / probe | DB/model readiness |

**Security note:** Ingestion credentials must be distinct from user credentials. Use TLS, scoped sensor API keys or mTLS, server-side key hashing, rotation, revocation, and per-sensor quotas. Avoid unauthenticated public ingestion.

## 9. Data model (minimum viable)

- **users:** ID, email, password hash or identity-provider subject, role, created_at.
- **sensors:** ID, name, key hash/credential reference, enabled flag, last_seen_at, schema version.
- **flows:** ID, sensor_id, event_id (unique per sensor), observed_at, metadata, model_version, score, ingested_at.
- **alerts:** ID, flow_id or grouped-flow reference, severity, rule/model reason, status, created_at, updated_at.
- **alert_feedback:** alert_id, analyst_id, disposition, note, timestamp.
- **audit_logs:** actor, action, resource, timestamp, outcome (never log credentials).

Index `flows(sensor_id, observed_at)`, unique `(sensor_id, event_id)`, and alert filters. Use retention policies and partitioning only when scale warrants them.

## 10. Dashboard requirements

1. **Overview:** monitored sensor count, last ingestion time, flows processed, alert count, severity distribution, and alert trend.
2. **Alerts:** searchable/paginated table with severity, timestamp, source/destination, status, score, and model version.
3. **Alert detail:** evidence, contributing features or interpretable rules where supportable, review notes, and disposition.
4. **Sensors:** online/stale/offline based on heartbeat or last-seen age, plus ingestion errors.
5. **Model status:** active artifact, feature-schema version, latest evaluation metrics, and operational drift warnings.

Never describe a prediction as a confirmed attack until investigated. Show timestamps with timezone and indicate when data is delayed.

## 11. Production security and privacy

- Collect **only traffic from networks with explicit authorization**; document scope and retention.
- Prefer flow metadata over payloads; minimize personal information and redact sensitive values in logs.
- Enforce HTTPS; restrict database to private networking; close unused ports.
- Use least-privilege database roles and non-root containers; pin and scan dependencies/images.
- Use a secure identity provider or properly implemented password hashing, session controls, and RBAC for the dashboard.
- Keep secrets in environment/secret management, **never in Git or frontend bundles**.
- Set body-size, batch-size, and per-sensor rate limits; defend against replay via event IDs and time-window checks.
- Treat sensor input as untrusted; validate fields and bound memory/CPU consumption.
- Store signed or checksum-verified model artifacts from a trusted build; never deserialize untrusted pickle/joblib files.
- Encrypt backups, test restoration, and enforce retention/deletion rules.
- Avoid exposing Prometheus, database, admin routes, and internal readiness details publicly.
- Maintain a process for credential compromise, sensor abuse, and false-positive escalation.

## 12. Deployment topology and environments

### Development

Docker Compose: backend + PostgreSQL + frontend, seeded with **synthetic/example flows**. Unit and integration tests run locally.

### Staging

Production-like deployment with a nonproduction database, dedicated test sensor, pinned image versions, and synthetic traffic. Run schema parity, load, security, and rollback tests here.

### Production

- Linux VM with Docker Compose; HTTPS reverse proxy in front of frontend/API.
- Only ports 80/443 publicly exposed where required; SSH restricted, ideally via VPN or allowlist.
- Backend/database reachable only through internal container network.
- Separate authorized sensor forwarding outbound over authenticated TLS.
- Automated backups, monitored disk capacity, health checks, and image rollback procedure.
- Deploy versioned immutable images, not ad-hoc source edits on the server.

**Scaling trigger:** Measure flows/sec, batch queue age, p95 inference latency, CPU, memory, database write throughput, and dropped-event rate. Add a durable queue and separate worker only after demonstrated need. For critical deployments, a single VPS is a single point of failure and is not a high-availability design.

## 13. Reliability, monitoring, and SLOs

Initial **engineering targets** (to validate under realistic load, not promised performance):

| Metric | Initial target |
|---|---|
| API availability | 99.5% monthly for a single-host student deployment |
| Inference latency | p95 < 250 ms per batch under documented test load |
| End-to-end alert delay | p95 < 30 s for healthy sensor/network under test load |
| Event loss | Explicitly measured and reported; no lossless guarantee without durable buffering |
| Sensor health | Alert when no heartbeat/flows within configured expected window |
| Backup recovery | Document and test restore; define RPO/RTO after choosing infrastructure |

Track HTTP 4xx/5xx, ingestion acceptance/rejection, deduplication, model load failures, feature mismatch, score distributions, drift indicators, alert volume, false-positive feedback, sensor lag, DB usage, and backup success. Set actionable alerts for sustained errors, disk pressure, sensor disconnects, and failed backups.

## 14. Testing and release gates

- **Unit:** feature transformations, input validation, threshold logic, deduplication, severity mapping.
- **Data:** missing/invalid fields, extreme values, timestamps, class imbalance, leakage checks.
- **Model:** reproducibility, held-out evaluation, schema parity, version loading, latency/memory budget.
- **Integration:** sensor → ingestion → database → inference → alert → dashboard.
- **Security:** authz by role, invalid/revoked sensor key, replay, oversized batches, dependency scan, secret scan.
- **Load:** documented flows/sec, burst tests, backpressure, queue/buffer exhaustion, recovery after restart.
- **Operations:** backup restore, DB migration rollback strategy, redeploy previous image, failed-model startup.
- **Acceptance:** test on a consented network; shadow mode first; analyst verifies sampled alerts before operational use.

**Go-live blocker:** No live deployment until feature parity between training and sensor is demonstrated. A visually working dashboard with invalid features is not a working NIDS.

## 15. Suggested repository layout

```text
sentinelnids/
├── OVERVIEW.md
├── README.md
├── docs/
│   ├── architecture.md
│   ├── data-and-model.md
│   ├── api.md
│   ├── threat-model.md
│   └── operations.md
├── backend/
│   ├── app/                  # FastAPI, ingestion, inference, alerts, auth
│   ├── tests/
│   ├── migrations/
│   ├── Dockerfile
│   └── pyproject.toml
├── frontend/                 # React + TypeScript dashboard
├── sensor/                   # Authorized flow forwarding and tests
│   ├── packet_capture.py     # PCAP/interface parsing where applicable
│   └── README.md
├── detection/                # Deterministic rules and unified detection results
│   ├── detection_engine.py
│   └── rules.yaml
├── ml/
│   ├── training/             # Offline reproducible training pipeline
│   ├── evaluation/
│   └── artifacts/            # Metadata/manifests; no large models in Git
├── deploy/
│   ├── compose.yaml
│   ├── Caddyfile
│   └── .env.example
├── alert_manager.py          # Optional thin service facade; DB schema remains in backend migrations
├── main.py                   # Application entry point/integration, if appropriate for the chosen layout
└── .github/workflows/        # Tests, scans, build, deployment approvals
```

This is a **target layout**, not a mandate to create every file on day one. Start with the minimum vertical slice and add docs/components as they become necessary.

## 16. Implementation roadmap

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0. Scope & sensor decision** | Threat model, authorized lab scope, chosen sensor, concrete flow schema | Sensor produces sample events with stable definitions |
| **1. Data & ML baseline** | Reproducible training, honest evaluation, versioned pipeline | Held-out metrics and offline/live feature-parity tests |
| **2. End-to-end MVP** | Sensor → FastAPI → PostgreSQL → inference → alert | One real authorized flow visible with traceable model version |
| **3. Dashboard & review** | Authenticated alert UI, filters, feedback | Analyst can investigate and disposition an alert |
| **4. Hardening** | Credential rotation, rate limits, tests, observability, backup/restore | Security and operational release gates pass |
| **5. Staging → production** | HTTPS, CI/CD, shadow mode, monitored rollout, rollback | Stable sensor ingestion, measured alert quality, successful recovery drill |
| **6. Iteration** | Drift review, threshold tuning, model retraining | Improvements verified on new held-out data before promotion |

**Build order:** Start by proving the hardest dependency—**sensor-to-model feature compatibility**—before investing in UI polish or infrastructure complexity.

## 17. Definition of done

A credible first production deployment must demonstrate all of the following:

- A real sensor is installed on an authorized network and sends metadata securely.
- The live feature schema matches the trained model's expected schema, with automated parity tests.
- A held-out evaluation report documents false positives and limitations.
- An authenticated dashboard shows traceable alerts with model version and review status.
- Invalid/replayed/oversized events are safely rejected; credentials can be revoked.
- Health, ingestion lag, and error metrics are observable; backups and restoration are tested.
- Staging rollout, production rollback, and a basic incident runbook are documented.
- No claims of universal attack detection or guaranteed prevention are made.

## 18. Known risks and decisions to make

| Risk / open decision | Consequence | Mitigation / next action |
|---|---|---|
| Dataset/live schema mismatch | Predictions meaningless | Select sensor and lock feature contract before training |
| Benchmark data leakage | Inflated scores | Group/time-aware splits and held-out evaluation |
| Changing network traffic | Drift, missed detections | Monitor distributions and review fresh labels |
| Low base rate of attacks | Excessive false alerts | Tune for precision and alerts/day, not accuracy alone |
| Sensor loss or tampering | Blind spots | Authenticated sensors, freshness alerts, bounded buffering |
| Public ingestion abuse | Cost or denial of service | Credential scope, quotas, validation, rate limiting |
| Single-host deployment | Downtime and data loss | Backups, rollback, recovery plan; upgrade if needed |
| Unclear privacy/legal scope | Unauthorized collection | Written authorization, minimal collection, retention controls |

## 19. Future enhancements (only after v1 proves value)

- Multi-sensor correlation and richer rule engine.
- Durable ingestion queue and horizontal workers for measured high throughput.
- Drift detection, controlled retraining, and model canary deployments.
- SIEM integrations (webhooks, syslog, or standard event formats).
- Advanced explainability where technically valid.
- Optional **human-approved** response actions with strict safeguards.

## 20. Immediate next step

**Choose the live telemetry source first**: Zeek `conn.log` or a specific flow exporter, plus the authorized network where it will run. Capture 20–50 representative sample records, define the normalized schema, and confirm which fields can be computed identically during offline training. Only then select a compatible dataset/model and implement the first end-to-end vertical slice.

---

**Project positioning:** “An end-to-end, flow-based ML intrusion detection platform with secure sensor ingestion, reproducible model evaluation, real-time alert review, and monitored cloud deployment.” This describes the intended product architecture; its detection quality must be established empirically.
