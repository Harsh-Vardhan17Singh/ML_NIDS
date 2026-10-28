# SentinelNIDS — Technical Requirements Document (TRD)

**Version:** 1.0  
**Last updated:** 28 October 2026  
**Status:** Proposed implementation baseline  
**Companion:** `OVERVIEW.md` and `PRD.md`

> This document defines **how** SentinelNIDS should be implemented. Names and paths below are recommendations; keep the first implementation small and add abstractions only when required.

## 1. Technical objectives

Implement an end-to-end defensive network intrusion detection pipeline that:
- Parses authorized PCAP files and optionally captures from an authorized interface.
- Normalizes packets/flows into a versioned event contract.
- Runs deterministic detection rules and optionally a compatible ML pipeline.
- Persists events, predictions, alerts, and audit actions.
- Exposes authenticated APIs and a dashboard.
- Can be tested, deployed, monitored, backed up, and rolled back.

The v1 runtime is passive and alert-only. No packet blocking, firewall mutation, packet injection, or active scanning.

## 2. Proposed technology stack

| Layer | Baseline | Notes |
|---|---|---|
| Language/runtime | Python 3.12 | Pin dependencies and runtime. |
| Packet parsing | Scapy or a maintained PCAP parser | Use only the functions required; raw live capture may need OS privileges and is platform-dependent. |
| Flow source | Authorized PCAP fixtures; optional Zeek or compatible exporter for live flow metadata | Choose one primary source before locking model features. |
| Detection | Python rule engine with YAML/TOML/JSON configuration | Deterministic rules first; avoid a complex rule framework. |
| ML | scikit-learn baseline; optional estimator only if evaluation justifies it | Bundle preprocessing and estimator in one trusted pipeline. |
| API | FastAPI + Pydantic | Validation, API schemas, OpenAPI. |
| Persistence | PostgreSQL in production; SQLite for isolated local tests only | CSV is for exports and reports, not live concurrent source-of-truth storage. |
| Frontend | React + TypeScript | Default production dashboard. Streamlit is optional for a separate local demo only. |
| Migrations | Alembic or equivalent migration tool | Schema changes must be reproducible. |
| Packaging | Docker + Docker Compose | Non-root app process; DB not public. |
| TLS proxy | Caddy or Nginx | TLS, request limits, security headers and routing. |
| CI | GitHub Actions or equivalent | Tests, linting, secret/dependency scans, image build. |
| Observability | Structured JSON logs and metrics endpoint | Do not include secrets or raw payloads in logs. |

## 3. Architecture

```text
Authorized network / approved PCAP
              |
              v
      Capture / PCAP parser
       packet_capture.py
              |
              v
       Normalized event schema
              |
              v
       detection_engine.py <---- rules.yaml
          |             |
          |             +---- optional versioned ML pipeline
          v
       Detection result
              |
              v
       alert_manager.py / persistence service
              |
              v
         PostgreSQL
              |
              v
    FastAPI authenticated API
              |
              v
    React + TypeScript dashboard

Tests: unit -> integration -> end-to-end
Operations: Docker Compose + TLS proxy + logs/metrics + backups
```

The modules may be packaged differently as the implementation evolves. Keep a single documented event contract between them. The names `packet_capture.py`, `detection_engine.py`, `alert_manager.py`, and `main.py` are example entry points, not a reason to split code unnecessarily.

## 4. Suggested repository structure

```text
sentinelnids/
├── OVERVIEW.md
├── PRD.md
├── TRD.md
├── README.md
├── .env.example
├── .gitignore
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── auth/
│   │   ├── ingestion/
│   │   ├── detection/
│   │   ├── alerts/
│   │   ├── db/
│   │   └── schemas/
│   ├── migrations/
│   ├── tests/
│   ├── Dockerfile
│   └── pyproject.toml
├── sensor/
│   ├── packet_capture.py
│   ├── normalize.py
│   ├── fixtures/
│   └── tests/
├── detection/
│   ├── detection_engine.py
│   ├── rules.yaml
│   └── tests/
├── ml/
│   ├── training/
│   ├── evaluation/
│   ├── feature_schema.json
│   └── model_cards/
├── frontend/
│   ├── src/
│   ├── package.json
│   └── Dockerfile
├── deploy/
│   ├── compose.yaml
│   └── Caddyfile
└── .github/workflows/
```

This is a target layout. Do not create empty directories or services in advance. If the MVP is simpler as one Python package, keep it together until a real boundary is needed.

## 5. Normalized event contract

All downstream detection and persistence should consume normalized records, not raw parser-specific packet objects.

### 5.1 Minimum fields

| Field | Type / semantics | Required? |
|---|---|---|
| `event_id` | UUID or stable unique ID | Yes |
| `observed_at` | UTC timestamp from capture/source | Yes; invalid values rejected or explicitly handled |
| `received_at` | UTC timestamp when application accepts event | Added by application |
| `source_type` | `pcap`, `live_interface`, or selected exporter | Yes |
| `sensor_id` | Configured sensor/collector ID | Required for deployed sensor ingestion |
| `src_ip`, `dst_ip` | Valid IP strings if available | Optional when source cannot provide them |
| `src_port`, `dst_port` | Integers 0–65535 when applicable | Optional for protocols without ports |
| `protocol` | Normalized protocol name/number | Yes when parseable |
| `packet_size_bytes` | Non-negative integer for packet-level record | Optional if not available |
| `duration_ms` | Non-negative flow duration | Optional for packet-level records |
| `packets_out`, `packets_in` | Non-negative counts if flow aggregation exists | Optional |
| `bytes_out`, `bytes_in` | Non-negative byte counts if flow aggregation exists | Optional |
| `schema_version` | Version of normalized schema | Yes |
| `parse_warnings` | Safe list of warning codes | Optional |

Do not fill unavailable values with misleading zeros. Distinguish “zero” from “unknown/not applicable.” Store timestamps in UTC and display them with an explicit timezone.

### 5.2 Example normalized event

```json
{
  "event_id": "d13c6c38-2f1e-4e0c-98db-c8f14790d842",
  "observed_at": "2026-10-28T10:00:00Z",
  "received_at": "2026-10-28T10:00:01Z",
  "source_type": "pcap",
  "sensor_id": "lab-sensor-01",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "src_port": 51234,
  "dst_port": 443,
  "protocol": "tcp",
  "packet_size_bytes": 820,
  "schema_version": "1.0",
  "parse_warnings": []
}
```

The IPs are documentation-only example addresses. The example is a normalized record, not a model feature specification.

## 6. Capture and parsing requirements

### 6.1 Offline PCAP
- Accept an explicit file path or configured fixture; do not recursively process arbitrary filesystem paths from untrusted requests.
- Validate file existence, file size, and parser-readable format.
- Iterate packets defensively; one malformed packet must not terminate processing of all later valid packets.
- Extract available timestamp, IP endpoints, transport ports, protocol, and packet length.
- Handle IPv4/IPv6 and TCP/UDP/ICMP only to the extent supported and tested.
- Track parsed, skipped, malformed, and unsupported packet counts.
- Avoid storing packet payloads. If the parser library internally exposes payload bytes, do not persist or log them.
- Add fixtures with redistribution permission and document source/authorization.

### 6.2 Live interface capture
- Enable only through explicit configuration and only on an authorized interface.
- Document OS-specific capture dependencies and permissions.
- Keep elevated capture privileges separate from the web API where practical; never run the entire public-facing application as root just to capture packets.
- Show capture state and last packet/event time.
- Stop safely on shutdown and handle interface errors.
- If live capture is unavailable in the deployment environment, PCAP mode must remain usable and the limitation must be clearly reported.

### 6.3 Error policy
Use structured error categories such as `malformed_packet`, `missing_field`, `unsupported_protocol`, `invalid_timestamp`, and `capture_source_unavailable`. Include packet index/event ID when safe. Do not include payloads or secrets in logs.

## 7. Detection engine contract

### 7.1 Result schema

Each analyzed event returns one consistent result object, whether it is flagged or not.

```json
{
  "event_id": "d13c6c38-2f1e-4e0c-98db-c8f14790d842",
  "decision": "review",
  "severity": "medium",
  "reasons": [
    {
      "kind": "rule",
      "rule_id": "CONNECTION_RATE_HIGH",
      "message": "Connection rate exceeded the configured threshold"
    }
  ],
  "model_version": null,
  "rule_config_version": "rules-v1",
  "score": null,
  "score_semantics": null,
  "analyzed_at": "2026-10-28T10:00:02Z"
}
```

Allowed decisions should be defined centrally, for example `normal`, `review`, `unsupported`, and `error`. Severity should use a fixed enum such as `low`, `medium`, `high`, `critical`; reserve `critical` for explicit high-confidence rules and do not infer it solely from an uncalibrated model score.

### 7.2 Rule behavior
- **Connection-rate rule:** count distinct or total connections for a defined source/window; configure threshold and exclusions.
- **Possible port-scan rule:** detect a source contacting many distinct destination ports or hosts in a time window; configure window and cardinality thresholds.
- Document whether a rule uses packet-level or flow-level events. Packet-level counts and flow-level counts are not interchangeable.
- Use bounded in-memory state for local/demo mode or a documented persistent store for deployed multi-process operation.
- Configure state expiry and prevent unbounded memory growth.
- Add allowlists/exclusions only through explicit configuration and log configuration changes.
- Test benign services that generate many connections to measure false positives.

### 7.3 Optional ML
- Choose a dataset only after the live source and normalized fields are defined.
- Use a shared versioned feature pipeline for training and inference.
- Split data before fitting transforms; prevent session/time/host leakage where feasible.
- Report confusion matrix, precision, recall, F1, PR-AUC where appropriate, per-class metrics, and false positives per time window.
- Pin and checksum model artifacts; load only artifacts produced by a trusted training pipeline.
- Store model version, feature schema version, training commit, dataset manifest, evaluation report, and score semantics with predictions.
- A model score is a ranking signal unless calibration is validated.
- Do not block or modify traffic based on model output.

## 8. Alert management and database

### 8.1 Suggested entities

| Entity | Core fields | Constraints / notes |
|---|---|---|
| `flow_events` | id, event_id, sensor_id, observed_at, received_at, schema_version, metadata | Unique event key scoped to sensor; index time and sensor |
| `predictions` | id, event_id, model_version, score, decision, latency_ms | Preserve model/version provenance |
| `alerts` | id, dedup_key, severity, status, first_seen_at, last_seen_at, count, summary | Index status/severity/time; bounded dedup window |
| `alert_events` | alert_id, event_id | Link grouped events to an alert |
| `audit_events` | id, actor, action, target, timestamp, safe_metadata | Never store credentials or tokens |
| `sensors` | id, name, status, last_seen_at, credential_verifier, revoked_at | Do not return credential secret after creation |
| `users` | id, identity, password_hash or identity-provider subject, role, active | No plaintext passwords |
| `model_registry` | version, artifact_digest, schema_version, metrics, status | Controlled candidate/active/retired lifecycle |

### 8.2 Persistence rules
- Use PostgreSQL in production, with migrations and a least-privilege application role.
- SQLite is suitable for isolated unit/integration tests or a single-user local demo; do not assume it is suitable for concurrent production ingestion.
- CSV should be used for exports, fixtures, and reports only.
- Use a unique constraint to enforce event idempotency, not only an in-memory check.
- Alert deduplication key should be documented and stable (for example, rule ID + relevant source/target dimensions + time bucket, adjusted to the rule).
- Use transactions for event/prediction/alert writes that must remain consistent.
- On storage failure, return/record a clear failure; do not acknowledge durable success when the record was not committed.
- Apply retention and deletion policies and index only the fields needed for common queries.

## 9. API design

Proposed API routes; final naming can be adjusted before implementation, but route contracts must be documented and tested.

| Method / route | Purpose | Access |
|---|---|---|
| `GET /api/v1/health/live` | Process liveness | Minimal |
| `GET /api/v1/health/ready` | Database/model readiness | Internal/minimal |
| `POST /api/v1/ingest/events` | Submit normalized events from an authenticated sensor | Sensor identity |
| `GET /api/v1/summary` | Counts and chart aggregates | Authenticated user |
| `GET /api/v1/events` | Paginated event search/filter | Authenticated user |
| `GET /api/v1/alerts` | Paginated alert search/filter | Authenticated user |
| `GET /api/v1/alerts/{alert_id}` | Alert details and evidence | Authenticated user |
| `PATCH /api/v1/alerts/{alert_id}` | Change disposition/add analyst note | Analyst/admin |
| `GET /api/v1/sensors` | Capture/forwarder health | Operator/admin |
| `GET /api/v1/models/active` | Active model metadata | Operator/admin |

### API constraints
- Use Pydantic request/response models and explicit schema versions.
- Apply body-size limits, batch limits, timeouts, and rate limits.
- Use bounded pagination and stable sorting; do not expose unbounded query endpoints.
- Validate timestamps, IPs, port ranges, enum values, and text lengths.
- Use server-side role checks for all protected operations.
- Return safe error codes; do not return stack traces or secrets.
- For sensor ingestion, implement authentication, revocation, idempotency, and quotas.

## 10. Dashboard requirements

The production dashboard uses React + TypeScript and the authenticated API.

Required views:
- **Overview:** event/flow counts, alert counts, severity/protocol distributions, timeline, capture/sensor health, model status.
- **Alerts:** paginated list, severity, status, observed time, source/destination when available, reason/rule, model version.
- **Alert detail:** evidence, related events, score semantics, rule/model version, disposition history.
- **Events/flows:** filters by time, source/destination IP, protocol, alert type, severity, and status where relevant.
- **Operations/status:** last capture event, parser errors, rejected records, database/API health, active model.
- **Reporting:** export permitted summary data and produce sanitized charts/screenshots for the project report.

Streamlit may be used for a local demonstration or quick evaluation tool only if deliberately selected. Avoid maintaining duplicate dashboards unless a concrete need is established.

## 11. Security requirements

- Capture only on explicitly authorized networks/interfaces and use authorized PCAPs.
- Keep payload capture/retention disabled by default.
- Use TLS in deployment and authenticate sensors and dashboard users.
- Use vetted authentication libraries or an established identity provider; do not invent cryptography.
- Enforce role-based authorization on the server for each protected operation.
- Hash local passwords with a modern password hashing algorithm if local passwords are used.
- Restrict CORS to the actual dashboard origin; avoid wildcard credentialed CORS.
- Use secure session cookies and CSRF protection where cookie-based sessions require it.
- Store secrets in deployment secret injection; `.env.example` contains placeholders only.
- Keep PostgreSQL, metrics, and internal health details off the public internet.
- Apply rate limits, file-size limits, request timeouts, and safe parser error handling.
- Use parameterized queries/ORM safely and migration scripts.
- Run containers as non-root where possible; pin dependencies and scan source/dependencies/images.
- Redact credentials, tokens, and unnecessary traffic data from logs.
- Verify model artifact provenance and digest; never load arbitrary user-supplied serialized models.

## 12. Configuration

Use environment variables for deployment-specific values and a versioned rules file for detection thresholds. Example names:

```dotenv
APP_ENV=development
DATABASE_URL=postgresql://USER:PASSWORD@DB_HOST:5432/sentinelnids
SENSOR_ID=lab-sensor-01
INGESTION_TOKEN=<inject-through-secret-management>
MODEL_PATH=/app/model/model-artifact
MODEL_VERSION=flow-v1.0.0
RULE_CONFIG_PATH=/app/config/rules.yaml
LOG_LEVEL=INFO
MAX_PCAP_SIZE_MB=250
MAX_INGEST_BATCH_SIZE=500
```

These are illustrative placeholders. Do not commit real secrets. Avoid putting tokens in frontend environment variables or logs. Production configuration must be validated at startup, and unsafe defaults must not silently enable public capture or unauthenticated ingestion.

Example rules configuration:

```yaml
version: "rules-v1"
connection_rate:
  enabled: true
  window_seconds: 60
  threshold: 100
  severity: medium
port_scan:
  enabled: true
  window_seconds: 60
  distinct_destination_ports_threshold: 20
  severity: high
```

The numbers above are example starting values only. They must be tuned using representative authorized traffic and documented before being treated as operational thresholds.

## 13. Testing strategy

### Unit tests
- PCAP parsing and field extraction.
- Missing fields, malformed/truncated packets, invalid timestamps, unsupported protocols.
- Normalization units and schema version.
- Connection-rate and port-scan thresholds, windows, expiry, and exclusions.
- ML feature transformations and schema parity if ML is included.
- Alert deduplication, state transitions, and severity mapping.

### Integration tests
- PCAP fixture -> normalized events -> detection -> database -> alert API.
- Database unavailable, transaction failure, duplicate event, and migration behavior.
- API authentication, authorization, request limits, and validation.
- Dashboard filters and API pagination.

### End-to-end tests
- Process an authorized benign fixture and confirm expected non-alert behavior.
- Process a controlled suspicious-pattern fixture and confirm expected rule result and visible alert.
- Verify timestamps, reasons, event IDs, severity, and rule/model version.
- Measure end-to-end latency and throughput under a documented workload.
- Confirm malformed events do not stop subsequent valid events.

### ML evaluation
Where labels are available, report dataset provenance, split method, class distribution, confusion matrix, precision, recall, F1, PR-AUC where appropriate, per-class metrics, false positives per time window, and known limitations. Never report training accuracy as generalization performance.

## 14. Observability and operational behavior

Track:
- packets/events read, accepted, rejected, malformed, and unsupported;
- capture status and last-event timestamp;
- rule matches by rule ID and alert rate;
- duplicate events and deduplicated alerts;
- inference failures, feature mismatch, active model version, and latency;
- API 4xx/5xx, request latency, DB connectivity/latency, CPU/memory/disk;
- backup age and last successful restore test.

Use structured logs with correlation/event IDs. Avoid high-cardinality metric labels such as raw IP addresses. Never log packet payloads, passwords, sensor tokens, or session cookies.

Minimum runbooks:
1. Capture source disconnected or permission denied.
2. Malformed/unsupported input spike.
3. Database unavailable or disk pressure.
4. False-alert spike or model incompatibility.
5. Credential compromise/revocation.
6. Failed deployment/model rollout and rollback.
7. Backup restore and validation.

## 15. Deployment

### Local development
- Use synthetic fixtures or authorized PCAP files.
- Use a local database and fake/test credentials.
- Run tests, linting, and type checks before integration.

### Staging
- Use production-like containers and an isolated database.
- Verify TLS, auth, role boundaries, schema migrations, rate limits, capture behavior, metrics, backups, and rollback.
- Start ML scoring in shadow/observe-only mode and review sampled detections.

### Production
- Deploy to a Linux VM/cloud VM or suitable managed environment.
- Expose only necessary web ports; restrict SSH and administrative access.
- Keep the database private and use TLS for remote database connections.
- Use immutable container images and versioned configuration.
- Inject secrets through the host/deployment secret mechanism.
- Schedule encrypted backups and test restore into an isolated environment.
- Configure health checks and notifications for sensor silence, service failures, disk pressure, and backup failures.
- Record the active application image, schema version, rule configuration version, and model version for every release.
- Roll back application and model changes independently where practical.

A single VM is not high availability. Availability targets and recovery objectives must be measured and documented for the chosen host.

## 16. Performance and acceptance testing

Do not invent throughput or accuracy. Establish a baseline with:
- documented CPU/RAM/storage and software versions;
- fixture size, event/packet count, protocol mix, and test duration;
- sustained and burst events/flows per second;
- parsing and end-to-end latency p50/p95;
- malformed/rejected/duplicate counts and observed event loss;
- database write/query latency and resource usage;
- rule false-positive rate against representative benign data;
- ML metrics on held-out data, if applicable.

Set performance targets after the baseline. If buffering is implemented, bound disk usage and report dropped events when the buffer is exhausted.

## 17. Implementation sequence

1. Confirm authorization, capture source, operating system, and PCAP/live-capture requirements.
2. Define normalized event schema and add fixtures/tests.
3. Implement defensive parsing and normalization.
4. Implement deterministic detection rules and result schema.
5. Implement persistence, unique constraints, alert deduplication, and error handling.
6. Add API authentication, validation, pagination, and health endpoints.
7. Build the React dashboard and reporting views.
8. Add optional ML only after training/live feature parity is proven.
9. Add end-to-end tests, metrics, deployment, backup/restore, and rollback.
10. Run staging in observe-only mode; publish measured evaluation and limitations before production sign-off.

## 18. Definition of done

- A clean environment can run the app and tests using documented commands.
- Authorized PCAP parsing works; optional live capture documents required permissions and limitations.
- Malformed input does not crash the entire processing pipeline.
- Every supported event gets a consistent detection result.
- Rules are configurable, versioned, and tested.
- Persistence is idempotent where specified and storage failures are observable.
- Dashboard filters, charts, and alert details work with pagination.
- ML, if included, has reproducible held-out evaluation and verified feature parity.
- Security, integration, and end-to-end tests pass.
- Deployment, monitoring, backup/restore, and rollback instructions are tested.
- The final demo/report includes screenshots, architecture, commands, evaluation, measured latency/throughput, and limitations.
