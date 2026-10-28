# SentinelNIDS — Product Requirements Document (PRD)

**Version:** 1.0  
**Last updated:** 28 October 2026  
**Status:** Proposed product specification  
**Product:** Machine Learning–Based Network Intrusion Detection System (ML-NIDS)

> This document defines **what** SentinelNIDS must do and how product acceptance will be judged. It is a target specification, not a claim that the system has already been implemented or validated.

## 1. Executive summary

SentinelNIDS is a defensive network monitoring application that analyzes authorized packet captures or live traffic from an explicitly authorized test interface, normalizes observed traffic into event/flow records, detects suspicious connection patterns, optionally scores compatible records with a trained ML model, stores events and alerts, and presents findings in a dashboard.

The first release is passive and alert-only. It must not block traffic, modify firewalls, inject packets, perform active scanning, or claim to detect every attack. The product must be useful both as a reproducible academic demonstration and as a deployable service with appropriate security and operational controls.

## 2. Problem statement

An ML classifier running on a static dataset is not by itself a usable intrusion detection system. A working product needs a reliable path from authorized traffic capture to validated records, consistent detection results, persistent alerts, analyst review, evaluation, and operational monitoring. It must also handle malformed packets, missing fields, duplicate events, storage failures, and differences between training data and live telemetry.

## 3. Goals

- Capture or parse traffic only from authorized interfaces and approved PCAP fixtures.
- Extract and normalize relevant metadata, including timestamps, IP addresses, ports, protocol, packet size and/or flow-level byte/packet counts where available.
- Detect suspicious connection rates and possible port scans with configurable deterministic rules.
- Optionally include an ML anomaly-detection or supervised model only when its input features match the live pipeline and evaluation is documented.
- Generate consistent, traceable event and alert records with event IDs, UTC timestamps, severity, reasons, and rule/model version.
- Persist records reliably, prevent duplicate events/alerts where practical, and handle storage errors visibly.
- Present alert summaries, distributions, timelines, filters, sensor/model status, and investigation details in an authenticated dashboard.
- Provide tests, evaluation results, deployment documentation, and a repeatable final demonstration.
- Support secure deployment and production operations without overengineering the MVP.

## 4. Non-goals for v1

- Automatic blocking, firewall changes, active response, or packet injection.
- Monitoring networks without explicit authorization.
- Deep packet inspection or retention of packet payloads by default.
- Guaranteeing detection of every attack, zero-days, or attribution of an attacker.
- Treating a model score as a confirmed attack or as a probability unless calibration is validated.
- Building a full SIEM/SOAR, multi-tenant SaaS, Kubernetes platform, or a large microservice fleet.
- Maintaining both React and Streamlit dashboards in production. React + TypeScript is the default production UI; Streamlit is optional for a local demo if deliberately selected.

## 5. Target users and use cases

### Target users
- **Lab operator:** configures the authorized capture source and verifies capture health.
- **Security analyst/student:** reviews suspicious events, understands detection reasons, and records a disposition.
- **Project evaluator:** checks that the end-to-end pipeline works and reviews reproducible evaluation results.
- **System maintainer:** deploys the service, manages configuration, investigates failures, and restores service.

### Core use cases
1. Parse an authorized PCAP file and produce normalized records without crashing on malformed packets.
2. Capture traffic from an explicitly authorized interface when the operating system and permissions permit it.
3. Detect suspicious connection bursts or possible port scans using configurable thresholds.
4. Score supported records using an optional compatible ML model.
5. Persist an event and create a deduplicated alert when detection criteria are met.
6. Review alerts in the dashboard and filter by time, IP, protocol, alert type, severity, and status.
7. Run tests against labeled data and report classification metrics, false-alert burden, latency, throughput, and limitations.
8. Demonstrate a complete authorized test from capture/fixture through a visible dashboard alert.

## 6. Product scope and requirements

### 6.1 Capture and normalization

**Requirements**
- Support offline parsing of approved PCAP files.
- Support live capture only on an explicitly authorized test interface and only where required permissions and capture libraries are available.
- Extract available source/destination IPs, source/destination ports, protocol, packet size, and timestamps.
- Where flow aggregation is implemented, calculate documented flow fields such as duration, packet counts, and byte counts.
- Normalize field names, units, timestamps, protocol representation, and missing-value behavior.
- Handle truncated/malformed packets, unsupported protocols, missing fields, invalid timestamps, and parser exceptions without terminating the entire processing run.
- Do not upload or retain raw payloads by default. PCAP fixtures must be authorized and sanitized where needed.

**Acceptance criteria**
- A known fixture produces expected normalized fields.
- Malformed and incomplete records are rejected, skipped, or marked according to documented policy; the parser continues processing subsequent valid records.
- Tests cover IPv4/IPv6 if claimed, TCP/UDP/ICMP as supported, missing transport fields, invalid timestamps, and truncated packets.
- A capture report lists extracted fields, units, unsupported cases, and limitations.

### 6.2 Detection engine

**Requirements**
- Detect suspicious connection rates and possible port scanning with deterministic rules.
- Make thresholds, time windows, exclusions, and severity mapping configurable.
- Return a consistent detection result for every analyzed flow/event, including event ID, timestamp, decision, severity if applicable, detection reasons/rule IDs, and rule/model version.
- Keep rule-based detections distinguishable from ML predictions.
- Optionally use ML only after feature compatibility with training data is proven.
- Test normal high-volume services and boundary cases to reduce false positives.

**Acceptance criteria**
- Unit tests cover threshold boundaries, repeated events, burst behavior, port-scan patterns, benign high-volume patterns, and missing fields.
- Identical inputs and configuration yield deterministic rule results.
- Configuration changes are validated and versioned.
- Model evaluation, if present, uses held-out data and documents dataset provenance, split method, and metrics.

### 6.3 Events, alerts, and persistence

**Requirements**
- Define stable event, flow, prediction, alert, and audit fields.
- Store event IDs, observed and received timestamps in UTC, source metadata where collected, severity, detection reasons, status, and rule/model version.
- Deduplicate using a stable event ID and a documented alert grouping window where practical.
- Handle database unavailable, constraint violations, disk/storage issues, and transaction errors explicitly.
- Support alert review states such as `open`, `investigating`, `true_positive`, `false_positive`, and `unresolved` if the UI supports review.
- Record who changed an alert disposition and when.
- Use PostgreSQL as the production source of truth. SQLite may be used for local development or isolated tests; CSV is for exports, fixtures, and reports—not concurrent production ingestion.

**Acceptance criteria**
- Replaying the same event does not create duplicate event rows or duplicate alerts within the defined deduplication policy.
- Storage failures create a visible operational error and do not silently report successful persistence.
- Database schema changes are managed by migrations.
- Logs do not contain passwords, API keys, or unnecessary sensitive traffic data.

### 6.4 Dashboard and reporting

**Requirements**
- Display event/flow totals, alert counts, severity distribution, protocol distribution, event timelines, sensor/capture health, and model status where applicable.
- Provide search and filtering by time range, source/destination IP where collected, protocol, alert type/rule, severity, and review status.
- Show event/alert detail with timestamps and timezone, detection reason, severity, related evidence, and rule/model version.
- Distinguish an unreviewed detection from a confirmed incident.
- Use server-side pagination and bounded time ranges.
- Produce sanitized screenshots and summary charts for the final demonstration, with captions describing what the charts measure.

**Acceptance criteria**
- Filters combine correctly and pagination does not repeat or omit results under stable data.
- Loading, empty, stale, and error states are visible.
- Charts are derived from stored data and use clearly labeled axes/time ranges.
- The dashboard never displays unavailable data as if it were zero.

### 6.5 Integration, testing, and evaluation

**Requirements**
- Integrate capture, normalization, detection, persistence, API, and dashboard using one documented event contract.
- Include unit, integration, and end-to-end tests.
- Compare predictions against labeled held-out data where labels are available.
- Report confusion matrix, precision, recall, F1, PR-AUC where suitable, per-class results where relevant, and false positives/alerts per time window.
- Measure end-to-end detection latency, throughput in events/flows per second, malformed/rejected input counts, duplicate handling, and observed event loss under a documented workload.
- Document dataset source, license/terms, label meaning, class distribution, split strategy, environment, commands, and limitations.
- Never invent accuracy figures or set an arbitrary accuracy claim before measuring a baseline.

**Acceptance criteria**
- A documented command runs automated tests from a clean checkout.
- An end-to-end test proves an authorized PCAP or test event can produce a stored result and visible alert when expected.
- Evaluation results can be reproduced from documented inputs and commands.
- The final report distinguishes offline benchmark performance from live operational performance.

## 7. Functional requirements summary

| ID | Requirement | Priority |
|---|---|---|
| PR-01 | Parse authorized PCAP files | Must |
| PR-02 | Capture from an authorized interface where supported | Must for live-capture demo; otherwise documented limitation |
| PR-03 | Normalize metadata and handle malformed/missing fields | Must |
| PR-04 | Detect suspicious connection rates | Must |
| PR-05 | Detect possible port scans | Must |
| PR-06 | Produce consistent detection results and reasons | Must |
| PR-07 | Optional ML inference with feature parity and evaluation | Should; mandatory only if ML is the agreed project requirement |
| PR-08 | Persist events and alerts with UTC timestamps and IDs | Must |
| PR-09 | Deduplicate repeated events/alerts where practical | Must |
| PR-10 | Dashboard summary, timeline, search and filters | Must |
| PR-11 | Unit, integration and end-to-end tests | Must |
| PR-12 | Accuracy-related metrics, latency and throughput report | Must |
| PR-13 | Secure deployment, health checks, backups and recovery docs | Must for production deployment |
| PR-14 | Sanitized screenshots and final demonstration package | Must |

## 8. Non-functional requirements

| Area | Requirement |
|---|---|
| Security | Authentication and server-side authorization for protected functions; TLS in deployment; secrets excluded from Git; least-privilege database credentials. |
| Input safety | Bound PCAP size and ingestion batch size; validate schemas; handle malformed input without process crashes. |
| Reliability | Explicitly report rejected records, storage failures, and capture failures; do not silently discard data. |
| Performance | Measure throughput and p50/p95 latency under a documented test workload; set final targets after baseline measurements. |
| Privacy | Monitor only authorized networks; collect metadata by default; define retention and deletion behavior. |
| Maintainability | Versioned schemas/configuration, automated tests, migrations, reproducible environment, and clear setup instructions. |
| Observability | Structured logs, health/readiness checks, capture status, error counts, inference latency, alert volume, database health, and backup status. |
| Accessibility/usability | Readable charts, keyboard-usable controls, responsive layout, and explicit loading/error states. |
| Recoverability | Document backups and test restoration; define RPO/RTO based on hosting and project needs. |

## 9. Security and privacy constraints

- Use the system only on networks and PCAP files the operator owns or has explicit permission to analyze.
- Keep live capture passive and alert-only.
- Disable payload retention by default.
- Authenticate sensor/API traffic and protect dashboard accounts.
- Validate all input; enforce request, file, and batch limits.
- Restrict the database, metrics, and internal endpoints from public exposure.
- Store credentials in environment/secret management, not source code or frontend bundles.
- Use parameterized database access and a vetted authentication/session implementation.
- Redact secrets from logs and define telemetry retention.
- Treat uploaded model artifacts as trusted supply-chain inputs only; verify provenance and checksums.

## 10. MVP acceptance gates

The MVP is accepted when:
1. A valid authorized PCAP can be parsed and normalized.
2. Invalid/malformed packet cases are handled without crashing the entire pipeline.
3. Rule-based connection-rate and port-scan tests pass.
4. A consistent detection result is emitted for every supported analyzed event.
5. Events and alerts persist with IDs, UTC timestamps, reasons, severity, and rule/model version as applicable.
6. Duplicate handling and storage failure paths are tested.
7. The dashboard shows counts, severity/protocol charts, timeline, search, and filters.
8. Unit, integration, and end-to-end tests pass.
9. A report documents ML metrics where applicable, plus latency, throughput, false-alert burden, and limitations.
10. Deployment documentation explains authorized capture, configuration, secrets, health checks, backups, and rollback.
11. No automatic blocking or unapproved network activity is performed.

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| PCAP fields do not match model features | Invalid predictions | Versioned feature contract and offline/live parity tests |
| Malformed packets crash processing | Lost events | Defensive parsing and malformed-input tests |
| Rule thresholds are too aggressive | Alert fatigue | Tune on representative benign traffic; measure alerts/time |
| Dataset leakage or unrealistic labels | Inflated metrics | Group/time-aware splits and transparent dataset report |
| Duplicate events create alert floods | Poor usability | Unique event IDs and documented deduplication windows |
| SQLite/CSV used for concurrent production writes | Locking or data integrity problems | PostgreSQL production source of truth |
| Sensor is not observing relevant traffic | Blind spots | Verify interface/mirror placement and report capture limitations |
| Sensitive telemetry leaks | Privacy/security incident | Authorization, minimization, TLS, RBAC, retention, redacted logs |
| Single server fails | Service downtime | Backups, restore drills, health monitoring, rollback plan |

## 12. Delivery roadmap

| Phase | Outcome | Exit condition |
|---|---|---|
| 0. Scope | Authorized test environment, capture source, event schema | Sample records and fields documented |
| 1. Capture | PCAP parser and optional live capture | Fixtures and malformed-input tests pass |
| 2. Detection | Rules, configuration, optional ML baseline | Deterministic rule tests and model evaluation pass |
| 3. Persistence | Event/alert schema, deduplication, storage errors | Records survive restart; duplicate behavior verified |
| 4. Dashboard | Summary, alert details, filters, charts | An analyst can find and review a test alert |
| 5. Integration | Full pipeline and test suite | End-to-end test passes |
| 6. Production hardening | TLS, auth, monitoring, backups, deployment docs | Staging checks and restore/rollback drill pass |
| 7. Evaluation/demo | Metrics, screenshots, report | Results are reproducible and limitations documented |

## 13. Definition of done

- A clean checkout can be configured and tested using documented instructions.
- Only authorized capture sources are used.
- Capture, detection, storage, and dashboard modules use a stable event contract.
- Tests cover normal, malformed, missing, duplicate, and failure scenarios.
- ML results, if included, are reproducible and not overstated.
- Latency, throughput, false alerts, and observed event loss are measured.
- Production secrets are not committed; public endpoints and database access are appropriately restricted.
- Backup/restore and rollback procedures are documented and tested.
- The final report includes architecture, setup, tests, results, screenshots, limitations, and future work.
