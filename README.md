# SentinelNIDS — Machine Learning-Based Network Intrusion Detection System

SentinelNIDS is a defensive, flow-based network intrusion detection platform. It ingests authorized network-flow telemetry, scores flows with versioned machine-learning models, evaluates deterministic rule patterns (such as port scans and high-rate connection bursts), generates deduplicated and explainable alerts, and presents findings through an authenticated web dashboard.

---

## Key Principles & Boundaries

- **Passive Detection Only**: SentinelNIDS is an alert-only monitoring platform. It does not perform autonomous packet blocking, firewall mutations, or active counter-attacks.
- **Authorized Telemetry**: Operates exclusively on network captures, mirrors, or lab telemetry from systems owned or explicitly authorized for monitoring.
- **Metadata-First Architecture**: Inspects and models network flow metadata (IPs, ports, protocol, packet counts, byte volumes, durations) without storing raw packet payloads by default.
- **Training-Serving Parity**: Guarantees identical feature transformations and schema enforcement across offline model training and real-time inference.
- **Explainable Findings**: Alerts distinguish deterministic rule detections from ML model predictions, providing auditable decision rationales.

---

## Project Structure

```text
sentinelnids/
├── docs/                     # Specifications, TRD, PRD, architecture, implementation plan
│   ├── SentinelNIDS_OVERVIEW.md
│   ├── PRD.md
│   ├── TRD.md
│   ├── architecture.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── data-dictionary.md    # Canonical flow schema definition
│   └── telemetry-source.md   # Sensor collection & source mapping
├── data/
│   ├── raw/                  # Immutable raw datasets (gitignored)
│   ├── interim/              # Preprocessed intermediate data (gitignored)
│   ├── processed/            # Final training/testing splits (gitignored)
│   └── sample/               # Redistributable sanitized test fixtures
├── sensor/                   # Telemetry ingestion, parsing & normalization
│   ├── schemas.py            # Canonical flow Pydantic contracts
│   ├── normalize.py          # Exporter-to-canonical schema normalizer
│   ├── parser.py             # Defensive flow & log parser
│   └── packet_capture.py     # PCAP/interface reader & flow aggregator
├── detection/                # Deterministic detection rules
│   └── rules.yaml            # Configurable thresholds and windows
├── backend/                  # FastAPI REST API & PostgreSQL persistence (Phase 3)
├── frontend/                 # React + TypeScript dashboard (Phase 4)
├── ml/                       # Offline dataset preparation & model training (Phase 2)
│   ├── src/
│   └── artifacts/
├── tests/                    # Comprehensive unit and integration test suite
├── pyproject.toml            # Python build & dependency configuration
└── .env.example              # Environment variables template
```

---

## Implementation Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | **Foundation and Data Collection** (Repo setup, canonical schema, defensive parser, fixtures) | **In Progress / Current** |
| **Phase 2** | **Data Pipeline & ML Training** (Data splits, feature parity, baseline model, held-out eval) | Pending training dataset |
| **Phase 3** | **Backend, Detection Engine & Storage** (FastAPI, PostgreSQL, alert manager, auth) | Scheduled |
| **Phase 4** | **Frontend & Full-Stack Integration** (React + TypeScript dashboard, alert review) | Scheduled |
| **Phase 5** | **Hardening, Evaluation & Deployment** (Docker Compose, TLS, metrics, final report) | Scheduled |

---

## Phase 1 Quick Start

### 1. Requirements
- Python 3.11+
- Node.js 18+ (for frontend dashboard in Phase 4)

### 2. Run Verification Tests
SentinelNIDS includes a standalone test runner that verifies schema constraints, defensive parser resilience, and normalization logic:

```bash
python run_tests.py
```
Or with pytest (if installed):
```bash
pytest
```
