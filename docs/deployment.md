# SentinelNIDS Production Deployment & Infrastructure Guide

This guide details the topology, container configuration, environment variables, security hardening, and operational routines for deploying **SentinelNIDS** across staging and production environments.

---

## 1. Architecture & Deployment Topology

SentinelNIDS employs a **defense-in-depth, three-tier containerized topology** isolated via an internal Docker bridge network with strict least-privilege exposure:

```
[ External Sensor Fleet / Zeek Forwarders ]
                    │
                    ▼ (HTTPS :443 or Mutual TLS)
 ┌──────────────────────────────────────────────────────────────┐
 │ Edge Reverse Proxy / Web Server (Nginx / Caddy)              │
 │ Container: `web` (Port 80/443 exposed)                       │
 │  - Serves static compiled React 18 + TypeScript SPA         │
 │  - Enforces Strict Security Headers (CSP, HSTS, X-Frame)     │
 │  - Terminates TLS & Proxies `/api/` -> `api:8000`            │
 └──────────────────────────────┬───────────────────────────────┘
                                │ Docker Internal Bridge (`sentinel-internal`)
 ┌──────────────────────────────▼───────────────────────────────┐
 │ Application & Detection Engine (FastAPI + Uvicorn)           │
 │ Container: `api` (Port 8000 internal only)                   │
 │  - Runs as unprivileged `appuser` (UID 1000)                │
 │  - Dual Engine: Hybrid Heuristic Rules + 71-Feature ML Model │
 │  - Real-time Alert Deduplication & Lifecycle Manager         │
 └──────────────────────────────┬───────────────────────────────┘
                                │ Docker Internal Bridge (Private - No Host Port)
 ┌──────────────────────────────▼───────────────────────────────┐
 │ Persistent Relational Store (PostgreSQL 16 Alpine)           │
 │ Container: `db` (Port 5432 internal only)                    │
 │  - Dedicated Docker Volume (`sentinel_pgdata`)               │
 │  - Isolated credentials with read/write access restricted     │
 └──────────────────────────────────────────────────────────────┘
```

---

## 2. Prerequisites

| Component | Minimum Specification | Recommended Production |
|---|---|---|
| **CPU** | 2 Cores (x86_64 or ARM64) | 4+ Cores |
| **RAM** | 4 GB | 8 GB+ (for high ingestion queues) |
| **Disk** | 20 GB SSD | 100 GB+ NVMe SSD |
| **OS** | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 | Ubuntu 24.04 LTS |
| **Docker** | Docker Engine 24.0+ & Compose v2.20+ | Docker Engine 26.0+ |

---

## 3. Environment Configuration

Copy `.env.example` to `.env` on the host:

```bash
cp .env.example .env
chmod 600 .env
```

### Key Environment Variables

```env
# Application Runtime
APP_ENV=production
LOG_LEVEL=INFO

# Relational Database
POSTGRES_DB=sentinel_nids
POSTGRES_USER=sentinel_user
POSTGRES_PASSWORD=<STRONG_RANDOM_SECRET_MIN_32_CHARS>
DATABASE_URL=postgresql://sentinel_user:${POSTGRES_PASSWORD}@db:5432/sentinel_nids

# Sensor Ingestion Authentication
SENSOR_API_KEY=<CRYPTOGRAPHICALLY_RANDOM_UUID_OR_BEARER_TOKEN>

# ML Detection Artifact Paths
ML_MODEL_PATH=/app/ml/artifacts/sentinel_model_v1.joblib
FEATURE_SCHEMA_PATH=/app/ml/artifacts/feature_schema.json
PREPROCESSOR_PATH=/app/ml/artifacts/preprocessor.joblib
LABEL_MAPPINGS_PATH=/app/ml/artifacts/label_mappings.json
ALERT_SCORE_THRESHOLD=0.65

# Web & CORS
CORS_ORIGINS=["https://nids.yourdomain.com"]
```

---

## 4. Multi-Container Orchestration (`docker-compose.yml`)

The application is deployed with standard Docker Compose:

### 4.1 Launch Services

```bash
# Build and start services in detached mode
docker compose up -d --build

# Verify container health
docker compose ps
```

### 4.2 Inspect Container Logs

```bash
# Follow backend application logs
docker compose logs -f api

# Follow web reverse proxy logs
docker compose logs -f web

# Follow database logs
docker compose logs -f db
```

---

## 5. Security Hardening Checklist

| Security Control | Implementation | Verification |
|---|---|---|
| **Zero Database Host Exposure** | PostgreSQL container `db` exposes no host ports; reachable only via `sentinel-internal` network. | `netstat -tlpn | grep 5432` returns empty. |
| **Unprivileged Runtime Execution** | Backend runs as non-root user `appuser` (UID 1000). | `docker exec sentinel-backend id` outputs `uid=1000(appuser)`. |
| **Sensor Credential Separation** | Sensors authenticate using `X-Sensor-Token` headers. Human SOC analysts authenticate with separate JWT sessions. | Sensor tokens cannot query analyst management APIs. |
| **Strict Security Headers** | Nginx emits `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin`. | `curl -I http://localhost/` verifies headers. |
| **Payload Immunity** | Architecture records flow summary statistics only; zero raw packet payloads stored on disk. | Minimizes liability and compliance risk (GDPR/HIPAA). |
| **Bounded Input Validation** | Max batch size capped at 1,000 flows per request; Pydantic enforces schema and IP bounds. | Requests exceeding limit reject with HTTP 413 / 422. |

---

## 6. Backup, Recovery & Rollback Procedures

### 6.1 Database Backup

Run periodic automated cron backups of PostgreSQL:

```bash
# Execute compressed PostgreSQL dump
docker exec -t sentinel-postgres pg_dump -U sentinel_user -F c sentinel_nids > backup_$(date +%Y%m%d_%H%M%S).dump

# Encrypt backup archive with GPG
gpg --symmetric --cipher-algo AES256 backup_*.dump
```

### 6.2 Database Disaster Recovery / Restore

```bash
# 1. Stop backend ingestion
docker compose stop api

# 2. Restore database from dump
docker exec -i sentinel-postgres pg_restore -U sentinel_user -d sentinel_nids --clean < backup_20261029.dump

# 3. Restart backend
docker compose start api
```

### 6.3 Application & Model Rollback

If an updated model or container release introduces drift or false alerts:

1. **Rollback Container Image**:
   ```bash
   docker tag sentinel-backend:v1.0.0 sentinel-backend:latest
   docker compose up -d --no-deps api
   ```
2. **Rollback Model Artifact**:
   Update `ML_MODEL_PATH` in `.env` to point to a known-stable artifact (e.g. `/app/ml/artifacts/sentinel_model_v1_backup.joblib`) and restart `api`.
