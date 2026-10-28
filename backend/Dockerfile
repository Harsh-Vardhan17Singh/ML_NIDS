# ==============================================================================
# SentinelNIDS Backend Dockerfile
# Production-ready multi-stage Python container with non-root security context
# ==============================================================================

FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies for C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime stage
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime libpq and curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

# Copy installed python wheels from builder
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Copy application directories
COPY --chown=appuser:appuser backend/ /app/backend/
COPY --chown=appuser:appuser sensor/ /app/sensor/
COPY --chown=appuser:appuser detection/ /app/detection/
COPY --chown=appuser:appuser ml/artifacts/ /app/ml/artifacts/

# Switch to unprivileged user
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
