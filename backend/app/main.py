"""
SentinelNIDS Backend Application Entry Point.
FastAPI modular application orchestrating ingestion, detection rules,
ML inference, alert management, and analyst APIs.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.db.session import init_db
from backend.app.services.inference import InferenceService
from backend.app.api.routes import health, ingest, alerts, dashboard, sensors, model

logging.basicConfig(level=settings.LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelnids.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("Initializing database tables...")
    init_db()

    logger.info("Loading active ML model...")
    infer_service = InferenceService.get_instance()
    if infer_service.model_loaded:
        logger.info(f"ML Model {infer_service.model_version} active and ready.")
    else:
        logger.warning("ML Model artifact not found or failed to load. Operating in rule-only mode.")

    yield
    logger.info("Shutting down SentinelNIDS backend.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="SentinelNIDS Production API — Flow-Based Machine Learning Intrusion Detection",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API route modules
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(sensors.router)
app.include_router(model.router)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health/live"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)

