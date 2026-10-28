"""
Application Configuration and Environment Settings.
Loads configuration from environment variables or .env file with safe defaults.
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """SentinelNIDS Backend Configuration Settings."""
    APP_NAME: str = "SentinelNIDS Backend API"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = Field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    DEBUG: bool = Field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    LOG_LEVEL: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # Server binding
    HOST: str = Field(default_factory=lambda: os.getenv("BACKEND_HOST", "0.0.0.0"))
    PORT: int = Field(default_factory=lambda: int(os.getenv("BACKEND_PORT", "8000")))

    # Security
    SECRET_KEY: str = Field(
        default_factory=lambda: os.getenv("SECRET_KEY", "dev_secret_key_sentinelnids_super_secure_32_bytes_minimum")
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Ingestion & Sensor
    INGESTION_TOKEN: str = Field(
        default_factory=lambda: os.getenv("INGESTION_TOKEN", "sensor_ingest_token_default_dev_secret")
    )
    MAX_INGEST_BATCH_SIZE: int = Field(
        default_factory=lambda: int(os.getenv("MAX_INGEST_BATCH_SIZE", "500"))
    )

    # Database
    # Defaults to local SQLite for zero-config out-of-the-box development, easily pointed to PostgreSQL via .env
    DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./sentinelnids_dev.db")
    )

    # ML & Detection paths
    MODEL_PATH: str = Field(
        default_factory=lambda: os.getenv("MODEL_PATH", "ml/artifacts/sentinel_model_v1.joblib")
    )
    ACTIVE_MODEL_VERSION: str = "flow-v1.0.0"
    FEATURE_SCHEMA_VERSION: str = "1.0"
    RULE_CONFIG_PATH: str = Field(
        default_factory=lambda: os.getenv("RULE_CONFIG_PATH", "detection/rules.yaml")
    )

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]


settings = Settings()

