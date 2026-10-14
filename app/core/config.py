"""ThreatLens Configuration and Settings."""

from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "threatlens-insecure-secret-key-change-in-production-min32chars"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    ALGORITHM: str = "HS256"

    # Server & Networking
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatlens.db"
    DB_ECHO: bool = False

    # Ingestion Pipeline
    MAX_PAYLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    DEFAULT_BATCH_SIZE: int = 500
    MAX_BATCH_SIZE: int = 2000
    WORKER_CONCURRENCY: int = 4
    MAX_INGESTION_RETRIES: int = 3

    # Groq AI Investigation
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama3-70b-8192"
    GROQ_TIMEOUT_SECONDS: float = 30.0

    # Default Seed / Admin Credentials
    ADMIN_USERNAME: str = "soc_admin"
    ADMIN_EMAIL: str = "admin@threatlens.internal"
    ADMIN_PASSWORD: str = "ThreatLens@Admin2026!"

    @property
    def is_ai_enabled(self) -> bool:
        return bool(self.GROQ_API_KEY and self.GROQ_API_KEY.strip())


settings = Settings()
