"""
VulnScan Lite — Application Configuration

Reads all settings from environment variables / .env file.
No secrets are hardcoded here.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = ""

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

    # Environment & SSRF Allowlist
    ENVIRONMENT: str = "development"
    ALLOW_DEV_TARGETS: bool = False
    DEV_TARGET_ALLOWLIST: str = "localhost:3000,localhost:8080,127.0.0.1:3000,127.0.0.1:8080"
    ALLOW_LOCAL_SCANNING: bool = False

    # Rate limiting (requests per minute per IP)
    RATE_LIMIT_REGISTER: str = "5/minute"
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_SCAN: str = "3/minute"
    RATE_LIMIT_PDF: str = "5/minute"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str) -> str:
        """Allow comma-separated CORS origins string."""
        return v

    def get_cors_origins(self) -> List[str]:
        """Return parsed list of CORS origins."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    def is_dev_allowlist_enabled(self) -> bool:
        """Development allowlist is active ONLY when explicitly enabled and NOT in production."""
        return bool(self.ALLOW_DEV_TARGETS) and self.ENVIRONMENT.lower() != "production"

    def get_dev_target_allowlist(self) -> List[str]:
        """Return parsed list of allowed development target host/port strings."""
        if not self.is_dev_allowlist_enabled():
            return []
        return [target.strip().lower() for target in self.DEV_TARGET_ALLOWLIST.split(",") if target.strip()]


# Singleton settings instance — imported throughout the app
settings = Settings()
