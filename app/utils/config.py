"""
Configuration Management — Core-Auth System
===========================================
Uses Pydantic BaseSettings to load all environment variables from .env file.
Pydantic validates every field at startup — if a required variable is missing
or has the wrong type, the app crashes immediately with a clear error message.
This "fail-fast" approach prevents misconfigured apps from accepting requests.

Dual-Secret Design (Spec §2.2):
    SECRET_KEY         → signs/verifies short-lived ACCESS tokens  (15 min)
    REFRESH_SECRET_KEY → signs/verifies long-lived REFRESH tokens  (7 days)

    Using two completely separate secrets means:
      - A compromised access secret CANNOT forge a refresh token
      - A compromised refresh secret CANNOT forge an access token
      - Token-type confusion attacks are cryptographically impossible
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All application settings, loaded from environment variables / .env file."""

    DATABASE_URL: str

    SECRET_KEY: str

    REFRESH_SECRET_KEY: str

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    REDIS_URL: str = "redis://localhost:6379"

    class Config:
        env_file = ".env"


settings = Settings()
