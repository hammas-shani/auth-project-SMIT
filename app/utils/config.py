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

    # -- Database --------------------------------------------------------------
    # Local dev  : sqlite+aiosqlite:///./test.db
    # Production : postgresql+asyncpg://user:pass@host:5432/db
    DATABASE_URL: str

    # -- JWT Access Token Secret (short-lived: 15 minutes) ---------------------
    # Signs and verifies ACCESS tokens ONLY.
    # Must be at least 32 random characters. Never share or commit this value.
    SECRET_KEY: str

    # -- JWT Refresh Token Secret (long-lived: 7 days) ------------------------
    # Signs and verifies REFRESH tokens ONLY.
    # MUST be completely different from SECRET_KEY — this is the core of
    # the dual-token key-separation requirement in Spec §2.2.
    REFRESH_SECRET_KEY: str

    # -- JWT Algorithm --------------------------------------------------------
    # HS256 = HMAC-SHA256. Standard, fast, required by Spec §2.2.
    ALGORITHM: str = "HS256"

    # -- Token Expiry Settings ------------------------------------------------
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Access token lifespan
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # Refresh token lifespan

    # -- Redis URL (In-Memory Blacklist Layer) ---------------------------------
    # Redis stores blacklisted token JTIs (JWT IDs) after logout.
    # Each Redis entry has a TTL equal to the token's remaining lifespan,
    # so the blacklist self-cleans — no manual purging needed.
    REDIS_URL: str = "redis://localhost:6379"

    class Config:
        # Load values from the .env file in the project root
        env_file = ".env"


# Single shared settings instance — imported by all other modules.
# Created ONCE at startup; Pydantic validates all fields immediately.
settings = Settings()
