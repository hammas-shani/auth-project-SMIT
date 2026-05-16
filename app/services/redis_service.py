"""
Redis Blacklist Service — Core-Auth System
==========================================
Implements "Stateful Token Invalidation" from Spec §2.2.

Why Redis for Blacklisting?
----------------------------
Standard JWTs are stateless — the server cannot "cancel" a token once issued
because it has no record of which tokens exist. The only built-in protection
is the expiry ("exp") claim.

To implement real logout (immediate revocation), we use Redis as a blacklist:

    Logout Flow:
    ┌──────────────────────────────────────────────────────────┐
    │  User logs out with their access token                   │
    │    → Extract JTI (unique UUID) from token payload       │
    │    → Calculate remaining TTL = token_exp - current_time │
    │    → Store key "blacklist:{jti}" in Redis with TTL      │
    │    → Redis auto-deletes the entry when TTL reaches zero │
    └──────────────────────────────────────────────────────────┘

    Next Request with the Same Token:
    ┌──────────────────────────────────────────────────────────┐
    │  Request arrives with the revoked access token           │
    │    → Decode token → Extract JTI                         │
    │    → Check Redis: does "blacklist:{jti}" exist?         │
    │    → YES → Return HTTP 401 Unauthorized immediately      │
    │    → NO  → Token is clean, proceed to route handler     │
    └──────────────────────────────────────────────────────────┘

Connection Pool — Spec §2.1:
    The Redis client is created ONCE at application startup (main.py lifespan).
    All requests reuse the same connection pool — no per-request reconnection.
    This satisfies "Pool Lifecycle Management" of Spec §2.1.
"""

import redis.asyncio as aioredis

from app.utils.config import settings


# ── Global Redis Client ───────────────────────────────────────────────────────
# Initialized to None at module load.
# Set to a live Redis client by init_redis() at application startup.
# All functions in this module reference this single shared client.
redis_client: aioredis.Redis | None = None


# =============================================================================
# LIFECYCLE FUNCTIONS — Called from app/main.py lifespan
# =============================================================================


async def init_redis() -> None:
    """
    Initialize the async Redis connection pool at application startup.

    Called once from the lifespan context manager in main.py BEFORE
    the application starts accepting requests.

    Creates a connection pool (not a single connection) so multiple
    concurrent requests can interact with Redis simultaneously without
    blocking each other.

    Pool settings:
        decode_responses=True → Redis returns str instead of bytes (cleaner)
        max_connections=10    → Limits concurrent Redis connections in the pool

    Spec §2.1: "External fast-storage systems must configure state connections
    using application start/stop lifespans instead of opening connections
    per-request."
    """
    global redis_client
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,  # Returns str, not bytes
        max_connections=10,  # Connection pool upper bound
    )


async def close_redis() -> None:
    """
    Gracefully close the Redis connection pool at application shutdown.

    Called from the lifespan context manager in main.py AFTER yield
    (i.e., after the application stops accepting new requests).

    Ensures all in-flight Redis operations complete before the pool is torn
    down. Prevents "Connection reset by peer" errors during graceful shutdown.
    """
    global redis_client
    if redis_client:
        await redis_client.aclose()
        redis_client = None


# =============================================================================
# BLACKLIST OPERATIONS
# =============================================================================


async def blacklist_token(jti: str, ttl_seconds: int) -> None:
    """
    Add a token's JTI to the Redis blacklist with an auto-expiring TTL.

    Key format : "blacklist:{jti}"   e.g. "blacklist:3f2e1a-uuid4-..."
    Value      : "1"                 (minimal — only key existence matters)
    TTL        : ttl_seconds         (remaining life of the original token)

    Self-Cleaning Design:
        The TTL is set to exactly the token's remaining valid lifespan.
        Example: Token expires in 13 minutes → TTL = 780 seconds.
        After 780 seconds, Redis deletes the entry automatically.
        Result: The blacklist never grows unboundedly — no manual purging.
        The entry disappears at exactly the moment the token would have
        expired anyway, so there is zero wasted memory.

    Args:
        jti:         Unique JWT ID (UUID4) from the token payload.
        ttl_seconds: Seconds until the token naturally expires.

    Raises:
        RuntimeError: If Redis client was not initialized (startup failure).
    """
    if redis_client is None:
        raise RuntimeError(
            "Redis client is not initialized. Verify app startup completed."
        )

    await redis_client.setex(
        name=f"blacklist:{jti}",  # Namespaced key to avoid collisions
        time=ttl_seconds,  # Auto-delete after this many seconds
        value="1",  # Minimal value — existence is what matters
    )


async def is_blacklisted(jti: str) -> bool:
    """
    Check whether a token's JTI exists in the Redis blacklist.

    Called on EVERY protected route request inside get_current_user().
    Redis EXISTS is an O(1) operation — sub-millisecond latency.
    This check adds virtually no overhead to each request.

    Flow:
        1. Construct key: "blacklist:{jti}"
        2. Call Redis EXISTS — returns 1 if key exists, 0 if not
        3. Return True (blocked) or False (clean)

    Args:
        jti: Unique JWT ID (UUID4) extracted from the incoming request token.

    Returns:
        True  → JTI is blacklisted → Deny the request (HTTP 401)
        False → JTI is not in blacklist → Allow the request to proceed

    Raises:
        RuntimeError: If Redis client was not initialized (startup failure).
    """
    if redis_client is None:
        raise RuntimeError(
            "Redis client is not initialized. Verify app startup completed."
        )

    result = await redis_client.exists(f"blacklist:{jti}")
    # redis.exists() returns an integer: 1 = key exists, 0 = key absent
    return result == 1
