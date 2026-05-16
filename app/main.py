"""
Application Entry Point — Core-Auth System
==========================================
Bootstraps the FastAPI application and manages all shared resource lifecycles.

Lifespan Context Manager (Spec §2.1):
--------------------------------------
FastAPI's lifespan replaces the deprecated @app.on_event("startup") pattern.
It manages the full lifecycle of ALL shared resources in one place:

    STARTUP (code before yield):
        1. Create all SQLAlchemy database tables (async, non-blocking)
        2. Initialize the Redis connection pool (async, non-blocking)

    APPLICATION RUNS (at yield):
        → The app accepts and handles all incoming HTTP requests

    SHUTDOWN (code after yield):
        3. Close the Redis connection pool (releases all connections)
        4. Dispose the SQLAlchemy engine (releases all DB connections)

This pattern satisfies Spec §2.1 "Pool Lifecycle Management" — database and
Redis connections are established ONCE at startup and reused across all
requests via dependency injection. No per-request reconnection.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database.db import engine, Base
from app.routes.auth import router as auth_router
from app.services.redis_service import init_redis, close_redis


# ── Lifespan Context Manager ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages startup and shutdown of all shared application resources.

    Everything BEFORE yield → runs once at startup (before first request).
    Everything AFTER  yield → runs once at shutdown (after last request).

    Using a single lifespan function (instead of separate on_event handlers)
    ensures startup and shutdown logic stays paired and readable.
    """
    # --- STARTUP ---------------------------------------------------------------

    # 1. Create all database tables defined in app/models/users.py.
    #    "create_all" is idempotent — if tables already exist, it skips them.
    #    Uses the async engine: non-blocking, runs entirely on the event loop.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created / verified")

    # 2. Initialize the Redis connection pool.
    #    Creates the pool now so every subsequent request reuses the same
    #    connections instead of opening a new one per request.
    await init_redis()
    print("✅ Redis connection pool initialized")

    # --- APPLICATION RUNS ------------------------------------------------------
    yield  # ← Application is live and accepting requests here

    # --- SHUTDOWN --------------------------------------------------------------

    # 3. Close the Redis pool — drains in-flight operations first.
    await close_redis()
    print("✅ Redis connection pool closed")

    # 4. Dispose the SQLAlchemy engine — releases all database connections back
    #    to the pool and then closes the pool itself.
    await engine.dispose()
    print("✅ Database engine disposed")


# ── FastAPI Application Instance ─────────────────────────────────────────────
app = FastAPI(
    title="Core-Auth System",
    description=(
        "High-performance async authentication engine. "
        "Implements dual-token JWT strategy (Spec §2.2) with Redis-backed "
        "stateful token blacklisting. Version: Core-Auth v1.4.2-Prod."
    ),
    version="1.4.2",
    lifespan=lifespan,  # Attach the lifecycle manager defined above
)


# -- Route Registration -------------------------------------------------------
# Mount all auth routes under the /auth URL prefix.
# Swagger UI at /docs groups them under the "Authentication" tag.
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])


# ── Health Check Endpoint ────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    """
    Root health check endpoint.

    Returns system status and version. Used by CI/CD pipelines and
    load balancers to verify the server is alive and responsive.
    All entry points are async (Spec §2.1 non-blocking I/O requirement).
    """
    return {
        "message": "Core Auth System Running",
        "status": "ok",
        "version": "1.4.2-Prod",
    }


# ── Local Development Entry Point ────────────────────────────────────────────
# Only executed when running: python -m app.main
# For development:   uvicorn app.main:app --reload
# For production:    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)
