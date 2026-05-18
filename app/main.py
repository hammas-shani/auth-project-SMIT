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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages startup and shutdown of all shared application resources.

    Everything BEFORE yield → runs once at startup (before first request).
    Everything AFTER  yield → runs once at shutdown (after last request).

    Using a single lifespan function (instead of separate on_event handlers)
    ensures startup and shutdown logic stays paired and readable.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created / verified")

    await init_redis()
    print("✅ Redis connection pool initialized")

    yield

    await close_redis()
    print("✅ Redis connection pool closed")

    await engine.dispose()
    print("✅ Database engine disposed")


app = FastAPI(
    title="Core-Auth System",
    description=(
        "High-performance async authentication engine. "
        "Implements dual-token JWT strategy (Spec §2.2) with Redis-backed "
        "stateful token blacklisting. Version: Core-Auth v1.4.2-Prod."
    ),
    version="1.4.2",
    lifespan=lifespan,
)

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)
