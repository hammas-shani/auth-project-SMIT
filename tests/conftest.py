"""
Test Configuration & Fixtures — Core-Auth System
=================================================
This file (conftest.py) is automatically loaded by pytest before any test runs.
It defines shared fixtures available to ALL test files in the tests/ directory.

Test Isolation Strategy:
    The production app uses:
        - PostgreSQL / SQLite (real persistent DB)
        - Redis (real in-memory store)

    Tests override BOTH with isolated, in-memory equivalents:
        - SQLite in-memory DB  → created fresh for EACH test, deleted after
        - Mock Redis (AsyncMock) → simulates Redis without a running server

    This means tests run anywhere — no Redis or Postgres installation needed.
    The CI pipeline (GitHub Actions) has real containers, but locally
    the mocks handle everything.

    engine_fixture  → Async SQLAlchemy engine using in-memory SQLite
    db_session      → Fresh database session per test (tables created + dropped)
    mock_redis      → Patches the global redis_client with an AsyncMock
    client          → httpx.AsyncClient pointed at the app with all overrides

Async Mode:
    All fixtures and tests use pytest-asyncio in "auto" mode.
    This means every async def test_* is run on the asyncio event loop
    without needing @pytest.mark.asyncio on each test.
"""

import pytest_asyncio
from unittest.mock import AsyncMock

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)

from app.main import app
from app.database.db import Base, get_db
import app.services.redis_service as redis_module

pytest_plugins = ["pytest_asyncio"]

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Provide a fresh async database session for each test function.

    Scope: "function" — a completely new database is created and destroyed
    for every individual test. This guarantees full test isolation:
    no test can pollute the state seen by another test.

    Flow:
        1. Create an in-memory SQLite async engine
        2. Create all tables defined by SQLAlchemy models (Base.metadata)
        3. Yield an AsyncSession for the test to use
        4. After the test completes: drop all tables, dispose the engine
    """
    test_engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        future=True,
    )

    TestSessionLocal = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def mock_redis():
    """
    Replace the real Redis client with an AsyncMock for ALL tests.

    autouse=True means this fixture is automatically applied to every test
    without needing to declare it — no test accidentally hits a real Redis.

    How the mock works:
        - redis_module.redis_client is the global variable used by
          blacklist_token() and is_blacklisted() in redis_service.py
        - We replace it with an AsyncMock that simulates Redis behavior:
            * setex()   → does nothing (simulates successful blacklist write)
            * exists()  → returns 0 by default (simulates "not blacklisted")
        - Tests that need to simulate a blacklisted token can override
          the return value: mock_redis.exists.return_value = 1

    This fixture yields the mock so individual tests can configure it.
    """
    mock = AsyncMock()

    mock.exists = AsyncMock(return_value=0)

    mock.setex = AsyncMock(return_value=True)

    original_client = redis_module.redis_client
    redis_module.redis_client = mock

    yield mock

    redis_module.redis_client = original_client


@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    """
    Provide an async HTTP test client that uses the isolated test database.

    Uses FastAPI's dependency override mechanism to replace the real get_db
    dependency with one that returns our test database session.

    httpx.AsyncClient with ASGITransport allows us to make real HTTP requests
    to the FastAPI app without starting an actual network server.
    All requests go through the ASGI interface directly — fast and reliable.

    Args:
        db_session: The isolated in-memory database session (injected fixture).

    Yields:
        httpx.AsyncClient: Ready-to-use async HTTP client for the test.
    """

    async def override_get_db():
        """
        Dependency override: replaces the real database session with
        the isolated test session for the duration of each test.
        """
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
