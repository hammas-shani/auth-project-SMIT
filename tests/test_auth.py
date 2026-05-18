"""
End-to-End Integration Tests — Core-Auth System
================================================
Implements the complete 6-step verification blueprint from Spec §4.1.

Every test is:
    - Async (uses pytest-asyncio auto mode — no blocking calls)
    - Isolated (in-memory SQLite + mock Redis — no shared state between tests)
    - End-to-End (sends real HTTP requests through the full FastAPI stack)

Test Execution Order (mirrors Spec §4.1):
    Step 1: test_01_register        → POST /auth/signup
    Step 2: test_02_login           → POST /auth/login
    Step 3: test_03_protected_me    → GET  /auth/me  (with valid token)
    Step 4: test_04_token_refresh   → POST /auth/refresh
    Step 5: test_05_logout          → POST /auth/logout
    Step 6: test_06_zero_trust      → GET  /auth/me  (with revoked token → 401)

Assertion Strategy:
    Each test asserts:
        1. The correct HTTP status code
        2. The exact response schema (all required fields present)
        3. Business logic correctness (e.g. password not in response, token type)
"""

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock

TEST_EMAIL = "testuser@coreauth.dev"
TEST_PASSWORD = "SecurePass123!"
TEST_NAME = "Test User"


@pytest.mark.asyncio
async def test_01_register(client: AsyncClient):
    """
    Spec §4.1 Step 1 — The Registration Step.

    Sends a POST request to /auth/signup with a new email and password.

    Assertions:
        ✅ HTTP 201 Created
        ✅ Response contains all UserRegistrationResponse fields (Spec §3.1)
        ✅ Password is NOT returned in the response (security check)
        ✅ is_active defaults to True
        ✅ is_superuser defaults to False
        ✅ created_at is present (ISO 8601 timestamp)
    """
    response = await client.post(
        "/auth/signup",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "name": TEST_NAME,
        },
    )

    assert (
        response.status_code == 201
    ), f"Expected 201, got {response.status_code}: {response.text}"

    data = response.json()

    assert "id" in data, "Response must contain 'id'"
    assert "email" in data, "Response must contain 'email'"
    assert "is_active" in data, "Response must contain 'is_active'"
    assert "is_superuser" in data, "Response must contain 'is_superuser'"
    assert "created_at" in data, "Response must contain 'created_at'"

    assert data["email"] == TEST_EMAIL, "Returned email must match the submitted email"
    assert data["is_active"] is True, "New accounts must be active by default"
    assert (
        data["is_superuser"] is False
    ), "New accounts must not be superuser by default"
    assert isinstance(data["id"], int), "ID must be an integer"

    assert "password" not in data, "Plaintext password must never be in response"
    assert "hashed_password" not in data, "Hashed password must never be in response"


@pytest.mark.asyncio
async def test_01b_register_duplicate_email(client: AsyncClient):
    """
    Duplicate registration must be rejected with HTTP 400.

    First register the user, then attempt to register again with same email.
    The second request must fail.
    """
    await client.post(
        "/auth/signup",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "name": TEST_NAME,
        },
    )

    response = await client.post(
        "/auth/signup",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert response.status_code == 400, "Duplicate email registration must return 400"
    assert "already registered" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_02_login(client: AsyncClient):
    """
    Spec §4.1 Step 2 — The Authentication Step.

    First registers a user, then submits credentials to /auth/login.

    Assertions:
        ✅ HTTP 200 OK
        ✅ Response contains all TokenExchangeResponse fields (Spec §3.2)
        ✅ token_type is exactly "bearer" (OAuth2 compliance)
        ✅ Both access_token and refresh_token are non-empty strings
        ✅ The two tokens are DIFFERENT (separate JTIs and payloads)
    """
    await client.post(
        "/auth/signup",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "name": TEST_NAME,
        },
    )

    response = await client.post(
        "/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    assert response.status_code == 200, f"Login failed: {response.text}"

    data = response.json()

    assert "access_token" in data, "Response must contain 'access_token'"
    assert "refresh_token" in data, "Response must contain 'refresh_token'"
    assert "token_type" in data, "Response must contain 'token_type'"

    assert (
        data["token_type"] == "bearer"
    ), "token_type must be exactly 'bearer' (OAuth2)"
    assert isinstance(data["access_token"], str) and len(data["access_token"]) > 10
    assert isinstance(data["refresh_token"], str) and len(data["refresh_token"]) > 10

    assert (
        data["access_token"] != data["refresh_token"]
    ), "Access and refresh tokens must be different JWT strings"


@pytest.mark.asyncio
async def test_02b_login_wrong_password(client: AsyncClient):
    """
    Login with wrong password must return HTTP 401, not 400 or 200.
    """
    await client.post(
        "/auth/signup",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )

    response = await client.post(
        "/auth/login",
        json={"email": TEST_EMAIL, "password": "WrongPassword999!"},
    )

    assert response.status_code == 401, "Wrong password must return 401"


@pytest.mark.asyncio
async def test_03_protected_me(client: AsyncClient):
    """
    Spec §4.1 Step 3 — The Security Access Step.

    Uses the access token from login to access the protected /auth/me route.

    Assertions:
        ✅ HTTP 200 OK with valid token
        ✅ Response contains UserProfileResponse fields
        ✅ Returned email matches the logged-in user
        ✅ HTTP 401 when no token is provided
    """
    await client.post(
        "/auth/signup",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "name": TEST_NAME,
        },
    )
    login_resp = await client.post(
        "/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    access_token = login_resp.json()["access_token"]

    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200, f"/me failed: {response.text}"

    data = response.json()
    assert data["email"] == TEST_EMAIL, "Returned email must match logged-in user"
    assert "id" in data
    assert "is_active" in data

    unauth_response = await client.get("/auth/me")
    assert unauth_response.status_code in (
        401,
        403,
    ), "Unauthenticated request to /me must be rejected"


@pytest.mark.asyncio
async def test_04_token_refresh(client: AsyncClient):
    """
    Spec §4.1 Step 4 — The Rotation Step.

    Submits the refresh token to /auth/refresh and receives a new token pair.

    Assertions:
        ✅ HTTP 200 OK
        ✅ Response contains a new TokenExchangeResponse (Spec §3.2)
        ✅ New tokens are different from the original tokens (new JTIs)
        ✅ token_type is "bearer"
        ✅ Passing an access token to /refresh must fail (wrong key)
    """
    await client.post(
        "/auth/signup",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    login_data = (
        await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
    ).json()

    original_access = login_data["access_token"]
    original_refresh = login_data["refresh_token"]

    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh},
    )

    assert response.status_code == 200, f"Refresh failed: {response.text}"

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

    assert data["access_token"] != original_access, "New access token must be different"
    assert (
        data["refresh_token"] != original_refresh
    ), "New refresh token must be different"

    bad_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_access},
    )
    assert (
        bad_response.status_code == 401
    ), "Access token must be rejected by /refresh (dual-secret enforcement)"


@pytest.mark.asyncio
async def test_05_logout(client: AsyncClient, mock_redis):
    """
    Spec §4.1 Step 5 — The Session Revocation Step.

    Sends the active access token to /auth/logout to revoke it.

    Assertions:
        ✅ HTTP 200 OK
        ✅ Response contains StandardActionResponse {"detail": "..."} (Spec)
        ✅ Redis setex was called — the JTI was blacklisted
        ✅ "detail" field contains a human-readable confirmation message
    """
    await client.post(
        "/auth/signup",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    access_token = (
        await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
    ).json()["access_token"]

    response = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200, f"Logout failed: {response.text}"

    data = response.json()
    assert "detail" in data, "Logout response must contain 'detail' field"
    assert len(data["detail"]) > 0, "Detail must not be empty"

    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_06_zero_trust_blacklisted_token(client: AsyncClient, mock_redis):
    """
    Spec §4.1 Step 6 — The Zero-Trust Post-Validation Step.

    After logout, attempts to use the revoked token again.
    The system must block it with HTTP 401 — the route handler never runs.

    This test simulates a real blacklisted token by configuring mock Redis
    to return 1 (key exists) for the exists() call, mimicking what would
    happen after a real logout had stored the JTI in Redis.

    Assertions:
        ✅ HTTP 401 Unauthorized when using a blacklisted token
        ✅ Protected endpoint is completely blocked (Zero-Trust enforcement)
        ✅ No user data is returned for a revoked token
    """
    await client.post(
        "/auth/signup",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    access_token = (
        await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
    ).json()["access_token"]

    mock_redis.exists = AsyncMock(return_value=1)

    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401, (
        f"Blacklisted token must return 401, got {response.status_code}. "
        "Zero-Trust enforcement failed!"
    )

    data = response.json()
    assert "email" not in data, "No user data must be returned for revoked tokens"
    assert "access_token" not in data
