"""
Authentication Dependency Injector — Core-Auth System
======================================================
Implements the "User Extraction Injection" system from Spec §2.2.

What is FastAPI Dependency Injection?
--------------------------------------
FastAPI's Depends() lets you declare reusable logic that runs automatically
BEFORE your route handler executes. The result is injected as a parameter.

    Example usage in a route:
        @router.get("/me")
        async def get_me(current_user: User = Depends(get_current_user)):
            return current_user   # ← validated, blacklist-checked, DB-fetched

get_current_user — Full Validation Pipeline (Spec §2.2):
    Step 1: Extract Bearer token from "Authorization: Bearer <token>" header
    Step 2: Decode and verify JWT signature using the access token secret
    Step 3: Confirm token type is "access" (not refresh — cross-type protection)
    Step 4: Check the token JTI against the Redis blacklist (logout detection)
    Step 5: Query the database for the live user record via the token's user_id
    Step 6: Return the User ORM object → injected into the route handler

    If ANY step fails → HTTP 401 Unauthorized is raised immediately.
    The route handler never executes with invalid credentials.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.db import get_db
from app.models.users import User
from app.services.redis_service import is_blacklisted
from app.utils.security import verify_access_token


# ── HTTP Bearer Token Extractor ─────────────────────────────────────────────
# HTTPBearer is a FastAPI utility that reads the "Authorization" header,
# expects the format "Bearer <token>", and extracts the token string.
# If the header is missing or malformed → automatically raises HTTP 403.
# auto_error=True means FastAPI handles the missing-header case for us.
bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency that validates an incoming request and returns
    the authenticated User object from the database.

    This single function enforces the entire authentication pipeline
    described in Spec §2.2 "User Extraction Injection."

    Validation Steps:
        1. bearer_scheme extracts token from "Authorization: Bearer <token>"
        2. verify_access_token() decodes the JWT and checks expiry + signature
        3. Token "type" field must equal "access" — prevents refresh misuse
        4. is_blacklisted() checks Redis — returns True if user has logged out
        5. Database query fetches the live User record using token's user_id
        6. Returns User ORM object to the route handler via dependency

    Args:
        credentials: Injected by HTTPBearer — contains the raw token string.
        db:          Injected async database session from get_db().

    Returns:
        The authenticated User ORM object from the database.

    Raises:
        HTTPException 401: If the token is invalid, expired, blacklisted,
                           wrong type, or if the user no longer exists in DB.
    """
    # Reusable 401 exception — used for ALL failure cases.
    # We deliberately use the same message to avoid leaking which check failed
    # (prevents attackers from probing which validation step they passed).
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # ── Step 1: Decode and verify the JWT ───────────────────────────────────
    # verify_access_token() uses SECRET_KEY (access secret only).
    # Returns None if the token is expired, tampered, or signed with wrong key.
    # The "Bearer <token>" → just "<token>"
    raw_token = credentials.credentials
    payload = verify_access_token(raw_token)

    if payload is None:
        # Token is expired, structurally invalid, or has wrong signature
        raise credentials_exception

    # ── Step 2: Enforce token type = "access" ───────────────────────────────
    # Refresh tokens are signed with a different secret, so verify_access_token
    # would already reject them. This check adds an explicit defense-in-depth
    # layer — even if somehow a refresh token passed signature validation,
    # the type field stops it from being used on protected routes.
    token_type = payload.get("type")
    if token_type != "access":
        raise credentials_exception

    # ── Step 3: Check the Redis blacklist ───────────────────────────────────
    # The JTI (JWT ID) is a unique UUID4 stored inside every token payload.
    # On logout, the JTI is added to Redis with a TTL = remaining token life.
    # If the JTI is in Redis → the user has already logged out → block request.
    jti = payload.get("jti")
    if jti and await is_blacklisted(jti):
        # Token is valid BUT has been explicitly revoked via logout (Spec §2.2)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Step 4: Fetch the user from the database ────────────────────────────
    # We use user_id from the token (faster than email for indexed PK lookup).
    # This also catches edge cases: user deleted after token was issued.
    user_id = payload.get("user_id")
    if user_id is None:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if user is None:
        # User was deleted from DB after the token was issued
        raise credentials_exception

    # ── Step 5: Return the validated User object ────────────────────────────
    # The route handler receives this directly as its "current_user" parameter.
    return user
