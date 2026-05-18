"""
Authentication Routes — Core-Auth System
=========================================
All HTTP endpoints for the full authentication lifecycle.
Every route is async — satisfying Spec §2.1 non-blocking I/O requirement.

Endpoints:
    POST /auth/signup   → Register a new user account
    POST /auth/login    → Authenticate and receive dual-token pair
    POST /auth/refresh  → Rotate tokens using a valid refresh token
    GET  /auth/me       → Fetch current user profile (protected)
    POST /auth/logout   → Revoke access token via Redis blacklist

Response Schemas (Spec §3):
    UserRegistrationResponse → /signup
    TokenExchangeResponse    → /login, /refresh
    StandardActionResponse   → /logout
    UserProfileResponse      → /me

Zero-Trust Enforcement (Spec §4.1 Step 6):
    After logout, any request with the revoked token is blocked at the
    get_current_user dependency (Redis blacklist check) → HTTP 401.
    The route handler itself never executes.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.db import get_db
from app.dependencies.auth import get_current_user
from app.models.users import User
from app.schemas.users import (
    StandardActionResponse,
    TokenExchangeResponse,
    TokenRefreshRequest,
    UserLoginRequest,
    UserProfileResponse,
    UserRegistrationResponse,
    UserSignupRequest,
)
from app.services.redis_service import blacklist_token
from app.utils.security import (
    create_access_token,
    create_refresh_token,
    get_remaining_ttl,
    hash_password,
    verify_password,
    verify_access_token,
    verify_refresh_token,
)

router = APIRouter()

bearer_scheme = HTTPBearer(auto_error=True)


@router.post(
    "/signup",
    response_model=UserRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def signup(
    request: UserSignupRequest,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponse:
    """
    Register a new user account.

    Flow:
        1. Pydantic validates the request body (email format, password length)
        2. Check the database — if email already exists → 400 Bad Request
        3. Hash the password with bcrypt (plaintext is NEVER stored)
        4. Insert the new User record into the database
        5. Return UserRegistrationResponse (id, email, flags, created_at)

    The hashed_password field is never included in any response schema.

    Returns:
        UserRegistrationResponse (Spec §3.1) — 201 Created

    Raises:
        400: Email is already registered.
    """
    result = await db.execute(
        select(User).where(User.email == request.email)
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    new_user = User(
        email=request.email,
        name=request.name,
        hashed_password=hash_password(request.password),
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post(
    "/login",
    response_model=TokenExchangeResponse,
    summary="Authenticate and receive a dual-token pair",
)
async def login(
    request: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenExchangeResponse:
    """
    Authenticate a user and return a dual-token pair.

    Flow:
        1. Look up the user record by email
        2. Verify the password against the stored bcrypt hash
        3. Generate ACCESS token  — signed with SECRET_KEY         (15 min TTL)
        4. Generate REFRESH token — signed with REFRESH_SECRET_KEY (7 day TTL)
        5. Return TokenExchangeResponse with both tokens

    Dual-Secret Key Separation (Spec §2.2):
        The two tokens are signed with COMPLETELY DIFFERENT cryptographic secrets.
        An access token cannot be used as a refresh token, and vice versa.
        This prevents token-type confusion and unauthorized token extension.

    Returns:
        TokenExchangeResponse (Spec §3.2):
            {access_token, refresh_token, token_type}

    Raises:
        401: Email not found or password is incorrect.
             (Identical message for both cases — prevents user enumeration)
    """
    result = await db.execute(
        select(User).where(User.email == request.email)
    )
    user = result.scalars().first()

    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenExchangeResponse(
        access_token=create_access_token(email=user.email, user_id=user.id),
        refresh_token=create_refresh_token(email=user.email, user_id=user.id),
        token_type="bearer",
    )


@router.post(
    "/refresh",
    response_model=TokenExchangeResponse,
    summary="Get a fresh token pair using a valid refresh token",
)
async def refresh_tokens(
    request: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenExchangeResponse:
    """
    Issue a new token pair using a valid refresh token.

    Flow:
        1. Decode the refresh token using REFRESH_SECRET_KEY (not SECRET_KEY)
           → If an access token is passed here, it fails (wrong key)
        2. Verify the token "type" claim equals "refresh"
        3. Fetch the current user from the database by user_id
        4. Generate a brand-new access token AND refresh token pair
        5. Return the fresh TokenExchangeResponse

    The user does NOT need to re-enter their password (Spec §4.1 Step 4).
    This is the "silent re-authentication" flow used by front-end clients.

    Returns:
        TokenExchangeResponse (Spec §3.2): Fresh {access_token, refresh_token}

    Raises:
        401: Refresh token is expired, invalid, or the wrong token type.
    """
    payload = verify_refresh_token(request.refresh_token)

    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(
        select(User).where(User.id == payload.get("user_id"))
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found",
        )

    return TokenExchangeResponse(
        access_token=create_access_token(email=user.email, user_id=user.id),
        refresh_token=create_refresh_token(email=user.email, user_id=user.id),
        token_type="bearer",
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get the authenticated user's profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserProfileResponse:
    """
    Return the profile of the currently authenticated user.

    This route is FULLY PROTECTED via the get_current_user dependency.
    Before this handler runs, the dependency automatically:
        ✅ Extracts the Bearer token from Authorization header
        ✅ Decodes and verifies JWT signature + expiry
        ✅ Confirms token type == "access"
        ✅ Checks the token JTI against the Redis blacklist
        ✅ Fetches and returns the live User record from the database

    If ANY check fails → HTTP 401 is raised by the dependency.
    This handler only runs with a fully validated, non-revoked token.

    Args:
        current_user: Injected by Depends(get_current_user) — fully validated.

    Returns:
        UserProfileResponse: {id, email, name, is_active, is_superuser}
    """
    return current_user


@router.post(
    "/logout",
    response_model=StandardActionResponse,
    summary="Logout: immediately revoke the current access token",
)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> StandardActionResponse:
    """
    Revoke the current access token by blacklisting its JTI in Redis.

    Implements "Stateful Token Invalidation" from Spec §2.2.

    Why we need this:
        Standard JWTs are stateless — once issued, they are valid until expiry.
        There is no built-in "cancel" mechanism. To implement real logout,
        we use Redis as a blacklist registry for revoked token JTIs.

    Flow:
        1. Extract the raw Bearer token from the Authorization header
        2. Decode and verify the token is a valid, non-expired access token
        3. Extract the JTI (UUID4 unique identifier) from the token payload
        4. Calculate remaining TTL = token_expiry_time - current_time (seconds)
        5. Store "blacklist:{jti}" in Redis with TTL as the auto-expiry time
        6. Return StandardActionResponse confirming revocation

    Self-Cleaning Blacklist:
        The Redis TTL equals the token's remaining valid lifespan.
        Example: Token expires in 8 minutes → Redis TTL = 480 seconds.
        After 480 seconds, Redis auto-deletes the entry.
        Result: The blacklist only ever contains "live" revoked tokens.
        Memory usage is naturally bounded — no manual cleanup needed.

    Post-Logout Behavior (Spec §4.1 Step 6 — Zero-Trust Validation):
        Any subsequent request with this token hits the Redis blacklist check
        inside get_current_user → HTTP 401 Unauthorized immediately.

    Returns:
        StandardActionResponse (Spec §3.3):
            {"detail": "Logout successful. Token revoked."}

    Raises:
        401: If the provided token is already expired or structurally invalid.
    """
    raw_token = credentials.credentials

    payload = verify_access_token(raw_token)

    if payload is None or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token does not contain a JTI claim. Cannot revoke.",
        )

    ttl = get_remaining_ttl(payload)

    if ttl > 0:
        await blacklist_token(jti=jti, ttl_seconds=ttl)

    return StandardActionResponse(detail="Logout successful. Token revoked.")
