"""
Security & Cryptography Layer — Core-Auth System
=================================================
Implements the dual-token cryptographic strategy from Spec §2.2.

Token Architecture:
┌──────────────────────────────┬──────────────────────────────────┐
│       ACCESS TOKEN           │       REFRESH TOKEN              │
├──────────────────────────────┼──────────────────────────────────┤
│ Secret : SECRET_KEY          │ Secret : REFRESH_SECRET_KEY      │
│ Expiry : 15 minutes          │ Expiry : 7 days                  │
│ Type   : "access"            │ Type   : "refresh"               │
│ Use    : access endpoints    │ Use    : generate new token pair │
└──────────────────────────────┴──────────────────────────────────┘

JTI (JWT ID) — Token Fingerprint for Blacklisting:
    Every token contains a unique UUID4 "jti" claim.
    On logout, the JTI is stored in Redis with a TTL = remaining token life.
    Every protected request checks Redis for the JTI before allowing access.
    This is the "Stateful Token Invalidation" mechanism from Spec §2.2.

Password Hashing:
    bcrypt via passlib. Passwords are truncated to 72 bytes before hashing
    because bcrypt silently ignores bytes beyond position 72 — this explicit
    truncation makes the behavior safe and predictable.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.utils.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _truncate_password(password: str) -> str:
    """
    Truncate password to bcrypt's 72-byte limit.

    Why: bcrypt silently ignores bytes after position 72, which could allow
    two different long passwords to hash identically — a security hole.
    By explicitly truncating, we make this behavior deterministic and safe.

    Args:
        password: Raw plaintext password string.

    Returns:
        Password string safely capped at 72 UTF-8 bytes.
    """
    password_bytes = password.encode("utf-8")
    if len(password_bytes) <= 72:
        return password
    return password_bytes[:72].decode("utf-8", errors="ignore")


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Flow:
        1. Truncate to 72 bytes (bcrypt limit safety)
        2. bcrypt generates a random salt internally
        3. Returns the full hash string (includes salt + algorithm metadata)

    The returned hash is safe to store in the database.
    Plaintext passwords must NEVER be stored.

    Args:
        password: Raw plaintext password from the user.

    Returns:
        bcrypt hash string (e.g. "$2b$12$<salt><hash>").
    """
    return pwd_context.hash(_truncate_password(password))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.

    bcrypt extracts the salt from the stored hash, re-hashes the input,
    and compares in constant time (preventing timing-based attacks).

    Args:
        plain_password:  Password provided by the user at login.
        hashed_password: bcrypt hash stored in the database.

    Returns:
        True if the password matches, False otherwise.
    """
    return pwd_context.verify(
        _truncate_password(plain_password), hashed_password
    )


def create_access_token(email: str, user_id: int) -> str:
    """
    Create a short-lived JWT Access Token (Spec §2.2).

    Payload structure:
        {
            "email"  : "user@example.com",  
            "user_id": 1,                    
            "type"   : "access",             
            "jti"    : "<uuid4>",            
            "exp"    : <unix_timestamp>      
        }

    Signed with: settings.SECRET_KEY — the ACCESS-token secret ONLY.
    This key is NEVER used for refresh tokens (dual-secret enforcement).

    Args:
        email:   User's email address.
        user_id: User's database primary key.

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "email": email,
        "user_id": user_id,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "exp": expire,
    }
    return jwt.encode(
        payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )


def create_refresh_token(email: str, user_id: int) -> str:
    """
    Create a long-lived JWT Refresh Token (Spec §2.2).

    KEY SEPARATION — The Core Requirement of Spec §2.2:
        Signed with: settings.REFRESH_SECRET_KEY — a COMPLETELY DIFFERENT
        secret from the access token key.

        Why this matters:
          - A compromised access secret CANNOT forge a refresh token
          - A compromised refresh secret CANNOT forge an access token
          - Token-type confusion attacks are cryptographically impossible
          - Unauthorized token extension attacks are prevented

    Args:
        email:   User's email address.
        user_id: User's database primary key.

    Returns:
        Encoded JWT string signed with REFRESH_SECRET_KEY.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "email": email,
        "user_id": user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "exp": expire,
    }
    return jwt.encode(
        payload, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM
    )


def verify_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT Access Token.

    Verification steps (handled by jose):
        1. Decode using SECRET_KEY (access secret only)
        2. Validate the "exp" claim — raises JWTError if expired
        3. Validate the signature — raises JWTError if tampered

    Note: This does NOT check the Redis blacklist because blacklist
    checking requires an async Redis call. That is done in
    app/dependencies/auth.py after this function returns.

    Args:
        token: Raw JWT string from the Authorization header.

    Returns:
        Decoded payload dict if valid, None if expired or invalid.
    """
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None


def verify_refresh_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT Refresh Token.

    Uses REFRESH_SECRET_KEY — a completely different key from access tokens.
    Passing an access token here will FAIL (signed with wrong key).
    Passing a refresh token to verify_access_token will also FAIL.

    This cross-type rejection is automatic due to key separation (Spec §2.2).

    Args:
        token: Raw JWT string (expected to be a refresh token).

    Returns:
        Decoded payload dict if valid, None if expired or invalid.
    """
    try:
        return jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None


def get_remaining_ttl(payload: dict) -> int:
    """
    Calculate the remaining valid seconds for a token.

    Used when blacklisting: we store the JTI in Redis with a TTL equal
    to the token's remaining lifespan. When the TTL expires, Redis
    automatically deletes the entry — zero maintenance required.

    Args:
        payload: Decoded JWT payload dict containing "exp" (unix timestamp).

    Returns:
        Remaining seconds as an integer. Returns 0 if already expired.
    """
    exp_timestamp = payload.get("exp", 0)
    if isinstance(exp_timestamp, datetime):
        exp_dt = exp_timestamp
    else:
        exp_dt = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

    now = datetime.now(timezone.utc)
    remaining = (exp_dt - now).total_seconds()
    return max(0, int(remaining))
