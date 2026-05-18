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

    return pwd_context.hash(_truncate_password(password))


def verify_password(plain_password: str, hashed_password: str) -> bool:

    return pwd_context.verify(_truncate_password(plain_password), hashed_password)


def create_access_token(email: str, user_id: int) -> str:

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
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(email: str, user_id: int) -> str:

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

    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None


def verify_refresh_token(token: str) -> Optional[dict]:

    try:
        return jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        return None


def get_remaining_ttl(payload: dict) -> int:

    exp_timestamp = payload.get("exp", 0)
    if isinstance(exp_timestamp, datetime):
        exp_dt = exp_timestamp
    else:
        exp_dt = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    remaining = (exp_dt - now).total_seconds()
    return max(0, int(remaining))
