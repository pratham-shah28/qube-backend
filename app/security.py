import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from app.config import Settings
from app.db import get_db
from app.models import Role, User

_hasher = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)

# No 0/O/1/I/L so codes can be read aloud and typed.
INVITE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_invite_code(length: int = 10) -> str:
    return "".join(secrets.choice(INVITE_ALPHABET) for _ in range(length))


def create_token(settings: Settings, user: User) -> str:
    now = datetime.now(UTC)
    ttl = (
        timedelta(hours=settings.admin_token_hours)
        if user.role == Role.admin
        else timedelta(days=settings.member_token_days)
    )
    payload = {
        "sub": str(user.id),
        "org": user.org_id,
        "role": user.role.value,
        "ver": user.token_version,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _unauthorized(detail: str = "not_authenticated") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> User:
    if creds is None:
        raise _unauthorized()
    try:
        claims = jwt.decode(creds.credentials, settings.jwt_secret, algorithms=["HS256"])
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, KeyError, ValueError) as e:
        raise _unauthorized("invalid_token") from e

    user = db.get(User, user_id)
    # Load the user on every request so deactivation and token_version bumps take effect.
    if (
        user is None
        or not user.active
        or user.token_version != claims.get("ver")
        or user.org_id != claims.get("org")
        or user.role.value != claims.get("role")
    ):
        raise _unauthorized("invalid_token")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="admin_only")
    return user


class RateLimiter:
    """In-memory sliding window per key. Fine for a single instance; swap for Redis later."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def auth_rate_limit(request: Request, settings: Settings = Depends(get_settings_dep)) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    ip = request.client.host if request.client else "unknown"
    if not limiter.check(f"{request.url.path}:{ip}", settings.auth_rate_limit_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail="rate_limited")
