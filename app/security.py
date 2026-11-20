"""Password hashing, JWT access tokens and rotating refresh tokens."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import Settings

# Argon2id with the library defaults (OWASP-recommended parameters).
_hasher = PasswordHasher()

# Verifying against this when the user does not exist keeps login timing
# similar for known and unknown emails (no user enumeration by timing).
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_access_token(settings: Settings, user_id: int, role: str, token_version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "ver": token_version,
        "typ": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> dict:
    """Raise jwt.InvalidTokenError on any problem.

    The accepted algorithm list is pinned, so `alg: none` and algorithm
    confusion attacks are rejected. exp/iat/iss/aud are all required.
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "iss", "aud", "jti"]},
    )
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def new_refresh_token() -> tuple[str, str]:
    """Return (token for the client, sha256 hex to store)."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# A short list is enough for a demo; production would check a breached-password
# corpus (e.g. the k-anonymity Pwned Passwords API).
COMMON_PASSWORDS = {
    "password1234",
    "123456789012",
    "qwerty123456",
    "admin1234567",
    "passwordpassword",
    "iloveyou1234",
    "welcome12345",
}


def password_problems(password: str, email: str) -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password) > 128:
        problems.append("must be at most 128 characters")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("is too common")
    if email and email.split("@")[0].lower() in password.lower():
        problems.append("must not contain the email name")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        problems.append("must mix at least 3 of: lowercase, uppercase, digits, symbols")
    return problems
