"""Request dependencies: DB session, current user, role checks."""

from collections.abc import Callable, Iterator

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.errors import AppError
from app.models import RevokedAccessToken, Role, User

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    yield from request.app.state.db.session()


def _unauthorized() -> AppError:
    return AppError(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})


def current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    from app.security import decode_access_token

    try:
        payload = decode_access_token(settings, creds.credentials)
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise _unauthorized()

    if db.get(RevokedAccessToken, payload["jti"]) is not None:  # logged out
        raise _unauthorized()
    request.state.token = payload

    user = db.get(User, user_id)
    # The role and version are re-read from the database on every request, so a
    # demoted, disabled or password-changed user loses access immediately.
    if user is None or not user.is_active or user.token_version != payload.get("ver"):
        raise _unauthorized()
    return user


def require_roles(*roles: Role) -> Callable[[User], User]:
    """Function-level authorization (OWASP API5)."""

    def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise AppError(403, "Your role cannot perform this action")
        return user

    return checker


STAFF = (Role.admin, Role.manager, Role.seller)
MANAGERS = (Role.admin, Role.manager)
