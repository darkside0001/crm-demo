import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app import audit, throttle
from app.config import Settings
from app.deps import current_user, get_db, get_settings
from app.errors import AppError
from app.models import RefreshToken, RevokedAccessToken, User
from app.schemas import LoginIn, PasswordChangeIn, RefreshIn, TokenOut, UserOut
from app.security import (
    create_access_token,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    new_refresh_token,
    password_problems,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Same message for unknown email, wrong password, locked or disabled account:
# the response must not tell an attacker which one it was.
BAD_LOGIN = "Invalid email or password"


def aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _issue_tokens(db: Session, settings: Settings, user: User, family: str | None = None) -> TokenOut:
    refresh, refresh_hash = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=refresh_hash,
            family=family or secrets.token_hex(16),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
        )
    )
    return TokenOut(
        access_token=create_access_token(settings, user.id, user.role.value, user.token_version),
        refresh_token=refresh,
        expires_in=settings.access_token_minutes * 60,
    )


def _revoke_all(db: Session, user_id: int) -> None:
    db.execute(update(RefreshToken).where(RefreshToken.user_id == user_id).values(revoked=True))


@router.post("/login", response_model=TokenOut)
def login(
    body: LoginIn,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    email = body.email.lower()
    ip = request.state.client_ip
    user = db.scalar(select(User).where(User.email == email))
    now = datetime.now(timezone.utc)

    if user is None:
        verify_password(body.password, None)  # same work as for a real account
        audit.record(db, request, "login_failed", details_email=email, reason="unknown_user")
        db.commit()
        raise AppError(401, BAD_LOGIN)

    locked = aware(user.locked_until)
    if locked and locked > now:
        verify_password(body.password, None)
        audit.record(db, request, "login_blocked", actor_id=user.id, entity="user", entity_id=user.id, scope="account")
        db.commit()
        raise AppError(401, BAD_LOGIN)

    attempt_id, from_ip, from_all = throttle.begin(db, settings, user, ip, "login")
    if from_ip > settings.login_max_failures:
        # This source used up its tries: refuse without checking the password.
        # The real user, from another address, can still log in.
        throttle.drop(db, attempt_id)
        verify_password(body.password, None)
        audit.record(db, request, "login_blocked", actor_id=user.id, entity="user", entity_id=user.id, scope="source")
        db.commit()
        raise AppError(401, BAD_LOGIN)

    password_ok = verify_password(body.password, user.password_hash)
    if not password_ok or not user.is_active:
        reason = "inactive" if password_ok else "bad_password"
        audit.record(db, request, "login_failed", actor_id=user.id, entity="user", entity_id=user.id, reason=reason)
        if from_ip == settings.login_max_failures:
            audit.record(db, request, "source_blocked", actor_id=user.id, entity="user", entity_id=user.id)
        if from_all >= settings.login_account_lock_failures:
            # Many failures from many addresses: a distributed attack on this account.
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            audit.record(db, request, "account_locked", actor_id=user.id, entity="user", entity_id=user.id,
                         failures=from_all)
        db.commit()
        raise AppError(401, BAD_LOGIN)

    throttle.clear(db, user, ip)
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    tokens = _issue_tokens(db, settings, user)
    audit.record(db, request, "login_success", actor_id=user.id, entity="user", entity_id=user.id)
    db.commit()
    return tokens


@router.post("/refresh", response_model=TokenOut)
def refresh(
    body: RefreshIn,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(body.refresh_token)))
    if row is None:
        raise AppError(401, "Invalid refresh token")

    if row.revoked:
        # A rotated token came back: someone holds a stolen copy. Kill the
        # whole token family so neither the thief nor the victim keeps a session.
        db.execute(update(RefreshToken).where(RefreshToken.family == row.family).values(revoked=True))
        audit.record(db, request, "refresh_reuse_detected", actor_id=row.user_id, entity="user", entity_id=row.user_id)
        db.commit()
        raise AppError(401, "Invalid refresh token")

    user = db.get(User, row.user_id)
    if aware(row.expires_at) <= datetime.now(timezone.utc) or user is None or not user.is_active:
        row.revoked = True
        db.commit()
        raise AppError(401, "Invalid refresh token")

    row.revoked = True  # rotation: every refresh token works once
    tokens = _issue_tokens(db, settings, user, family=row.family)
    db.commit()
    return tokens


@router.post("/logout", status_code=204)
def logout(
    body: RefreshIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(body.refresh_token)))
    if row is not None and row.user_id == user.id:
        db.execute(update(RefreshToken).where(RefreshToken.family == row.family).values(revoked=True))
    # End the access token too, not only the refresh token (pentest finding F-05).
    claims = request.state.token
    exp = datetime.fromtimestamp(claims["exp"], timezone.utc)
    if db.get(RevokedAccessToken, claims["jti"]) is None:
        db.add(RevokedAccessToken(jti=claims["jti"], expires_at=exp))
    db.execute(delete(RevokedAccessToken).where(RevokedAccessToken.expires_at < datetime.now(timezone.utc)))
    audit.record(db, request, "logout", actor_id=user.id, entity="user", entity_id=user.id)
    db.commit()


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/change-password", status_code=204)
def change_password(
    body: PasswordChangeIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    attempt_id, from_ip, _ = throttle.begin(db, settings, user, request.state.client_ip, "password_change")
    if not verify_password(body.current_password, user.password_hash):
        audit.record(db, request, "password_change_failed", actor_id=user.id, entity="user", entity_id=user.id)
        if from_ip >= settings.login_max_failures:
            # Someone with this session is guessing the password (pentest finding
            # F-08): end every session of the account.
            user.token_version += 1
            _revoke_all(db, user.id)
            audit.record(db, request, "password_guessing_detected", actor_id=user.id, entity="user", entity_id=user.id)
            db.commit()
            raise AppError(401, "Too many wrong passwords. Log in again.")
        db.commit()
        raise AppError(400, "Current password is incorrect")
    throttle.drop(db, attempt_id)
    problems = password_problems(body.new_password, user.email)
    if problems:
        raise AppError(422, "Password " + "; ".join(problems), code="weak_password")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # every existing access token stops working
    _revoke_all(db, user.id)
    audit.record(db, request, "password_changed", actor_id=user.id, entity="user", entity_id=user.id)
    db.commit()
