"""Brute-force protection keyed on (account, client IP).

Why not a counter on the user row (the original design):
- five wrong passwords from anyone locked the real user out (targeted DoS);
- `failed_logins += 1` is a read-modify-write, so parallel guesses were lost
  and an attacker got more than five tries (pentest findings F-03, F-04).

Here every attempt is inserted and committed *before* the password is checked,
then counted. A request whose own row is the n-th one sees at least n rows, so
no more than `login_max_failures` checks can run per window, however many
requests arrive in parallel.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AuthFailure, User


def _since(settings: Settings) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=settings.login_lockout_minutes)


def begin(db: Session, settings: Settings, user: User, ip: str, kind: str) -> tuple[int, int, int]:
    """Record an attempt. Returns (attempt id, failures from this IP, failures from all IPs)."""
    since = _since(settings)
    # Old rows no longer count: drop them so the table stays small under attack.
    db.execute(delete(AuthFailure).where(AuthFailure.user_id == user.id, AuthFailure.at < since))
    row = AuthFailure(user_id=user.id, ip=ip, kind=kind)
    db.add(row)
    db.commit()
    base = select(func.count()).select_from(AuthFailure).where(AuthFailure.user_id == user.id, AuthFailure.at >= since)
    per_ip = db.scalar(base.where(AuthFailure.ip == ip))
    total = db.scalar(base)
    return row.id, per_ip, total


def drop(db: Session, attempt_id: int) -> None:
    """Forget one attempt (it was refused before any password check)."""
    db.execute(delete(AuthFailure).where(AuthFailure.id == attempt_id))


def clear(db: Session, user: User, ip: str) -> None:
    """Successful authentication from this IP: its failures no longer count."""
    db.execute(delete(AuthFailure).where(AuthFailure.user_id == user.id, AuthFailure.ip == ip))
