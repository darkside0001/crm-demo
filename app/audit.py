from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog

# Keys that must never reach the audit log even if a caller passes them.
_REDACT = {"password", "new_password", "current_password", "token", "refresh_token", "password_hash"}


def record(
    db: Session,
    request: Request,
    action: str,
    actor_id: int | None = None,
    entity: str | None = None,
    entity_id: int | None = None,
    **details,
) -> None:
    """Add an audit entry to the current transaction (caller commits)."""
    clean = {k: ("[redacted]" if k in _REDACT else v) for k, v in details.items()}
    db.add(
        AuditLog(
            actor_id=actor_id,
            action=action,
            entity=entity,
            entity_id=entity_id,
            ip=getattr(request.state, "client_ip", None),
            request_id=getattr(request.state, "request_id", None),
            details=clean or None,
        )
    )
