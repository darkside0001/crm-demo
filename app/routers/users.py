from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app.deps import get_db, require_roles
from app.errors import AppError
from app.models import RefreshToken, Role, User
from app.schemas import Page, UserCreate, UserOut, UserUpdate
from app.security import hash_password, password_problems

router = APIRouter(prefix="/users", tags=["users"])

admin_only = require_roles(Role.admin)


@router.get("", response_model=Page[UserOut])
def list_users(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
    _: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    total = db.scalar(select(func.count()).select_from(User))
    rows = db.scalars(select(User).order_by(User.id).limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    admin: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    email = body.email.lower()
    problems = password_problems(body.password, email)
    if problems:
        raise AppError(422, "Password " + "; ".join(problems), code="weak_password")
    if db.scalar(select(User.id).where(User.email == email)):
        raise AppError(409, "A user with this email already exists")
    user = User(email=email, full_name=body.full_name, role=body.role, password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    audit.record(db, request, "user_created", actor_id=admin.id, entity="user", entity_id=user.id, role=body.role.value)
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    admin: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "User not found")
    changes = body.model_dump(exclude_unset=True)
    if user.id == admin.id and (changes.get("role", Role.admin) != Role.admin or changes.get("is_active") is False):
        raise AppError(400, "Admins cannot demote or disable themselves")

    before = {k: getattr(user, k) for k in changes}
    for k, v in changes.items():
        setattr(user, k, v)
    if "role" in changes or changes.get("is_active") is False:
        # Privilege change: end every session of this user right away.
        user.token_version += 1
        db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked=True))
    audit.record(
        db,
        request,
        "user_updated",
        actor_id=admin.id,
        entity="user",
        entity_id=user.id,
        before={k: getattr(v, "value", v) for k, v in before.items()},
        after={k: getattr(v, "value", v) for k, v in changes.items()},
    )
    db.commit()
    return user
