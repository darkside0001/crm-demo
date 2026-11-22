from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app import audit
from app.deps import MANAGERS, STAFF, get_db, require_roles
from app.errors import AppError
from app.models import Customer, Order, Role, User
from app.schemas import CustomerCreate, CustomerOut, CustomerUpdate, Page
from app.search import like_pattern

router = APIRouter(prefix="/customers", tags=["customers"])


def mask_phone(phone: str) -> str:
    return phone[:4] + "*" * max(len(phone) - 7, 0) + phone[-3:]


def mask_email(email: str | None) -> str | None:
    if not email:
        return email
    name, _, domain = email.partition("@")
    return name[:1] + "***@" + domain


def present(customer: Customer, viewer: User, masked: bool) -> CustomerOut:
    out = CustomerOut.model_validate(customer)
    if masked and viewer.role == Role.seller:
        # Data minimisation: lists show sellers just enough to pick the right person.
        out.phone = mask_phone(out.phone)
        out.email = mask_email(out.email)
    return out


def has_relationship(db: Session, viewer: User, customer: Customer) -> bool:
    """A seller sees full contact details only for customers they work with."""
    if viewer.role != Role.seller or customer.created_by_id == viewer.id:
        return True
    return db.scalar(
        select(Order.id).where(Order.customer_id == customer.id, Order.seller_id == viewer.id).limit(1)
    ) is not None


@router.get("", response_model=Page[CustomerOut])
def list_customers(
    q: str | None = Query(None, max_length=60),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    stmt = select(Customer)
    if q:
        pattern = like_pattern(q)
        if user.role == Role.seller:
            # Sellers see masked phones, so a substring search on the phone column would let
            # them rebuild the hidden digits one query at a time. They may only look a
            # customer up by the exact number the customer gives them.
            phone_match = Customer.phone == q.strip()
        else:
            phone_match = Customer.phone.like(pattern, escape="\\")
        stmt = stmt.where(or_(Customer.full_name.ilike(pattern, escape="\\"), phone_match))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Customer.id).limit(limit).offset(offset)).all()
    return Page(items=[present(c, user, masked=True) for c in rows], total=total, limit=limit, offset=offset)


@router.get("/{customer_id}", response_model=CustomerOut)
def get_customer(
    customer_id: int,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    customer = db.get(Customer, customer_id)
    if customer is None:
        raise AppError(404, "Customer not found")
    # Opening a full customer card is personal-data access: keep a record of who looked.
    audit.record(db, request, "customer_viewed", actor_id=user.id, entity="customer", entity_id=customer.id)
    db.commit()
    return present(customer, user, masked=not has_relationship(db, user, customer))


@router.post("", response_model=CustomerOut, status_code=201)
def create_customer(
    body: CustomerCreate,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    if db.scalar(select(Customer.id).where(Customer.phone == body.phone)):
        raise AppError(409, "A customer with this phone already exists")
    customer = Customer(**body.model_dump(), created_by_id=user.id)
    db.add(customer)
    db.flush()
    audit.record(db, request, "customer_created", actor_id=user.id, entity="customer", entity_id=customer.id)
    db.commit()
    return present(customer, user, masked=False)


@router.patch("/{customer_id}", response_model=CustomerOut)
def update_customer(
    customer_id: int,
    body: CustomerUpdate,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    customer = db.get(Customer, customer_id)
    if customer is None:
        raise AppError(404, "Customer not found")
    # Object-level check: sellers may only edit customers they registered.
    if user.role not in MANAGERS and customer.created_by_id != user.id:
        raise AppError(403, "You can only edit customers you registered")
    changes = body.model_dump(exclude_unset=True)
    if "phone" in changes and changes["phone"] != customer.phone:
        if db.scalar(select(Customer.id).where(Customer.phone == changes["phone"])):
            raise AppError(409, "A customer with this phone already exists")
    for k, v in changes.items():
        setattr(customer, k, v)
    audit.record(
        db, request, "customer_updated", actor_id=user.id, entity="customer", entity_id=customer.id,
        fields=sorted(changes),
    )
    db.commit()
    return present(customer, user, masked=False)
