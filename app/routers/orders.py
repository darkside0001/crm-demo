from collections import Counter

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app.deps import MANAGERS, STAFF, get_db, require_roles
from app.errors import AppError
from app.models import Customer, Order, OrderItem, OrderStatus, Product, Role, User
from app.schemas import OrderCreate, OrderOut, OrderStatusIn, Page

router = APIRouter(prefix="/orders", tags=["orders"])

# Allowed status changes and who may make them.
TRANSITIONS: dict[tuple[OrderStatus, OrderStatus], tuple[Role, ...]] = {
    (OrderStatus.new, OrderStatus.paid): STAFF,
    (OrderStatus.paid, OrderStatus.shipped): MANAGERS,
    (OrderStatus.new, OrderStatus.cancelled): MANAGERS,
    (OrderStatus.paid, OrderStatus.cancelled): MANAGERS,
}


def visible_orders(user: User):
    """Object-level authorization (OWASP API1, BOLA): sellers see only their own orders."""
    stmt = select(Order)
    if user.role == Role.seller:
        stmt = stmt.where(Order.seller_id == user.id)
    return stmt


def load_order(db: Session, user: User, order_id: int) -> Order:
    order = db.scalar(visible_orders(user).where(Order.id == order_id))
    if order is None:
        # 404, not 403: do not confirm that someone else's order exists.
        raise AppError(404, "Order not found")
    return order


@router.get("", response_model=Page[OrderOut])
def list_orders(
    status: OrderStatus | None = None,
    customer_id: int | None = Query(None, gt=0),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    stmt = visible_orders(user)
    if status:
        stmt = stmt.where(Order.status == status)
    if customer_id:
        stmt = stmt.where(Order.customer_id == customer_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Order.id.desc()).limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.get("/{order_id}", response_model=OrderOut)
def get_order(order_id: int, user: User = Depends(require_roles(*STAFF)), db: Session = Depends(get_db)):
    return load_order(db, user, order_id)


@router.post("", response_model=OrderOut, status_code=201)
def create_order(
    body: OrderCreate,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    if db.get(Customer, body.customer_id) is None:
        raise AppError(404, "Customer not found")

    # Unpaid orders reserve stock. Without a cap one seller account could hold the
    # whole catalogue in "new" orders that only a manager can cancel.
    settings = request.app.state.settings
    if user.role == Role.seller:
        open_orders = db.scalar(
            select(func.count()).select_from(Order).where(
                Order.seller_id == user.id, Order.status == OrderStatus.new
            )
        )
        if open_orders >= settings.max_open_orders_per_seller:
            raise AppError(403, "Too many unpaid orders; ask a manager to review them")

    quantities = Counter()
    for item in body.items:
        quantities[item.product_id] += item.quantity

    products = {
        p.id: p for p in db.scalars(select(Product).where(Product.id.in_(quantities), Product.is_active)).all()
    }
    missing = sorted(set(quantities) - set(products))
    if missing:
        raise AppError(404, f"Products not found or inactive: {missing}")

    order = Order(customer_id=body.customer_id, seller_id=user.id, total=0)
    total = 0
    for product_id, qty in sorted(quantities.items()):
        product = products[product_id]
        # Atomic reserve: fails instead of overselling when two sellers race.
        result = db.execute(
            update(Product)
            .where(Product.id == product_id, Product.stock >= qty)
            .values(stock=Product.stock - qty)
        )
        if result.rowcount == 0:
            db.rollback()
            raise AppError(409, f"Not enough stock for product {product_id}")
        # Price comes from the catalogue, never from the client.
        order.items.append(OrderItem(product_id=product_id, quantity=qty, unit_price=product.price))
        total += product.price * qty
    order.total = total
    db.add(order)
    db.flush()
    audit.record(db, request, "order_created", actor_id=user.id, entity="order", entity_id=order.id, total=total)
    db.commit()
    return order


@router.post("/{order_id}/status", response_model=OrderOut)
def change_status(
    order_id: int,
    body: OrderStatusIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    order = load_order(db, user, order_id)
    allowed_roles = TRANSITIONS.get((order.status, body.status))
    if allowed_roles is None:
        raise AppError(409, f"Cannot change status from {order.status.value} to {body.status.value}")
    if user.role not in allowed_roles:
        raise AppError(403, "Your role cannot make this status change")

    if body.status == OrderStatus.cancelled:
        for item in order.items:
            db.execute(update(Product).where(Product.id == item.product_id).values(stock=Product.stock + item.quantity))

    old = order.status
    order.status = body.status
    audit.record(
        db, request, "order_status_changed", actor_id=user.id, entity="order", entity_id=order.id,
        old=old.value, new=body.status.value,
    )
    db.commit()
    return order
