from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app.deps import MANAGERS, STAFF, get_db, require_roles
from app.errors import AppError
from app.models import Product, User
from app.schemas import Page, ProductCreate, ProductOut, ProductUpdate, StockAdjust
from app.search import like_pattern

router = APIRouter(prefix="/products", tags=["products"])


@router.get("", response_model=Page[ProductOut])
def list_products(
    q: str | None = Query(None, max_length=60),
    category: str | None = Query(None, max_length=60),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
    _: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    stmt = select(Product)
    if q:
        # Bound parameter + escaped wildcards: no SQL injection, no LIKE abuse.
        stmt = stmt.where(Product.name.ilike(like_pattern(q), escape="\\"))
    if category:
        stmt = stmt.where(Product.category == category)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Product.id).limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.get("/{product_id}", response_model=ProductOut)
def get_product(product_id: int, _: User = Depends(require_roles(*STAFF)), db: Session = Depends(get_db)):
    product = db.get(Product, product_id)
    if product is None:
        raise AppError(404, "Product not found")
    return product


@router.post("", response_model=ProductOut, status_code=201)
def create_product(
    body: ProductCreate,
    request: Request,
    user: User = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
):
    if db.scalar(select(Product.id).where(Product.sku == body.sku)):
        raise AppError(409, "SKU already exists")
    product = Product(**body.model_dump())
    db.add(product)
    db.flush()
    audit.record(db, request, "product_created", actor_id=user.id, entity="product", entity_id=product.id)
    db.commit()
    return product


@router.patch("/{product_id}", response_model=ProductOut)
def update_product(
    product_id: int,
    body: ProductUpdate,
    request: Request,
    user: User = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
):
    product = db.get(Product, product_id)
    if product is None:
        raise AppError(404, "Product not found")
    changes = body.model_dump(exclude_unset=True)
    if "price" in changes and changes["price"] != product.price:
        # Price changes are a classic insider-fraud signal: always audited.
        audit.record(
            db, request, "price_changed", actor_id=user.id, entity="product", entity_id=product.id,
            old=product.price, new=changes["price"],
        )
    for k, v in changes.items():
        setattr(product, k, v)
    db.commit()
    return product


@router.post("/{product_id}/stock", response_model=ProductOut)
def adjust_stock(
    product_id: int,
    body: StockAdjust,
    request: Request,
    user: User = Depends(require_roles(*MANAGERS)),
    db: Session = Depends(get_db),
):
    # Single conditional UPDATE: stock can never go negative, even under
    # concurrent requests (no read-modify-write race).
    result = db.execute(
        update(Product)
        .where(Product.id == product_id, Product.stock + body.delta >= 0)
        .values(stock=Product.stock + body.delta)
    )
    if result.rowcount == 0:
        if db.get(Product, product_id) is None:
            raise AppError(404, "Product not found")
        raise AppError(409, "Stock cannot go below zero")
    audit.record(
        db, request, "stock_adjusted", actor_id=user.id, entity="product", entity_id=product_id,
        delta=body.delta, reason=body.reason,
    )
    db.commit()
    product = db.get(Product, product_id)
    db.refresh(product)
    return product
