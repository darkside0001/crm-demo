"""Request and response models.

Every input model forbids unknown fields, so a client cannot slip in `role`,
`price` or `seller_id` where they are not expected (mass assignment).
Every response model lists its fields explicitly, so internal columns such
as password_hash or failed_logins can never leak (excessive data exposure).
"""

from datetime import datetime
from typing import Annotated, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.models import OrderStatus, Role

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Phone = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^\+?[0-9]{9,15}$")]
Sku = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Z0-9-]{3,32}$")]
Money = Annotated[int, Field(ge=0, le=1_000_000_000)]
# Input models are strict; enums still have to accept their JSON string value.
RoleIn = Annotated[Role, Field(strict=False)]
StatusIn = Annotated[OrderStatus, Field(strict=False)]


class In(BaseModel):
    # strict: "2" is not silently turned into 2, 1.5 is not truncated.
    model_config = ConfigDict(extra="forbid", strict=True)


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth -----------------------------------------------------------------


class LoginIn(In):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]


class RefreshIn(In):
    refresh_token: Annotated[str, Field(min_length=20, max_length=200)]


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class PasswordChangeIn(In):
    current_password: Annotated[str, Field(max_length=128)]
    new_password: Annotated[str, Field(max_length=128)]


# --- users ----------------------------------------------------------------


class UserCreate(In):
    email: EmailStr
    full_name: Name
    password: Annotated[str, Field(max_length=128)]
    role: RoleIn


class UserUpdate(In):
    full_name: Name | None = None
    role: RoleIn | None = None
    is_active: bool | None = None


class UserOut(Out):
    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool
    created_at: datetime


# --- products -------------------------------------------------------------


class ProductCreate(In):
    sku: Sku
    name: Name
    category: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]
    size: Annotated[str, StringConstraints(strip_whitespace=True, max_length=10)] | None = None
    price: Money
    stock: Annotated[int, Field(ge=0, le=1_000_000)] = 0


class ProductUpdate(In):
    name: Name | None = None
    category: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)] | None = None
    size: Annotated[str, StringConstraints(strip_whitespace=True, max_length=10)] | None = None
    price: Money | None = None
    is_active: bool | None = None


class StockAdjust(In):
    delta: Annotated[int, Field(ge=-100_000, le=100_000)]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=200)]


class ProductOut(Out):
    id: int
    sku: str
    name: str
    category: str
    size: str | None
    price: int
    stock: int
    is_active: bool


# --- customers ------------------------------------------------------------


class CustomerCreate(In):
    full_name: Name
    phone: Phone
    email: EmailStr | None = None
    notes: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None


class CustomerUpdate(In):
    full_name: Name | None = None
    phone: Phone | None = None
    email: EmailStr | None = None
    notes: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None


class CustomerOut(Out):
    id: int
    full_name: str
    phone: str
    email: str | None
    notes: str | None
    created_at: datetime


# --- orders ---------------------------------------------------------------


class OrderItemIn(In):
    product_id: Annotated[int, Field(gt=0)]
    quantity: Annotated[int, Field(ge=1, le=1000)]
    # Deliberately no price field: the server takes prices from the catalogue.


class OrderCreate(In):
    customer_id: Annotated[int, Field(gt=0)]
    items: Annotated[list[OrderItemIn], Field(min_length=1, max_length=50)]


class OrderStatusIn(In):
    status: StatusIn


class OrderItemOut(Out):
    product_id: int
    quantity: int
    unit_price: int


class OrderOut(Out):
    id: int
    customer_id: int
    seller_id: int
    status: OrderStatus
    total: int
    created_at: datetime
    items: list[OrderItemOut]


# --- audit ----------------------------------------------------------------


class AuditOut(Out):
    id: int
    at: datetime
    actor_id: int | None
    action: str
    entity: str | None
    entity_id: int | None
    ip: str | None
    request_id: str | None
    details: dict | None


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int
