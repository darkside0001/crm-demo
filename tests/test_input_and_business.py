"""Input validation, mass assignment, injection, business-logic abuse (API3, API6, A03)."""

import pytest

from app.models import Product
from tests.conftest import ADMIN, MANAGER, SELLER, TEST_DB


def test_mass_assignment_rejected(ctx):
    # A seller tries to set the price of an order line and who sold it.
    r = ctx.post("/api/v1/orders", SELLER, json={
        "customer_id": ctx.customer_id, "seller_id": 1,
        "items": [{"product_id": ctx.product_id, "quantity": 1, "unit_price": 1}],
    })
    assert r.status_code == 422
    fields = {f["field"] for f in r.json()["error"]["fields"]}
    assert "seller_id" in fields and "items.0.unit_price" in fields


def test_user_cannot_set_hidden_fields(ctx):
    body = {"email": "new@example.com", "full_name": "New", "password": "Str0ng!Passw0rd", "role": "seller",
            "token_version": 0, "is_active": True}
    assert ctx.post("/api/v1/users", ADMIN, json=body).status_code == 422


def test_price_comes_from_server(ctx):
    r = ctx.post("/api/v1/orders", SELLER, json={"customer_id": ctx.customer_id, "items": [
        {"product_id": ctx.product_id, "quantity": 2}, {"product_id": ctx.product_id, "quantity": 1},
    ]})
    assert r.status_code == 201
    order = r.json()
    assert order["total"] == 3 * 289_000
    assert order["items"] == [{"product_id": ctx.product_id, "quantity": 3, "unit_price": 289_000}]


@pytest.mark.parametrize("qty", [0, -1, 1001, "2", 1.5])
def test_bad_quantities_rejected(ctx, qty):
    r = ctx.post("/api/v1/orders", SELLER, json={"customer_id": ctx.customer_id, "items": [{"product_id": ctx.product_id, "quantity": qty}]})
    assert r.status_code == 422


def test_cannot_oversell(ctx):
    # product2 has stock 2
    body = {"customer_id": ctx.customer_id, "items": [{"product_id": ctx.product2_id, "quantity": 3}]}
    assert ctx.post("/api/v1/orders", SELLER, json=body).status_code == 409
    with ctx.session() as db:
        assert db.get(Product, ctx.product2_id).stock == 2


def test_failed_order_does_not_reserve_other_lines(ctx):
    body = {"customer_id": ctx.customer_id, "items": [
        {"product_id": ctx.product_id, "quantity": 1}, {"product_id": ctx.product2_id, "quantity": 99},
    ]}
    assert ctx.post("/api/v1/orders", SELLER, json=body).status_code == 409
    with ctx.session() as db:
        assert db.get(Product, ctx.product_id).stock == 10


def test_cancel_returns_stock(ctx):
    r = ctx.post("/api/v1/orders", SELLER, json={"customer_id": ctx.customer_id, "items": [{"product_id": ctx.product2_id, "quantity": 2}]})
    order_id = r.json()["id"]
    with ctx.session() as db:
        assert db.get(Product, ctx.product2_id).stock == 0
    assert ctx.post(f"/api/v1/orders/{order_id}/status", MANAGER, json={"status": "cancelled"}).status_code == 200
    with ctx.session() as db:
        assert db.get(Product, ctx.product2_id).stock == 2
    # Cancelled is final: no double refund of stock.
    assert ctx.post(f"/api/v1/orders/{order_id}/status", MANAGER, json={"status": "cancelled"}).status_code == 409


def test_stock_cannot_go_negative(ctx):
    r = ctx.post(f"/api/v1/products/{ctx.product2_id}/stock", MANAGER, json={"delta": -3, "reason": "damaged"})
    assert r.status_code == 409


def test_negative_price_rejected(ctx):
    assert ctx.patch(f"/api/v1/products/{ctx.product_id}", MANAGER, json={"price": -1}).status_code == 422


def test_price_change_is_audited(ctx):
    ctx.patch(f"/api/v1/products/{ctx.product_id}", MANAGER, json={"price": 1000})
    entry = ctx.get("/api/v1/audit?action=price_changed", ADMIN).json()["items"][0]
    assert entry["details"] == {"old": 289_000, "new": 1000}
    assert entry["actor_id"] == ctx.ids[MANAGER]


@pytest.mark.parametrize("q", ["' OR '1'='1", "x'; DROP TABLE products; --", "%", "_", "\\"])
def test_search_is_injection_safe(ctx, q):
    r = ctx.get("/api/v1/products", SELLER, params={"q": q})
    assert r.status_code == 200
    assert r.json()["total"] == 0
    assert ctx.get("/api/v1/products", SELLER).json()["total"] == 2


def test_search_finds_literal_match(ctx):
    assert ctx.get("/api/v1/products", SELLER, params={"q": "oxford"}).json()["total"] == 1


def test_pagination_is_capped(ctx):
    assert ctx.get("/api/v1/products?limit=1000", SELLER).status_code == 422
    assert ctx.get("/api/v1/products?limit=100", SELLER).status_code == 200


@pytest.mark.parametrize("phone", ["12", "abc", "+99890123456789012", "<script>"])
def test_customer_phone_validated(ctx, phone):
    assert ctx.post("/api/v1/customers", SELLER, json={"full_name": "A", "phone": phone}).status_code == 422


def test_validation_error_does_not_echo_input(ctx):
    payload = "<script>alert(1)</script>"
    r = ctx.post("/api/v1/customers", SELLER, json={"full_name": "A", "phone": payload})
    assert payload not in r.text


def test_duplicate_sku_conflict(ctx):
    body = {"sku": "SH-001", "name": "Dup", "category": "Shirts", "price": 1}
    assert ctx.post("/api/v1/products", MANAGER, json=body).status_code == 409


@pytest.mark.skipif(not TEST_DB.startswith("postgresql"), reason="needs PostgreSQL row locking")
def test_concurrent_orders_cannot_oversell(ctx):
    from concurrent.futures import ThreadPoolExecutor

    headers = ctx.headers(SELLER)
    body = {"customer_id": ctx.customer_id, "items": [{"product_id": ctx.product2_id, "quantity": 1}]}

    def buy(_):
        return ctx.client.post("/api/v1/orders", headers=headers, json=body).status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(buy, range(10)))
    assert codes.count(201) == 2 and codes.count(409) == 8
    with ctx.session() as db:
        assert db.get(Product, ctx.product2_id).stock == 0
