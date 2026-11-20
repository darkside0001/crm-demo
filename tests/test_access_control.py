"""Authorization: RBAC (function level) and object-level checks (OWASP API1, API3, API5)."""

import pytest

from tests.conftest import ADMIN, MANAGER, SELLER, SELLER2


@pytest.mark.parametrize(
    "who,method,url,expected",
    [
        (SELLER, "get", "/api/v1/users", 403),
        (MANAGER, "get", "/api/v1/users", 403),
        (ADMIN, "get", "/api/v1/users", 200),
        (SELLER, "get", "/api/v1/audit", 403),
        (MANAGER, "get", "/api/v1/audit", 403),
        (ADMIN, "get", "/api/v1/audit", 200),
        (SELLER, "get", "/api/v1/products", 200),
    ],
)
def test_role_matrix_reads(ctx, who, method, url, expected):
    assert getattr(ctx, method)(url, who).status_code == expected


def test_seller_cannot_manage_catalogue(ctx):
    new = {"sku": "TS-001", "name": "Tee", "category": "Shirts", "price": 99_000}
    assert ctx.post("/api/v1/products", SELLER, json=new).status_code == 403
    assert ctx.patch(f"/api/v1/products/{ctx.product_id}", SELLER, json={"price": 1}).status_code == 403
    assert ctx.post(f"/api/v1/products/{ctx.product_id}/stock", SELLER, json={"delta": 5, "reason": "found"}).status_code == 403
    assert ctx.post("/api/v1/products", MANAGER, json=new).status_code == 201


def test_seller_cannot_create_users(ctx):
    body = {"email": "x@example.com", "full_name": "X", "password": "Str0ng!Passw0rd", "role": "admin"}
    assert ctx.post("/api/v1/users", SELLER, json=body).status_code == 403


def _order(ctx, who):
    r = ctx.post("/api/v1/orders", who, json={"customer_id": ctx.customer_id, "items": [{"product_id": ctx.product_id, "quantity": 1}]})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_seller_cannot_see_other_sellers_order(ctx):
    order_id = _order(ctx, SELLER)
    assert ctx.get(f"/api/v1/orders/{order_id}", SELLER).status_code == 200
    # BOLA: guessing another id returns 404, the same as a missing order.
    assert ctx.get(f"/api/v1/orders/{order_id}", SELLER2).status_code == 404
    assert ctx.get("/api/v1/orders/99999", SELLER2).status_code == 404
    assert ctx.get("/api/v1/orders", SELLER2).json()["total"] == 0
    assert ctx.get(f"/api/v1/orders/{order_id}", MANAGER).status_code == 200


def test_seller_cannot_change_other_sellers_order(ctx):
    order_id = _order(ctx, SELLER)
    assert ctx.post(f"/api/v1/orders/{order_id}/status", SELLER2, json={"status": "paid"}).status_code == 404


def test_seller_cannot_cancel_or_ship(ctx):
    order_id = _order(ctx, SELLER)
    assert ctx.post(f"/api/v1/orders/{order_id}/status", SELLER, json={"status": "cancelled"}).status_code == 403
    assert ctx.post(f"/api/v1/orders/{order_id}/status", SELLER, json={"status": "paid"}).status_code == 200
    assert ctx.post(f"/api/v1/orders/{order_id}/status", SELLER, json={"status": "shipped"}).status_code == 403
    assert ctx.post(f"/api/v1/orders/{order_id}/status", MANAGER, json={"status": "shipped"}).status_code == 200


def test_seller_edits_only_own_customers(ctx):
    r = ctx.post("/api/v1/customers", SELLER2, json={"full_name": "Other", "phone": "+998907777777"})
    other_id = r.json()["id"]
    assert ctx.patch(f"/api/v1/customers/{other_id}", SELLER, json={"notes": "x"}).status_code == 403
    assert ctx.patch(f"/api/v1/customers/{ctx.customer_id}", SELLER, json={"notes": "VIP"}).status_code == 200
    assert ctx.patch(f"/api/v1/customers/{other_id}", MANAGER, json={"notes": "ok"}).status_code == 200


def test_seller_sees_masked_pii_in_lists(ctx):
    item = ctx.get("/api/v1/customers", SELLER).json()["items"][0]
    assert item["phone"] == "+998******567" and item["email"] == "d***@example.com"
    assert ctx.get("/api/v1/customers", MANAGER).json()["items"][0]["phone"] == "+998901234567"


def test_opening_customer_card_is_audited(ctx):
    ctx.get(f"/api/v1/customers/{ctx.customer_id}", SELLER)
    log = ctx.get("/api/v1/audit?action=customer_viewed", ADMIN).json()
    assert log["total"] == 1 and log["items"][0]["actor_id"] == ctx.ids[SELLER]


def test_demotion_takes_effect_immediately(ctx):
    h = ctx.headers(MANAGER)
    assert ctx.client.get("/api/v1/products", headers=h).status_code == 200
    r = ctx.patch(f"/api/v1/users/{ctx.ids[MANAGER]}", ADMIN, json={"role": "seller"})
    assert r.status_code == 200
    # Old token was issued before the change: it no longer works at all.
    assert ctx.client.get("/api/v1/products", headers=h).status_code == 401


def test_admin_cannot_lock_themselves_out(ctx):
    assert ctx.patch(f"/api/v1/users/{ctx.ids[ADMIN]}", ADMIN, json={"role": "seller"}).status_code == 400
    assert ctx.patch(f"/api/v1/users/{ctx.ids[ADMIN]}", ADMIN, json={"is_active": False}).status_code == 400


def test_responses_never_include_password_hash(ctx):
    body = ctx.get("/api/v1/users", ADMIN).text + ctx.get("/api/v1/auth/me", SELLER).text
    assert "password" not in body and "argon2" not in body and "failed_logins" not in body
