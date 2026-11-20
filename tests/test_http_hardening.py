"""Security headers, error handling, rate limiting, config (OWASP A05, API4, API8)."""

import pytest
from pydantic import ValidationError

from tests.conftest import SELLER, make_settings


def test_security_headers_present(ctx):
    r = ctx.client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert len(r.headers["x-request-id"]) == 16
    assert "server" not in r.headers


def test_headers_also_on_errors(ctx):
    r = ctx.client.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.headers["x-content-type-options"] == "nosniff"


def test_hsts_when_enabled(make_ctx):
    assert "strict-transport-security" in make_ctx(enable_hsts=True).client.get("/health").headers


def test_error_shape_and_request_id(ctx):
    r = ctx.get("/api/v1/orders/424242", SELLER)
    err = r.json()["error"]
    assert r.status_code == 404
    assert set(err) == {"code", "message", "request_id"}
    assert err["request_id"] == r.headers["x-request-id"]


def test_unhandled_error_hides_internals(ctx):
    @ctx.app.get("/boom")
    def boom():
        raise RuntimeError("db password is hunter2")

    from fastapi.testclient import TestClient

    r = TestClient(ctx.app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    assert "hunter2" not in r.text and "Traceback" not in r.text
    assert r.json()["error"]["code"] == "internal"


def test_oversized_body_rejected(ctx):
    r = ctx.client.post("/api/v1/auth/login", content=b"x" * 1_000_001, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_login_rate_limited(make_ctx):
    ctx = make_ctx(rate_limit_enabled=True, rate_limit_login=3, login_max_failures=100)
    codes = [ctx.login("nobody@example.com", "wrong-password").status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    r = ctx.login("nobody@example.com", "wrong-password")
    assert int(r.headers["retry-after"]) > 0


def test_global_rate_limit(make_ctx):
    ctx = make_ctx(rate_limit_enabled=True, rate_limit_default=5)
    codes = [ctx.client.get("/health").status_code for _ in range(7)]
    assert codes.count(429) == 2


def test_forwarded_for_ignored_unless_proxy_trusted(make_ctx):
    ctx = make_ctx(rate_limit_enabled=True, rate_limit_login=2, login_max_failures=100)
    # Spoofing X-Forwarded-For must not give an attacker fresh rate-limit buckets.
    codes = [
        ctx.client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "x"},
                        headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code
        for i in range(4)
    ]
    assert codes[-1] == 429


def test_docs_disabled_in_production(make_ctx):
    ctx = make_ctx(env="production")
    assert ctx.client.get("/docs").status_code == 404
    assert ctx.client.get("/openapi.json").status_code == 404


def test_docs_available_in_development(ctx):
    assert ctx.client.get("/openapi.json").status_code == 200


def test_production_refuses_weak_secret():
    with pytest.raises(ValidationError):
        make_settings(env="production", jwt_secret="short")


def test_wildcard_cors_refused():
    with pytest.raises(ValidationError):
        make_settings(cors_origins=["*"])


def test_cors_allows_only_listed_origin(make_ctx):
    ctx = make_ctx(cors_origins=["https://crm.example.com"])
    ok = ctx.client.options("/api/v1/products", headers={"Origin": "https://crm.example.com", "Access-Control-Request-Method": "GET"})
    bad = ctx.client.options("/api/v1/products", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://crm.example.com"
    assert "access-control-allow-origin" not in bad.headers
