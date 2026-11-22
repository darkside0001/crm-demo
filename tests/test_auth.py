"""Authentication: hashing, JWT validation, lockout, refresh rotation (OWASP API2 / A07)."""

import base64
import json
from datetime import datetime, timedelta, timezone

import jwt

from app.models import AuditLog, AuthFailure, User
from tests.conftest import ADMIN, PASSWORD, SELLER


def test_password_is_stored_as_argon2id(ctx):
    with ctx.session() as db:
        user = db.query(User).filter_by(email=SELLER).one()
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


def test_login_success_returns_tokens(ctx):
    r = ctx.login(SELLER)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 15 * 60
    assert ctx.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}).json()["email"] == SELLER


def test_login_is_case_insensitive_on_email(ctx):
    assert ctx.login(SELLER.upper()).status_code == 200


def test_unknown_user_and_wrong_password_look_identical(ctx):
    a = ctx.login("nobody@example.com", "whatever-password")
    b = ctx.login(SELLER, "wrong-password-123")
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_source_is_blocked_after_repeated_failures(ctx):
    for _ in range(5):
        assert ctx.login(SELLER, "wrong-password-123").status_code == 401
    # The same source now gets the generic 401 even with the right password.
    r = ctx.login(SELLER)
    assert r.status_code == 401
    with ctx.session() as db:
        actions = [a.action for a in db.query(AuditLog).all()]
    assert "source_blocked" in actions and "login_blocked" in actions


def test_block_expires(ctx):
    for _ in range(5):
        ctx.login(SELLER, "wrong-password-123")
    with ctx.session() as db:
        for row in db.query(AuthFailure).all():
            row.at = datetime.now(timezone.utc) - timedelta(minutes=16)
        db.commit()
    assert ctx.login(SELLER).status_code == 200


def test_account_locks_under_distributed_guessing(make_ctx):
    ctx = make_ctx(trust_proxy=True, login_account_lock_failures=12)
    for i in range(12):
        ip = f"203.0.113.{i // 4 + 1}"  # 3 sources, 4 tries each: none hits the per-source limit
        r = ctx.client.post("/api/v1/auth/login", json={"email": SELLER, "password": "wrong-password-123"},
                            headers={"X-Forwarded-For": ip})
        assert r.status_code == 401
    r = ctx.client.post("/api/v1/auth/login", json={"email": SELLER, "password": PASSWORD},
                        headers={"X-Forwarded-For": "192.0.2.20"})
    assert r.status_code == 401
    with ctx.session() as db:
        user = db.query(User).filter_by(email=SELLER).one()
        assert user.locked_until is not None
        assert "account_locked" in [a.action for a in db.query(AuditLog).all()]


def test_disabled_user_cannot_log_in(ctx):
    with ctx.session() as db:
        db.query(User).filter_by(email=SELLER).one().is_active = False
        db.commit()
    assert ctx.login(SELLER).status_code == 401


def test_missing_and_garbage_tokens_rejected(ctx):
    assert ctx.client.get("/api/v1/auth/me").status_code == 401
    r = ctx.client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_alg_none_token_rejected(ctx):
    real = jwt.decode(ctx.login(ADMIN).json()["access_token"], options={"verify_signature": False})
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(real)}."
    assert ctx.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_signed_with_other_key_rejected(ctx):
    real = jwt.decode(ctx.login(SELLER).json()["access_token"], options={"verify_signature": False})
    real["role"] = "admin"
    forged = jwt.encode(real, "attacker-key-" + "y" * 40, algorithm="HS256")
    assert ctx.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_rejected(ctx):
    settings = ctx.app.state.settings
    claims = jwt.decode(
        ctx.login(SELLER).json()["access_token"], settings.jwt_secret, algorithms=["HS256"],
        audience=settings.jwt_audience,
    )
    claims["exp"] = datetime.now(timezone.utc) - timedelta(minutes=1)
    token = jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
    assert ctx.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_role_claim_in_token_is_not_trusted(ctx):
    """Even a validly signed token claiming admin gets the role from the database."""
    settings = ctx.app.state.settings
    claims = jwt.decode(
        ctx.login(SELLER).json()["access_token"], settings.jwt_secret, algorithms=["HS256"],
        audience=settings.jwt_audience,
    )
    claims["role"] = "admin"
    token = jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
    assert ctx.client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_refresh_rotates_and_detects_reuse(ctx):
    first = ctx.login(SELLER).json()
    r = ctx.client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 200
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]

    # Replaying the old token = theft signal: whole family is revoked.
    assert ctx.client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert ctx.client.post("/api/v1/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code == 401
    with ctx.session() as db:
        assert db.query(AuditLog).filter_by(action="refresh_reuse_detected").count() >= 1


def test_logout_revokes_refresh_token(ctx):
    tokens = ctx.login(SELLER).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert ctx.client.post("/api/v1/auth/logout", headers=h, json={"refresh_token": tokens["refresh_token"]}).status_code == 204
    assert ctx.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_password_change_kills_existing_sessions(ctx):
    tokens = ctx.login(SELLER).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    r = ctx.client.post(
        "/api/v1/auth/change-password", headers=h,
        json={"current_password": PASSWORD, "new_password": "N3w!Sufficiently-Long"},
    )
    assert r.status_code == 204
    assert ctx.client.get("/api/v1/auth/me", headers=h).status_code == 401
    assert ctx.client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert ctx.login(SELLER, "N3w!Sufficiently-Long").status_code == 200


def test_weak_new_password_rejected(ctx):
    for weak in ["short1!A", "alllowercaseletters", "seller-Password-123"]:
        r = ctx.post("/api/v1/auth/change-password", SELLER, json={"current_password": PASSWORD, "new_password": weak})
        assert r.status_code == 422, weak


def test_password_never_written_to_audit_log(ctx):
    ctx.login(SELLER, "wrong-password-123")
    ctx.login(SELLER)
    with ctx.session() as db:
        dump = json.dumps([a.details for a in db.query(AuditLog).all()])
    assert PASSWORD not in dump and "wrong-password-123" not in dump
