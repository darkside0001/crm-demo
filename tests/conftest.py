import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Customer, Product, Role, User
from app.security import hash_password

PASSWORD = "Str0ng!Passw0rd"
# Hashing is the slow part of the suite, so hash once.
_HASH = hash_password(PASSWORD)


# Set CRM_TEST_DATABASE_URL to run the suite against PostgreSQL (CI does).
# That database is wiped before every test.
TEST_DB = os.environ.get("CRM_TEST_DATABASE_URL", "sqlite://")


def make_settings(**overrides) -> Settings:
    base = dict(
        env="test",
        database_url=TEST_DB,
        jwt_secret="test-secret-" + "x" * 40,
        rate_limit_enabled=False,
    )
    base.update(overrides)
    return Settings(**base)


class Ctx:
    def __init__(self, client: TestClient):
        self.client = client
        self.app = client.app
        self.tokens: dict[str, dict] = {}

    def session(self):
        return self.app.state.db.SessionLocal()

    def add_user(self, email: str, role: Role) -> int:
        with self.session() as db:
            user = User(email=email, full_name=email.split("@")[0], role=role, password_hash=_HASH)
            db.add(user)
            db.commit()
            return user.id

    def login(self, email: str, password: str = PASSWORD):
        return self.client.post("/api/v1/auth/login", json={"email": email, "password": password})

    def headers(self, email: str) -> dict:
        if email not in self.tokens:
            r = self.login(email)
            assert r.status_code == 200, r.text
            self.tokens[email] = r.json()
        return {"Authorization": f"Bearer {self.tokens[email]['access_token']}"}

    def get(self, url, who, **kw):
        return self.client.get(url, headers=self.headers(who), **kw)

    def post(self, url, who, **kw):
        return self.client.post(url, headers=self.headers(who), **kw)

    def patch(self, url, who, **kw):
        return self.client.patch(url, headers=self.headers(who), **kw)


ADMIN, MANAGER, SELLER, SELLER2 = "admin@example.com", "manager@example.com", "seller@example.com", "seller2@example.com"


def _wipe(url: str) -> None:
    if url.startswith("sqlite"):
        return
    from app import models  # noqa: F401
    from app.db import Base, make_engine

    engine = make_engine(url)
    Base.metadata.drop_all(engine)
    engine.dispose()


def build(settings: Settings) -> Ctx:
    _wipe(settings.database_url)
    client = TestClient(create_app(settings))
    ctx = Ctx(client)
    ctx.ids = {
        ADMIN: ctx.add_user(ADMIN, Role.admin),
        MANAGER: ctx.add_user(MANAGER, Role.manager),
        SELLER: ctx.add_user(SELLER, Role.seller),
        SELLER2: ctx.add_user(SELLER2, Role.seller),
    }
    with ctx.session() as db:
        p1 = Product(sku="SH-001", name="Oxford shirt", category="Shirts", size="M", price=289_000, stock=10)
        p2 = Product(sku="JN-001", name="Slim jeans", category="Jeans", size="32", price=459_000, stock=2)
        c1 = Customer(full_name="Demo Customer", phone="+998901234567", email="demo@example.com",
                      created_by_id=ctx.ids[SELLER])
        db.add_all([p1, p2, c1])
        db.commit()
        ctx.product_id, ctx.product2_id, ctx.customer_id = p1.id, p2.id, c1.id
    return ctx


@pytest.fixture
def ctx() -> Ctx:
    return build(make_settings())


@pytest.fixture
def make_ctx():
    return lambda **kw: build(make_settings(**kw))
