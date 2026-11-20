"""crm-demo: a retail CRM API built to show secure backend practices."""

import logging

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import errors, middleware
from app.config import Settings, get_settings
from app.db import Database
from app.routers import audit_log, auth, customers, orders, products, users

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    docs = not settings.is_production  # no public API explorer in production

    app = FastAPI(
        title="crm-demo",
        version="1.0.0",
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.db = Database(settings.database_url)
    app.state.db.create_all()
    app.state.limiter = middleware.RateLimiter()

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,  # bearer tokens, no cookies
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Authorization", "Content-Type"],
        )
    middleware.install(app, settings, app.state.limiter)
    errors.install(app)

    api = APIRouter(prefix="/api/v1")
    for r in (auth, users, products, customers, orders, audit_log):
        api.include_router(r.router)
    app.include_router(api)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    return app
