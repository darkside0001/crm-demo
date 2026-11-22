"""Application settings, loaded from environment variables.

Secrets never live in code. In production the app refuses to start with a
missing or weak JWT secret instead of silently falling back to a default.
"""

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CRM_", extra="ignore")

    env: str = Field(default="development", pattern="^(development|test|production)$")
    database_url: str = "sqlite:///./crm.db"

    jwt_secret: str = ""
    jwt_issuer: str = "crm-demo"
    jwt_audience: str = "crm-demo-api"
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1, le=30)

    # Brute-force protection
    login_max_failures: int = 5  # per account *and* client IP, within the window
    login_lockout_minutes: int = 15  # the window, and how long a source stays blocked
    # Failures from all IPs together that lock the account itself (distributed attack).
    login_account_lock_failures: int = 50

    # Business limits (OWASP API6): unpaid orders one seller may keep open.
    max_open_orders_per_seller: int = 10

    # Rate limiting (requests per window, per client IP)
    rate_limit_enabled: bool = True
    rate_limit_default: int = 120  # per minute, any endpoint
    rate_limit_login: int = 10  # per minute, /auth/login and /auth/refresh

    # Only trust X-Forwarded-For when running behind a known reverse proxy
    trust_proxy: bool = False

    cors_origins: list[str] = []
    max_body_bytes: int = 1_000_000
    enable_hsts: bool = False

    @field_validator("cors_origins")
    @classmethod
    def no_wildcard_origin(cls, v: list[str]) -> list[str]:
        if "*" in v:
            raise ValueError("wildcard CORS origin is not allowed with credentials")
        return v

    @model_validator(mode="after")
    def check_secret(self) -> "Settings":
        if self.env == "production" and len(self.jwt_secret) < 32:
            raise ValueError("CRM_JWT_SECRET must be set to at least 32 characters in production")
        if not self.jwt_secret:
            # Development/test only: a random per-process secret. Tokens die on restart.
            import secrets

            self.jwt_secret = secrets.token_urlsafe(48)
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
