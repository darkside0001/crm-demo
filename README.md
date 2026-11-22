# crm-demo

[![ci](https://github.com/darkside0001/crm-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/darkside0001/crm-demo/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A REST API for a small clothing store CRM (products, stock, customers, orders), written to show how I
secure a backend. Every control below has a test that tries to break it.

**Penetration test:** I attacked my own first version with an authenticated test harness, found 8 issues
(top CVSS 6.8), fixed them and re-ran the same attacks. Full report: [docs/pentest-report.md](docs/pentest-report.md).

I build CRM systems for retail clients. Their code and data stay private, so this is a separate, smaller
codebase with fictional data. The stack is the one I use in production: **FastAPI, PostgreSQL, PyJWT**.

## What it does

| Area | Endpoints | Who |
|---|---|---|
| Auth | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/change-password`, `GET /auth/me` | everyone |
| Staff | `GET/POST /users`, `PATCH /users/{id}` | admin |
| Catalogue | `GET /products`, `GET /products/{id}` | all staff |
|  | `POST /products`, `PATCH /products/{id}`, `POST /products/{id}/stock` | admin, manager |
| Customers | `GET/POST /customers`, `GET/PATCH /customers/{id}` | all staff (sellers edit only their own) |
| Orders | `GET/POST /orders`, `GET /orders/{id}`, `POST /orders/{id}/status` | all staff (sellers see only their own) |
| Audit log | `GET /audit` | admin |

All routes are under `/api/v1`. Money is stored as integers (whole UZS), never floats.

### Roles

| Action | admin | manager | seller |
|---|:-:|:-:|:-:|
| Create staff, change roles, read audit log | ✓ | | |
| Create products, change prices, adjust stock | ✓ | ✓ | |
| Ship or cancel an order | ✓ | ✓ | |
| See all orders, full customer phone numbers in lists | ✓ | ✓ | |
| Create customers and orders, mark own order paid | ✓ | ✓ | ✓ |
| See and change only own orders | | | ✓ |

## Security controls

Mapped to the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
The test column points to the test that checks each one.

| OWASP | Risk | What this API does | Tests |
|---|---|---|---|
| **API1** | Broken object level authorization | Sellers' order queries are always filtered by `seller_id`. Another seller's order returns **404**, the same as a missing one, so ids cannot be probed. Sellers edit only customers they registered, and see a customer's full phone and email only if they registered that customer or sold to them. | `test_seller_cannot_see_other_sellers_order`, `test_seller_edits_only_own_customers`, `test_f01_*` |
| **API2** | Broken authentication | Argon2id password hashes. Access JWT lives 15 minutes, with pinned `HS256` and required `exp`, `iss`, `aud`, `jti`. Refresh tokens are random, stored only as SHA-256, rotated on every use; replaying an old one revokes the whole session family. Failed logins are counted per account *and* client IP: 5 wrong passwords block that source for 15 minutes, so an attacker cannot lock the real user out; 50 failures from all sources lock the account (distributed guessing). Every attempt is committed before the password is checked, so parallel requests cannot exceed the limit. Logout revokes the access token too (`jti` denylist). Guessing the current password in change-password with a stolen session ends every session of the account. The same error is returned for unknown email, wrong password and locked account, and an unknown email still runs a hash check so timing gives nothing away. Password policy: 12+ characters, 3 character classes, not common, not the email name. | `tests/test_auth.py` (alg `none`, wrong key, expired, reuse detection, lockout), `test_f03_*`, `test_f04_*`, `test_f05_*`, `test_f08_*` |
| **API3** | Broken object property level authorization | Every input model has `extra="forbid"` and strict types, so `role`, `seller_id` or `unit_price` cannot be smuggled in. Every response model lists its fields, so `password_hash`, `failed_logins` and `token_version` never leave the server. Sellers get masked phone and email in customer lists, and can search phone numbers only by exact match, so the hidden digits cannot be rebuilt one query at a time. | `test_mass_assignment_rejected`, `test_responses_never_include_password_hash`, `test_seller_sees_masked_pii_in_lists`, `test_f02_*` |
| **API4** | Unrestricted resource consumption | Rate limit per IP (120/min overall, 10/min on login and refresh) with `Retry-After`. `limit` capped at 100. Request bodies over 1 MB rejected, by `Content-Length` and by counting the bytes of chunked uploads. Max 50 lines per order, string lengths bounded. | `test_login_rate_limited`, `test_pagination_is_capped`, `test_oversized_body_rejected`, `test_f07_*` |
| **API5** | Broken function level authorization | Each route declares its roles with `require_roles(...)`. The role is read from the database on every request, not trusted from the token: a demoted or disabled user loses access on the next call. | `test_role_matrix_reads`, `test_role_claim_in_token_is_not_trusted`, `test_demotion_takes_effect_immediately` |
| **API6** | Unrestricted access to sensitive business flows | Order prices always come from the catalogue. Stock is reserved with one conditional `UPDATE ... WHERE stock >= qty`, so concurrent orders cannot oversell. Status changes follow a fixed state machine, so a cancelled order cannot be cancelled twice to return stock twice. A seller can hold at most 10 unpaid orders, so one account cannot reserve the whole stock. | `test_price_comes_from_server`, `test_concurrent_orders_cannot_oversell` (PostgreSQL), `test_cancel_returns_stock`, `test_f06_*` |
| **API7** | Server-side request forgery | The API makes no outbound requests from user input. | n/a |
| **API8** | Security misconfiguration | Strict security headers on every response (CSP `default-src 'none'`, `nosniff`, `DENY` framing, `no-store`, optional HSTS), no `Server` header. CORS is an explicit allow-list; `*` is refused at startup. Swagger UI and OpenAPI are off in production. The app will not start in production without a 32+ character JWT secret. Errors have one shape and never contain stack traces. | `tests/test_http_hardening.py` |
| **API9** | Improper inventory management | One versioned prefix (`/api/v1`), no debug or legacy routes, docs hidden in production. | `test_docs_disabled_in_production` |
| **API10** | Unsafe consumption of APIs | No third-party API data is consumed. | n/a |

Also covered from the [OWASP Top 10 (2021)](https://owasp.org/Top10/):

- **A03 Injection.** SQLAlchemy with bound parameters only; `%` and `_` in search terms are escaped so a search box cannot become a full-table wildcard scan. Tests send classic payloads (`' OR '1'='1`, `; DROP TABLE`).
- **A06 Vulnerable components.** Dependencies are pinned; CI runs `pip-audit` and `bandit` on every push.
- **A09 Logging and monitoring failures.** Append-only audit log (no update or delete route) records logins, failures, lockouts, refresh-token reuse, role changes, price changes, stock adjustments, order status changes and every opening of a full customer card. Each entry has actor, IP and request id; the same request id is returned in the `X-Request-ID` header. Passwords and tokens are redacted even if passed in by mistake.

## Try it

### Docker

```bash
cp .env.example .env        # set CRM_JWT_SECRET, POSTGRES_PASSWORD, CRM_ADMIN_PASSWORD
docker compose up --build -d
docker compose exec api python -m scripts.seed
curl http://127.0.0.1:8000/health
```

The database has no published port, and the API container runs as a non-root user with a read-only
filesystem and all Linux capabilities dropped.

### Local (Windows PowerShell)

```powershell
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements-dev.txt
$env:CRM_ENV="development"; $env:CRM_ADMIN_EMAIL="admin@example.com"; $env:CRM_ADMIN_PASSWORD="Blue!Harbor-2026"
python -m scripts.seed
uvicorn app.main:create_app --factory --reload   # http://127.0.0.1:8000/docs
```

Without `CRM_DATABASE_URL` it uses a local SQLite file.

### What an attacker sees

Output from a real run (production mode, PostgreSQL):

```text
# seller sets their own price on an order line
POST /api/v1/orders {"customer_id":1,"items":[{"product_id":1,"quantity":1,"unit_price":1}]}
422 {"error":{"code":"validation_error","message":"Invalid input","fields":[{"field":"items.0.unit_price","issue":"Extra inputs are not permitted"}]}}

# seller2 reads seller1's order
GET /api/v1/orders/1
404 {"error":{"code":"not_found","message":"Order not found","request_id":"0ac4ce594d5c68d4"}}

# seller changes a price
PATCH /api/v1/products/1 {"price":1}
403 {"error":{"code":"forbidden","message":"Your role cannot perform this action"}}

# SQL injection in search
GET /api/v1/products?q=' OR 1=1 --
200 {"items":[],"total":0,"limit":20,"offset":0}

# password guessing: 5 wrong attempts, then the right password from the same address
401 401 401 401 401 -> 401 "Invalid email or password"   (source blocked, attacker can't tell)
# the real user, from their own address, at the same moment
200 {"access_token": "...", ...}
```

And what the admin sees in `GET /api/v1/audit`:

```text
login_success   actor=3 user#3                     ip=198.51.100.7
login_blocked   actor=3 user#3 {"scope": "source"} ip=203.0.113.66
source_blocked  actor=3 user#3                     ip=203.0.113.66
login_failed    actor=3 user#3 {"reason": "bad_password"} ip=203.0.113.66
```

## Tests

```bash
pytest                                   # 91 tests on SQLite, about 15 seconds
CRM_TEST_DATABASE_URL=postgresql+psycopg://crm:crm@localhost:5432/crm_test pytest   # adds the concurrency test
```

CI runs the suite on Python 3.12 and 3.13, again on PostgreSQL 17, then `bandit`, `pip-audit` and a Docker build.

| File | Covers |
|---|---|
| `tests/test_auth.py` | hashing, login, lockout, forged and expired JWTs, refresh rotation and reuse, password change |
| `tests/test_access_control.py` | role matrix, BOLA, own-record rules, PII masking, instant demotion |
| `tests/test_input_and_business.py` | mass assignment, strict types, price tampering, overselling, injection, pagination |
| `tests/test_http_hardening.py` | headers, error shape, rate limits, body size, CORS, production config |
| `tests/test_pentest_regressions.py` | one test per pentest finding F-01 to F-08, so a fixed bug stays fixed |

The pentest harness itself (`pentest/harness.py`) runs against a live instance; see the report for how.

## Project layout

```
app/
  main.py         app factory, wiring
  config.py       settings from env, refuses unsafe production config
  security.py     Argon2id, JWT, refresh tokens, password policy
  deps.py         current user, role checks, revoked-token check
  throttle.py     login and password-change attempt limits per account and IP
  middleware.py   request id, body limit, rate limiter, security headers
  errors.py       single error format, no internals in responses
  audit.py        audit log writer with redaction
  models.py       SQLAlchemy models
  schemas.py      strict Pydantic input / explicit output models
  routers/        auth, users, products, customers, orders, audit_log
scripts/seed.py   first admin + fictional demo data
pentest/          attack harness and raw results before / after the fixes
docs/             pentest report
tests/
```

## Before running this for real

Things I left out on purpose to keep the demo small, and what I would do in production:

- **Migrations.** Tables are created at startup. A real deployment uses versioned migrations (Alembic or plain SQL files).
- **Rate limiter.** Counters live in process memory. With several workers or servers they go to Redis.
- **TLS.** The API speaks plain HTTP and expects a reverse proxy (Caddy, nginx) for HTTPS. Turn on `CRM_ENABLE_HSTS` and `CRM_TRUST_PROXY` only behind that proxy.
- **Refresh token storage.** It is returned in the JSON body, which suits mobile and server clients. For a browser front end I would move it to an `HttpOnly; Secure; SameSite=Strict` cookie.
- **Breached passwords.** The common-password list is tiny. Production would check the Pwned Passwords k-anonymity API.
- **MFA** for admin accounts.

## License

MIT
