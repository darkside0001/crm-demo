"""One error shape for every response, and no internals in it.

    {"error": {"code": "...", "message": "...", "request_id": "..."}}
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("crm")

_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    423: "locked",
    429: "rate_limited",
}


class AppError(HTTPException):
    def __init__(self, status: int, message: str, code: str | None = None, headers=None):
        super().__init__(status_code=status, detail=message, headers=headers)
        self.code = code or _CODES.get(status, "error")


def error_body(request: Request, status: int, message: str, code: str | None = None, **extra) -> dict:
    body = {
        "code": code or _CODES.get(status, "error"),
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    body.update(extra)
    return {"error": body}


def install(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        code = getattr(exc, "code", None)
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(
            error_body(request, exc.status_code, message, code),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Report where and what, but never echo the submitted value back.
        fields = [
            {"field": ".".join(str(p) for p in e["loc"] if p != "body"), "issue": e["msg"]}
            for e in exc.errors()
        ]
        return JSONResponse(
            error_body(request, 422, "Invalid input", fields=fields), status_code=422
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Full detail goes to the server log, the client gets a request id only.
        log.exception("unhandled error request_id=%s", getattr(request.state, "request_id", None))
        return JSONResponse(error_body(request, 500, "Internal server error", "internal"), status_code=500)
