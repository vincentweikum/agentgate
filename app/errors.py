"""One error format for every API response: RFC 9457 "Problem Details".

Every 4xx/5xx response from this API looks the same, so client teams (and AI
agents) can handle errors with one piece of code. Standard STD-ERR-01.
"""

from __future__ import annotations

import logging
import re

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .models import int32, text

PROBLEM_MEDIA_TYPE = "application/problem+json"
PROBLEM_BASE_URI = "https://docs.agentgate.example/problems/"

logger = logging.getLogger("agentgate.errors")


class FieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = text(200, description="Dotted path to the field that failed validation.")
    message: str = text(500, description="What was wrong with the field.")


class Problem(BaseModel):
    """RFC 9457 Problem Details object."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(max_length=300, pattern=r"^https://[A-Za-z0-9./_-]+$",
                      description="URI that identifies the problem type.", examples=[PROBLEM_BASE_URI + "not-found"])
    title: str = text(200, description="Short, human-readable summary of the problem type.")
    status: int = int32(400, 599, description="HTTP status code.")
    detail: str = text(1000, description="Human-readable explanation specific to this occurrence.")
    code: str = Field(max_length=64, pattern=r"^[a-z0-9_]+$", description="Stable machine-readable error code.")
    instance: str | None = text(500, default=None, description="The request path that caused the problem.")
    request_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9-]{8,64}$",
                                   description="Correlates with server logs.")
    errors: list[FieldError] | None = Field(default=None, max_length=50, description="Field-level validation errors.")


class APIError(Exception):
    """Raise this anywhere in the app to return a Problem response."""

    def __init__(self, status: int, code: str, title: str, detail: str, headers: dict[str, str] | None = None):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.headers = headers or {}


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def _clean(value: str, limit: int) -> str:
    """Error bodies must never echo control characters back (log/terminal injection)."""
    return _CONTROL_CHARS.sub("", value)[:limit]


def problem_response(
    request: Request,
    status: int,
    code: str,
    title: str,
    detail: str,
    errors: list[FieldError] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    # Use the raw (still percent-encoded) path so attacker-supplied bytes are never decoded into the response.
    raw_path = request.scope.get("raw_path") or request.url.path.encode()
    body = Problem(
        type=PROBLEM_BASE_URI + code.replace("_", "-"),
        title=_clean(title, 200),
        status=status,
        detail=_clean(detail, 1000),
        code=code,
        instance=_clean(raw_path.decode("ascii", "replace"), 500),
        request_id=getattr(request.state, "request_id", None),
        errors=errors,
    )
    return JSONResponse(
        status_code=status,
        content=body.model_dump(exclude_none=True),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


_STATUS_TITLES = {
    400: ("bad_request", "Bad request"),
    401: ("unauthorized", "Authentication required"),
    403: ("forbidden", "Forbidden"),
    404: ("not_found", "Resource not found"),
    405: ("method_not_allowed", "Method not allowed"),
    409: ("conflict", "Conflict"),
    429: ("rate_limited", "Too many requests"),
}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api_error(request: Request, exc: APIError):
        return problem_response(request, exc.status, exc.code, exc.title, exc.detail, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        errors = [
            FieldError(
                field=_clean(".".join(str(p) for p in err.get("loc", []) if p not in ("body", "query", "path")), 200) or "request",
                message=_clean(str(err.get("msg", "invalid value")), 500),
            )
            for err in exc.errors()[:50]
        ]
        return problem_response(
            request, 422, "validation_failed", "Request validation failed",
            "One or more fields are invalid. See 'errors' for details.", errors=errors,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        code, title = _STATUS_TITLES.get(exc.status_code, ("http_error", "HTTP error"))
        detail = exc.detail if isinstance(exc.detail, str) else title
        headers = dict(getattr(exc, "headers", None) or {})
        if exc.status_code == 405:
            # List every method the path supports, not just the first matching route's.
            headers["Allow"] = ", ".join(sorted(_allowed_methods(request)))
        return problem_response(request, exc.status_code, code, title, detail, headers=headers)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        # Never leak stack traces or internals to callers (OWASP API8). Log them instead.
        logger.exception("Unhandled error on %s", request.url.path)
        return problem_response(
            request, 500, "internal_error", "Internal server error",
            "Something went wrong on our side. Use request_id when contacting support.",
        )


def _allowed_methods(request: Request) -> set[str]:
    """Methods documented for this path in the OpenAPI spec (the contract is the source of truth)."""
    methods: set[str] = set()
    for template, item in request.app.openapi().get("paths", {}).items():
        pattern = "^" + re.sub(r"\{[^/]+\}", "[^/]+", template) + "$"
        if re.match(pattern, request.url.path):
            methods |= {m.upper() for m in item if m in ("get", "put", "post", "patch", "delete")}
    return methods or {"GET"}


def problem_responses(*statuses: int) -> dict:
    """OpenAPI response docs for the given error statuses (all share the Problem schema)."""
    descriptions = {
        400: "Bad request.",
        401: "Missing, expired, or invalid access token.",
        403: "The token is valid but lacks the required scope.",
        404: "The resource does not exist.",
        409: "The request conflicts with the resource's current state.",
        410: "This API version has been retired.",
        422: "The request failed validation.",
        429: "Rate limit exceeded. Retry after the time in the Retry-After header.",
        500: "Unexpected server error.",
    }
    out = {}
    for s in statuses:
        entry = {"model": Problem, "description": descriptions[s]}
        if s == 429:
            entry["headers"] = {
                "Retry-After": {"description": "Seconds until the rate limit window resets.", "schema": {"type": "integer", "minimum": 0, "maximum": 3600, "format": "int32"}},
            }
        out[s] = entry
    return out
