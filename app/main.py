"""AgentGate Claims API: application factory.

Run locally:  uvicorn app.main:app --reload
Docs:         http://localhost:8000/docs
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from . import __version__
from .auth import rate_limit_anonymous
from .auth import router as auth_router
from .config import get_settings, load_catalog_entry
from .errors import PROBLEM_MEDIA_TYPE, install_error_handlers, problem_responses
from .lifecycle import version_info
from .models import Health
from .routers import v1, v2
from .telemetry import install_telemetry

DESCRIPTION = """
Policies, claims, notes, and payments for personal lines auto and home insurance.

**Authentication:** OAuth 2.0 client credentials. Get a token from `/oauth/token`
and send it as `Authorization: Bearer <token>`. Each endpoint lists the scope it needs.

**Errors:** every error uses RFC 9457 Problem Details (`application/problem+json`).

**Versioning:** the major version is in the path (`/v2`). Breaking changes require a
new major version. `v1` is deprecated and sunsets on {v1_sunset}.

**Rate limits:** 120 requests per minute per client. See the `RateLimit-*` response headers.
"""

TAGS = [
    {"name": "Policies", "description": "Insurance policies."},
    {"name": "Claims", "description": "Claims, notes, and claim status."},
    {"name": "Payments", "description": "Claim payments. Human-operated clients only."},
    {"name": "Claims (v1, deprecated)", "description": "Deprecated v1 endpoints. Sunsets {v1_sunset}."},
    {"name": "Health", "description": "Service health."},
]


def _int_header(description: str) -> dict:
    return {"description": description, "schema": {"type": "integer", "format": "int32", "minimum": 0, "maximum": 100000}}


COMMON_HEADERS = {
    "X-Request-ID": {"description": "Unique ID for this request. Include it when reporting problems.",
                     "schema": {"type": "string", "maxLength": 64, "pattern": "^[A-Za-z0-9-]{8,64}$"}},
    "Access-Control-Allow-Origin": {"description": "Present when the request came from an allowed browser origin.",
                                    "schema": {"type": "string", "maxLength": 200, "format": "uri"}},
    "RateLimit-Limit": _int_header("Requests allowed per one-minute window."),
    "RateLimit-Remaining": _int_header("Requests left in the current window."),
    "RateLimit-Reset": _int_header("Seconds until the window resets."),
}


def create_app() -> FastAPI:
    settings = get_settings()
    v1_sunset = str(version_info("v1")["sunset_on"])
    tags = [{**t, "description": t["description"].format(v1_sunset=v1_sunset)} for t in TAGS]
    app = FastAPI(
        title="AgentGate Claims API",
        version=__version__,
        description=DESCRIPTION.strip().format(v1_sunset=v1_sunset),
        contact={"name": "Claims Platform team", "email": "claims-platform@agentgate.example"},
        license_info={"name": "MIT", "identifier": "MIT"},
        servers=[
            {"url": "https://api.agentgate.example", "description": "Production environment (example)", "x-internal": False},
            {"url": "https://sandbox.api.agentgate.example", "description": "Sandbox environment for integration testing (example)", "x-internal": True},
        ],
        openapi_tags=tags,
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
                        "Deprecation", "Sunset", "Link", "Location"],
    )
    install_telemetry(app)
    install_error_handlers(app)

    app.include_router(auth_router)
    app.include_router(v2.router)
    app.include_router(v1.router)

    @app.get("/health", response_model=Health, tags=["Health"], operation_id="getHealth",
             summary="Health check", description="Liveness check. Intentionally public (see governance exception EXC-001).",
             openapi_extra={"security": []}, responses=problem_responses(429, 500),
             dependencies=[Depends(rate_limit_anonymous)])
    async def health() -> Health:
        return Health(status="ok", version=__version__)

    app.openapi = lambda: _custom_openapi(app)
    return app


def _custom_openapi(app: FastAPI) -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title, version=app.version, description=app.description, routes=app.routes,
        tags=app.openapi_tags, servers=app.servers, contact=app.contact, license_info=app.license_info,
    )

    # Document the headers the telemetry middleware adds to responses.
    schema.setdefault("components", {})["headers"] = COMMON_HEADERS
    for path_item in schema.get("paths", {}).values():
        for op in path_item.values():
            for status, resp in op.get("responses", {}).items():
                # Errors are served as application/problem+json; make the spec say so.
                if status[0] in "45" and "content" in resp:
                    media = next(iter(resp["content"].values()))
                    resp["content"] = {PROBLEM_MEDIA_TYPE: media}
                headers = resp.setdefault("headers", {})
                names = ["X-Request-ID", "Access-Control-Allow-Origin"]
                if status[0] in "24":
                    names += ["RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"]
                for name in names:
                    headers.setdefault(name, {"$ref": f"#/components/headers/{name}"})

    # FastAPI's default validation-error schemas are unused (we use Problem); drop them.
    comps = schema.get("components", {}).get("schemas", {})
    for unused in ("HTTPValidationError", "ValidationError"):
        comps.pop(unused, None)

    # Catalog metadata travels with the spec so tools can index it.
    entry = load_catalog_entry()
    schema["info"]["x-api-id"] = entry["api_id"]
    schema["info"]["x-owner"] = entry["owner"]["team"]
    schema["info"]["x-lifecycle-status"] = entry["lifecycle_status"]
    schema["info"]["x-data-classification"] = entry["data_classification"]

    _tidy_numbers(schema)
    app.openapi_schema = schema
    return schema


def _tidy_numbers(node) -> None:
    """Write integer bounds as integers (100000000, not 100000000.0)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("minimum", "maximum") and isinstance(value, float) and value.is_integer():
                node[key] = int(value)
            else:
                _tidy_numbers(value)
    elif isinstance(node, list):
        for item in node:
            _tidy_numbers(item)


app = create_app()
