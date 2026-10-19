"""Request telemetry: request IDs, security headers, rate-limit headers, and one
structured access-log line per API request (who called what, the status, and
how long it took), so usage and errors can be monitored in any log system.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid

from fastapi import FastAPI, Request

_REQUEST_ID_OK = re.compile(r"^[A-Za-z0-9-]{8,64}$")
access_log = logging.getLogger("agentgate.access")


def install_telemetry(app: FastAPI) -> None:
    @app.middleware("http")
    async def telemetry(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_OK.match(incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            route = getattr(request.scope.get("route"), "path", request.url.path)
            access_log.info(json.dumps({
                "method": request.method,
                "route": route,
                "status": status,
                "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                "client_id": getattr(request.state, "client_id", None),
                "deprecated_version": route.startswith("/v1/"),
                "request_id": request_id,
            }))

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers.setdefault("Cache-Control", "no-store")
        rate = getattr(request.state, "rate_limit", None)
        if rate:
            limit, remaining, reset = rate
            response.headers["RateLimit-Limit"] = str(limit)
            response.headers["RateLimit-Remaining"] = str(remaining)
            response.headers["RateLimit-Reset"] = str(reset)
        return response
