"""Error format, lifecycle headers, retirement, rate limiting, and response headers."""

from fastapi.testclient import TestClient

from app import lifecycle
from app.config import get_settings
from app.main import create_app


def test_errors_never_leak_internals():
    app = create_app()

    @app.get("/v2/boom", include_in_schema=False)
    async def boom():
        raise RuntimeError("database password is hunter2")

    resp = TestClient(app, raise_server_exceptions=False).get("/v2/boom")
    assert resp.status_code == 500
    assert resp.headers["content-type"] == "application/problem+json"
    assert "hunter2" not in resp.text and "Traceback" not in resp.text
    assert resp.json()["code"] == "internal_error"


def test_unknown_route_is_problem_json(client):
    resp = client.get("/v2/nothing-here")
    assert resp.status_code == 404 and resp.headers["content-type"] == "application/problem+json"


def test_v1_sends_deprecation_headers(client, auth, monkeypatch):
    monkeypatch.setattr(lifecycle, "is_retired", lambda version, today=None: False)  # freeze "before sunset"
    resp = client.get("/v1/claims/CLM-2001", headers=auth("claims-portal"))
    assert resp.status_code == 200
    assert resp.json()["amount"] == "4200.00"
    assert resp.headers["deprecation"].startswith("@")
    assert resp.headers["sunset"] == "Wed, 31 Mar 2027 00:00:00 GMT"
    assert resp.headers["link"] == '</v2/claims/CLM-2001>; rel="successor-version"'


def test_v2_has_no_deprecation_headers(client, auth):
    resp = client.get("/v2/claims/CLM-2001", headers=auth("claims-portal"))
    assert "deprecation" not in resp.headers


def test_v1_returns_410_after_sunset(client, auth, monkeypatch):
    monkeypatch.setattr(lifecycle, "is_retired", lambda version, today=None: True)
    resp = client.get("/v1/claims/CLM-2001", headers=auth("claims-portal"))
    assert resp.status_code == 410 and resp.json()["code"] == "version_retired"


def test_retirement_date_logic():
    from datetime import date
    assert not lifecycle.is_retired("v1", today=date(2027, 3, 31))
    assert lifecycle.is_retired("v1", today=date(2027, 4, 1))
    assert not lifecycle.is_retired("v2", today=date(2030, 1, 1))


def test_rate_limit(client, auth, monkeypatch):
    h = auth("claims-portal")
    monkeypatch.setattr(get_settings(), "rate_limit_per_minute", 3)
    for _ in range(3):
        ok = client.get("/v2/claims", headers=h)
        assert ok.status_code == 200
    assert ok.headers["ratelimit-remaining"] == "0"
    blocked = client.get("/v2/claims", headers=h)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert blocked.json()["code"] == "rate_limited"


def test_security_and_tracing_headers(client, auth):
    resp = client.get("/v2/claims", headers={**auth("claims-portal"), "X-Request-ID": "trace-12345678"})
    assert resp.headers["x-request-id"] == "trace-12345678"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"
    assert int(resp.headers["ratelimit-limit"]) > 0


def test_cors_only_for_allowed_origins(client, auth):
    h = auth("claims-portal")
    allowed = client.get("/v2/claims", headers={**h, "Origin": "https://claims.agentgate.example"})
    assert allowed.headers["access-control-allow-origin"] == "https://claims.agentgate.example"
    evil = client.get("/v2/claims", headers={**h, "Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers


def test_health_is_public(client):
    assert client.get("/health").json()["status"] == "ok"
