"""OAuth 2.0 client credentials and JWT verification."""

import base64
import time

import jwt

from app.auth import _key_id, _private_key
from app.config import get_settings

from .conftest import SECRETS


def _token_request(client, **overrides):
    data = {"grant_type": "client_credentials", "client_id": "agent-claims-assistant",
            "client_secret": SECRETS["agent-claims-assistant"]}
    data.update(overrides)
    return client.post("/oauth/token", data={k: v for k, v in data.items() if v is not None})


def test_issues_token_with_only_registered_scopes(client):
    resp = _token_request(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert set(body["scope"].split()) == {"policies:read", "claims:read", "claims:write"}
    assert resp.headers["cache-control"] == "no-store"


def test_can_request_a_narrower_scope(client):
    resp = _token_request(client, scope="claims:read")
    assert resp.json()["scope"] == "claims:read"


def test_agent_cannot_get_payment_scope(client):
    resp = _token_request(client, scope="claims:read payments:write")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_wrong_secret_is_rejected(client):
    resp = _token_request(client, client_secret="nope")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_unknown_client_is_rejected(client):
    resp = _token_request(client, client_id="someone-else")
    assert resp.status_code == 401


def test_only_client_credentials_grant_is_supported(client):
    resp = _token_request(client, grant_type="password")
    assert resp.json()["error"] == "unsupported_grant_type"


def test_http_basic_client_auth(client):
    creds = base64.b64encode(f"adjuster-console:{SECRETS['adjuster-console']}".encode()).decode()
    resp = client.post("/oauth/token", data={"grant_type": "client_credentials"},
                       headers={"Authorization": f"Basic {creds}"})
    assert resp.status_code == 200
    assert "payments:write" in resp.json()["scope"]


def test_missing_token_returns_problem_401(client):
    resp = client.get("/v2/claims")
    assert resp.status_code == 401
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.headers["www-authenticate"] == "Bearer"
    assert resp.json()["code"] == "unauthorized"


def test_garbage_token_rejected(client):
    resp = client.get("/v2/claims", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


def _forge(claims_overrides: dict, key=None, algorithm="RS256"):
    s = get_settings()
    now = int(time.time())
    claims = {"iss": s.issuer, "aud": s.audience, "sub": "agent-claims-assistant", "client_type": "ai_agent",
              "scope": "claims:read", "iat": now, "nbf": now, "exp": now + 60, "jti": "x"}
    claims.update(claims_overrides)
    return jwt.encode(claims, key or _private_key(), algorithm=algorithm, headers={"kid": _key_id()})


def test_expired_token_rejected(client):
    token = _forge({"exp": int(time.time()) - 10})
    resp = client.get("/v2/claims", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"]


def test_wrong_audience_rejected(client):
    token = _forge({"aud": "some-other-api"})
    assert client.get("/v2/claims", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_signed_with_another_key_rejected(client):
    from cryptography.hazmat.primitives.asymmetric import rsa

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _forge({}, key=attacker_key)
    assert client.get("/v2/claims", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_alg_none_token_rejected(client):
    s = get_settings()
    token = jwt.encode({"iss": s.issuer, "aud": s.audience, "sub": "adjuster-console", "scope": "payments:write",
                        "exp": int(time.time()) + 60, "iat": int(time.time()), "jti": "x"}, key=None, algorithm="none")
    assert client.get("/v2/claims", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_insufficient_scope_returns_403(client, auth):
    resp = client.get("/v2/claims", headers=auth("agent-intake-bot"))
    assert resp.status_code == 403
    assert resp.json()["code"] == "insufficient_scope"
    assert 'error="insufficient_scope"' in resp.headers["www-authenticate"]


def test_jwks_publishes_public_key_only(client):
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert keys[0]["kty"] == "RSA" and keys[0]["kid"] == _key_id()
    assert "d" not in keys[0]  # private exponent must never be published
