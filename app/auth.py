"""OAuth 2.0 client credentials + JWT access tokens.

How it works:
  1. A client (an app or an AI agent) sends its client_id + client_secret to
     POST /oauth/token and asks for scopes.
  2. We check the secret, grant only scopes the client is registered for, and
     return a short-lived JWT (15 minutes) signed with our RSA private key.
  3. Every API call sends `Authorization: Bearer <token>`. We verify the
     signature with the public key, check issuer/audience/expiry, then check
     the endpoint's required scope. Missing scope -> 403.

The public key is published at /.well-known/jwks.json so other services can
verify our tokens without ever seeing the private key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, Form, Request
from fastapi.openapi.models import OAuthFlowClientCredentials, OAuthFlows
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2, SecurityScopes

from .config import get_settings
from .errors import APIError
from .ratelimit import limiter

SCOPES = {
    "policies:read": "Read policy details",
    "claims:read": "Read claims",
    "claims:write": "Create claims, add notes, and change claim status",
    "payments:write": "Issue claim payments",
    "pii:read": "See unmasked policyholder contact details",
}

oauth2_scheme = OAuth2(
    flows=OAuthFlows(clientCredentials=OAuthFlowClientCredentials(tokenUrl="/oauth/token", scopes=SCOPES)),
    scheme_name="OAuth2",
    description=(
        "OAuth 2.0 client credentials. Access tokens are RS256-signed JWTs that expire after 15 minutes and "
        "follow RFC8725 (JWT Best Current Practices): the algorithm is pinned, and issuer, audience, and expiry "
        "are always verified. Public keys are published at /.well-known/jwks.json."
    ),
    auto_error=False,
)


@dataclass(frozen=True)
class Client:
    client_id: str
    client_type: str
    owner: str
    scopes: frozenset[str]
    secret_env: str

    def secret(self) -> str | None:
        return os.environ.get(self.secret_env)


@dataclass(frozen=True)
class Principal:
    """Who is calling, as proven by their token."""

    client_id: str
    client_type: str
    scopes: frozenset[str]
    token_id: str

    @property
    def is_agent(self) -> bool:
        return self.client_type == "ai_agent"


@lru_cache
def load_clients() -> dict[str, Client]:
    raw = yaml.safe_load(get_settings().clients_file.read_text())["clients"]
    return {
        cid: Client(cid, c["type"], c["owner"], frozenset(c["scopes"]), c["secret_env"])
        for cid, c in raw.items()
    }


# ---------- signing keys ----------

@lru_cache
def _private_key():
    pem = get_settings().private_key_pem
    if pem:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    # Dev/test only: generate a throwaway key at startup. Production sets AGENTGATE_PRIVATE_KEY_PEM.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@lru_cache
def _key_id() -> str:
    der = _private_key().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()[:12]).decode().rstrip("=")


def jwks() -> dict:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(_private_key().public_key(), as_dict=True)
    jwk.update({"kid": _key_id(), "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def issue_token(client: Client, scopes: frozenset[str]) -> dict:
    s = get_settings()
    now = int(time.time())
    claims = {
        "iss": s.issuer,
        "aud": s.audience,
        "sub": client.client_id,
        "client_type": client.client_type,
        "scope": " ".join(sorted(scopes)),
        "iat": now,
        "nbf": now,
        "exp": now + s.token_ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(claims, _private_key(), algorithm="RS256", headers={"kid": _key_id()})
    return {"access_token": token, "token_type": "Bearer", "expires_in": s.token_ttl_seconds, "scope": claims["scope"]}


def verify_token(token: str) -> Principal:
    s = get_settings()
    try:
        claims = jwt.decode(
            token,
            _private_key().public_key(),
            algorithms=["RS256"],  # pinned: never accept "none" or HS256 with a public key
            audience=s.audience,
            issuer=s.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("The access token has expired. Request a new one.")
    except jwt.InvalidTokenError:
        raise _unauthorized("The access token is invalid.")
    if claims["sub"] not in load_clients():
        raise _unauthorized("The token's client is no longer registered.")
    return Principal(
        client_id=claims["sub"],
        client_type=claims.get("client_type", "application"),
        scopes=frozenset(claims.get("scope", "").split()),
        token_id=claims["jti"],
    )


def _unauthorized(detail: str) -> APIError:
    return APIError(401, "unauthorized", "Authentication required", detail,
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})


# ---------- FastAPI dependency ----------

async def authorize(
    security_scopes: SecurityScopes,
    request: Request,
    authorization: str | None = Depends(oauth2_scheme),
) -> Principal:
    """Use as `Security(authorize, scopes=["claims:read"])` on any endpoint."""
    try:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise APIError(401, "unauthorized", "Authentication required",
                           "Send an OAuth 2.0 access token as 'Authorization: Bearer <token>'.",
                           headers={"WWW-Authenticate": "Bearer"})
        principal = verify_token(authorization.split(" ", 1)[1].strip())
    except APIError:
        # Unauthenticated callers are rate limited by IP, so token guessing is throttled too.
        rate_limit_anonymous(request)
        raise
    request.state.client_id = principal.client_id
    request.state.client_type = principal.client_type

    limiter.check(request, principal.client_id)

    missing = set(security_scopes.scopes) - principal.scopes
    if missing:
        needed = " ".join(sorted(security_scopes.scopes))
        raise APIError(403, "insufficient_scope", "Forbidden",
                       f"This operation requires the scope(s): {', '.join(sorted(missing))}.",
                       headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{needed}"'})
    return principal


def rate_limit_anonymous(request: Request) -> None:
    """Rate limit callers that have no valid token, keyed by IP address."""
    limiter.check(request, f"anon:{request.client.host if request.client else 'unknown'}")


# ---------- token + JWKS endpoints ----------

router = APIRouter()


def _oauth_error(status: int, error: str, description: str) -> JSONResponse:
    # OAuth endpoints use the RFC 6749 error format, not Problem Details.
    return JSONResponse(status_code=status, content={"error": error, "error_description": description},
                        headers={"Cache-Control": "no-store"})


@router.post("/oauth/token", include_in_schema=False)
async def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    scope: str | None = Form(None),
):
    # Client credentials may come in the form body or as HTTP Basic auth (RFC 6749 section 2.3.1).
    basic = request.headers.get("authorization", "")
    if basic.lower().startswith("basic "):
        try:
            client_id, client_secret = base64.b64decode(basic[6:]).decode().split(":", 1)
        except Exception:
            return _oauth_error(401, "invalid_client", "Malformed Basic credentials.")

    if grant_type != "client_credentials":
        return _oauth_error(400, "unsupported_grant_type", "Only client_credentials is supported.")

    caller = client_id or (request.client.host if request.client else "unknown")
    limiter.check(request, f"token:{caller}")

    client = load_clients().get(client_id or "")
    expected = client.secret() if client else None
    # Constant-time compare so attackers can't learn the secret from response timing.
    if not client or not expected or not client_secret or not hmac.compare_digest(client_secret, expected):
        return _oauth_error(401, "invalid_client", "Unknown client or wrong secret.")

    requested = frozenset(scope.split()) if scope else client.scopes
    if not requested <= client.scopes:
        extra = ", ".join(sorted(requested - client.scopes))
        return _oauth_error(400, "invalid_scope", f"Client is not allowed these scopes: {extra}.")

    return JSONResponse(issue_token(client, requested), headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks_endpoint():
    return jwks()
