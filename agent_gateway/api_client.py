"""Small client for the Claims API that authenticates with OAuth client credentials.

The gateway holds the agent's credentials, so the AI model never sees a secret
or a token. Each client identity (agent or human-operated app) gets its own
token with only its own scopes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx


@dataclass
class APIResult:
    status: int
    body: dict

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def error_summary(self) -> dict:
        return {"reason": self.body.get("code", "api_error"), "http_status": self.status,
                "message": self.body.get("detail", "The API rejected the request.")}


class ClaimsAPI:
    def __init__(self, client_id: str, client_secret: str, *, base_url: str | None = None,
                 http: httpx.Client | None = None) -> None:
        if not client_secret:
            raise ValueError(f"No client secret configured for {client_id}")
        self.client_id = client_id
        self._secret = client_secret
        self.http = http or httpx.Client(base_url=base_url or "http://localhost:8000", timeout=15)
        self._token: str | None = None
        self._expires_at = 0.0

    def _bearer(self) -> str:
        if not self._token or time.time() > self._expires_at - 30:
            resp = self.http.post("/oauth/token", data={
                "grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self._secret,
            })
            resp.raise_for_status()
            data = resp.json()
            self._token, self._expires_at = data["access_token"], time.time() + data["expires_in"]
        return self._token

    def call(self, method: str, path: str, **kwargs) -> APIResult:
        headers = {"Authorization": f"Bearer {self._bearer()}", **kwargs.pop("headers", {})}
        resp = self.http.request(method, path, headers=headers, **kwargs)
        try:
            body = resp.json()
        except ValueError:
            body = {"detail": resp.text[:500]}
        return APIResult(resp.status_code, body if isinstance(body, dict) else {"items": body})
