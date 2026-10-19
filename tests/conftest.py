import os
import tempfile
from pathlib import Path

# Test configuration must be in place BEFORE the app is imported.
_STATE = Path(tempfile.mkdtemp(prefix="agentgate-test-"))
os.environ.update({
    "AGENTGATE_STATE_DIR": str(_STATE),
    "CLAIMS_PORTAL_SECRET": "test-portal-secret",
    "ADJUSTER_CONSOLE_SECRET": "test-adjuster-secret",
    "AGENT_CLAIMS_ASSISTANT_SECRET": "test-assistant-secret",
    "AGENT_INTAKE_BOT_SECRET": "test-intake-secret",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.data import store  # noqa: E402
from app.main import app  # noqa: E402
from app.ratelimit import limiter  # noqa: E402

SECRETS = {
    "claims-portal": "test-portal-secret",
    "adjuster-console": "test-adjuster-secret",
    "agent-claims-assistant": "test-assistant-secret",
    "agent-intake-bot": "test-intake-secret",
}


@pytest.fixture(autouse=True)
def _fresh_state():
    store.reset()
    limiter.reset()
    yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def get_token(client: TestClient, client_id: str, scope: str | None = None) -> str:
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": SECRETS[client_id]}
    if scope:
        data["scope"] = scope
    resp = client.post("/oauth/token", data=data)
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def auth(client):
    """auth("agent-claims-assistant") -> headers dict with a fresh bearer token."""
    def _auth(client_id: str, scope: str | None = None) -> dict:
        return {"Authorization": f"Bearer {get_token(client, client_id, scope)}"}
    return _auth


@pytest.fixture
def state_dir() -> Path:
    return _STATE
