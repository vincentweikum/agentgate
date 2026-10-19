"""Runs the API and gateway together in one process, for tests, evals, and demos.

No server, ports, or real secrets needed: the API runs in-process via FastAPI's
test client, every client gets a random secret for this run, and audit logs /
approval queues go to a folder you choose.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import yaml

from .api_client import ClaimsAPI
from .approvals import ApprovalQueue, execute_approved
from .audit import AuditLog
from .core import Gateway

ROOT = Path(__file__).resolve().parent.parent


class Harness:
    def __init__(self, state_dir: Path) -> None:
        from fastapi.testclient import TestClient

        from app.data import store
        from app.main import app
        from app.ratelimit import limiter

        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.store, self.limiter = store, limiter
        clients = yaml.safe_load((ROOT / "config" / "clients.yaml").read_text())["clients"]
        self.secrets = {}
        for client_id, spec in clients.items():
            # Reuse a secret if one is already configured (e.g. tests), otherwise make one up for this run.
            self.secrets[client_id] = os.environ.setdefault(spec["secret_env"], secrets.token_urlsafe(24))
        self.http = TestClient(app)
        self.audit = AuditLog(self.state_dir / "agent-audit.jsonl")
        self.approvals = ApprovalQueue(self.state_dir / "approvals.db", audit=self.audit)

    def reset_data(self) -> None:
        self.store.reset()
        self.limiter.reset()

    def api(self, client_id: str) -> ClaimsAPI:
        return ClaimsAPI(client_id, self.secrets[client_id], http=self.http)

    def gateway(self, agent_id: str, **kwargs) -> Gateway:
        return Gateway(agent_id, self.api(agent_id), audit=self.audit, approvals=self.approvals, **kwargs)

    def human_executor(self):
        """Approved actions run with the human adjuster console's credentials."""
        api = self.api("adjuster-console")
        return lambda item, approver: execute_approved(api, item, approver)
