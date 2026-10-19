"""Human approval queue for high-risk agent actions (STD-AI-03).

When an agent tries a high-risk action (approving or denying a claim, paying
out money), the gateway does NOT do it. It files an approval request here and
tells the agent the action is pending. A human reviews the request and either
approves it, which executes the action under the HUMAN's application identity
(adjuster-console), or denies it. Either way the decision is in the audit log.

    python -m agent_gateway.approvals list [--status pending]
    python -m agent_gateway.approvals show APR-0001
    python -m agent_gateway.approvals approve APR-0001 --by "J. Alvarez"
    python -m agent_gateway.approvals deny APR-0001 --by "J. Alvarez" --note "Receipts don't match"
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import app.config  # noqa: F401  (loads .env so the CLI has the adjuster console's secret)

from .api_client import APIResult, ClaimsAPI
from .audit import AuditLog

Executor = Callable[[dict, str], APIResult]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_db() -> Path:
    state = Path(os.environ.get("AGENTGATE_STATE_DIR", Path(__file__).resolve().parent.parent / "state"))
    state.mkdir(parents=True, exist_ok=True)
    return state / "approvals.db"


class ApprovalQueue:
    def __init__(self, db_path: Path | None = None, audit: AuditLog | None = None) -> None:
        self.db_path = Path(db_path or default_db())
        self.audit = audit or AuditLog()
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, tool TEXT NOT NULL, arguments TEXT NOT NULL,
                justification TEXT NOT NULL, risk_flags TEXT NOT NULL, status TEXT NOT NULL,
                requested_at TEXT NOT NULL, decided_by TEXT, decided_at TEXT, decision_note TEXT, result TEXT)""")

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create(self, agent_id: str, tool: str, arguments: dict, justification: str, risk_flags: list[str],
               session_id: str) -> dict:
        with self._db() as db:
            n = db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] + 1
            approval_id = f"APR-{n:04d}"
            db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
                       (approval_id, agent_id, tool, json.dumps(arguments), justification,
                        json.dumps(risk_flags), "pending", _now()))
        self.audit.write(event="approval_requested", agent_id=agent_id, session_id=session_id, tool=tool,
                         approval_id=approval_id, arguments=arguments, risk_flags=risk_flags)
        return self.get(approval_id)

    def get(self, approval_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        for key in ("arguments", "risk_flags", "result"):
            item[key] = json.loads(item[key]) if item[key] else None
        return item

    def list(self, status: str | None = None) -> list[dict]:
        # Two fixed queries instead of building SQL from strings (flagged by Bandit B608).
        with self._db() as db:
            if status:
                rows = db.execute("SELECT id FROM approvals WHERE status = ? ORDER BY id", (status,)).fetchall()
            else:
                rows = db.execute("SELECT id FROM approvals ORDER BY id").fetchall()
        return [self.get(r["id"]) for r in rows]

    def decide(self, approval_id: str, approve: bool, approver: str, note: str = "",
               executor: Executor | None = None) -> dict:
        item = self.get(approval_id)
        if not item:
            raise KeyError(f"No approval request {approval_id}")
        if item["status"] != "pending":
            raise ValueError(f"{approval_id} was already {item['status']}")
        if not approver.strip():
            raise ValueError("The approver's name is required")

        status, result = "denied", None
        if approve:
            outcome = (executor or default_executor())(item, approver)
            status = "executed" if outcome.ok else "failed"
            result = outcome.body if outcome.ok else outcome.error_summary()
        with self._db() as db:
            db.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=?, decision_note=?, result=? WHERE id=?",
                       (status, approver, _now(), note, json.dumps(result) if result else None, approval_id))
        self.audit.write(event="approval_decided", agent_id=item["agent_id"], tool=item["tool"],
                         approval_id=approval_id, decision=status, decided_by=approver, reason=note or None)
        return self.get(approval_id)


def execute_approved(api: ClaimsAPI, item: dict, approver: str) -> APIResult:
    """Run an approved action with the human-operated application's credentials."""
    args = item["arguments"]
    if item["tool"] == "update_claim_status":
        body = {"status": args["status"],
                "reason": f"{args['reason']} [proposed by {item['agent_id']} in {item['id']}, approved by {approver}]"[:500]}
        if args.get("approved_amount_cents") is not None:
            body["approved_amount_cents"] = args["approved_amount_cents"]
        return api.call("PATCH", f"/v2/claims/{args['claim_id']}/status", json=body)
    if item["tool"] == "propose_payment":
        return api.call("POST", f"/v2/claims/{args['claim_id']}/payments", json={
            "amount_cents": args["amount_cents"], "payee_name": args["payee_name"], "approved_by": approver,
        })
    return APIResult(400, {"code": "unsupported_action", "detail": f"Don't know how to execute {item['tool']}"})


def default_executor() -> Executor:
    api = ClaimsAPI("adjuster-console", os.environ.get("ADJUSTER_CONSOLE_SECRET", ""),
                    base_url=os.environ.get("AGENTGATE_API_URL", "http://localhost:8000"))
    return lambda item, approver: execute_approved(api, item, approver)


def main() -> int:
    parser = argparse.ArgumentParser(description="Review AI agent actions that need human approval")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--status", choices=["pending", "executed", "denied", "failed"])
    show = sub.add_parser("show")
    show.add_argument("approval_id")
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("approval_id")
        p.add_argument("--by", required=True, help="your name (recorded as the approver of record)")
        p.add_argument("--note", default="")
    args = parser.parse_args()

    queue = ApprovalQueue()
    if args.cmd == "list":
        for item in queue.list(args.status):
            flags = f"  FLAGS: {', '.join(item['risk_flags'])}" if item["risk_flags"] else ""
            print(f"{item['id']}  {item['status']:<9} {item['agent_id']:<24} {item['tool']:<20} "
                  f"{json.dumps(item['arguments'])}{flags}")
        return 0
    if args.cmd == "show":
        print(json.dumps(queue.get(args.approval_id), indent=2))
        return 0
    item = queue.decide(args.approval_id, approve=args.cmd == "approve", approver=args.by, note=args.note)
    print(f"{item['id']} -> {item['status']}")
    if item["result"]:
        print(json.dumps(item["result"], indent=2))
    return 0 if item["status"] in ("executed", "denied") else 1


if __name__ == "__main__":
    sys.exit(main())
