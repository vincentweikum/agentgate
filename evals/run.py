"""Run the agent guardrail scenarios in evals/scenarios.yaml.

    python -m evals.run            # all scenarios
    python -m evals.run --only S02

Writes reports/eval-report.json and copies the run's audit log to
reports/eval-audit.jsonl so CI can verify its hash chain.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("AGENTGATE_STATE_DIR", tempfile.mkdtemp(prefix="agentgate-evals-"))
sys.path.insert(0, str(ROOT))

from agent_gateway.audit import head_path, verify  # noqa: E402
from agent_gateway.harness import Harness  # noqa: E402

SCENARIOS = ROOT / "evals" / "scenarios.yaml"


def check_call(gateway, step: dict) -> tuple[str, bool, str]:
    out = gateway.call(step["tool"], step.get("args", {}))
    label = f"{step['tool']} -> {step['expect']}"
    ok = out["status"] == step["expect"]
    if ok and step.get("expect_reason"):
        ok, label = out.get("reason") == step["expect_reason"], label + f" ({step['expect_reason']})"
    if ok and step.get("expect_flags"):
        ok, label = bool(out.get("security_flags")), label + " with injection flag"
    if ok and step.get("expect_masked"):
        ok, label = "***" in json.dumps(out.get("policy", {})), label + " with personal data masked"
    detail = out["status"] + (f" ({out['reason']})" if out.get("reason") else "")
    return label, ok, detail


def check_outcome(h: Harness, expect: dict, new_approvals: list[dict]) -> list[tuple[str, bool, str]]:
    claims, checks = h.store.claims, []
    if expect.get("no_money_moved"):
        paid = sum(len(c["payments"]) for c in claims.values())
        checks.append(("no money moved", paid == 0, f"{paid} payment(s)"))
    for cid, status in (expect.get("claim_status") or {}).items():
        checks.append((f"{cid} stays {status}", claims[cid]["status"] == status, claims[cid]["status"]))
    if expect.get("approval_requested"):
        found = [a["id"] for a in new_approvals if a["tool"] == expect["approval_requested"] and a["status"] == "pending"]
        checks.append((f"human approval requested for {expect['approval_requested']}", bool(found), ", ".join(found) or "none"))
    for rule in expect.get("forbidden_approvals") or []:
        bad = [a["id"] for a in new_approvals if a["tool"] == rule["tool"]]
        checks.append((f"no approval request for {rule['tool']}", not bad, ", ".join(bad) or "none"))
    if expect.get("new_claim_by"):
        new = [c["claim_id"] for c in claims.values() if c["created_by"] == expect["new_claim_by"]]
        checks.append((f"new claim filed by {expect['new_claim_by']}", bool(new), ", ".join(new) or "none"))
    if expect.get("no_new_claim_on"):
        new = [c for c in claims.values() if c["policy_id"] == expect["no_new_claim_on"] and c["claim_id"] >= "CLM-3000"]
        checks.append((f"no new claim on {expect['no_new_claim_on']}", not new, f"{len(new)} created"))
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", nargs="*", help="scenario IDs to run")
    parser.add_argument("--out", type=Path, default=ROOT / "reports")
    args = parser.parse_args(argv)

    scenarios = [s for s in yaml.safe_load(SCENARIOS.read_text())["scenarios"] if not args.only or s["id"] in args.only]
    h = Harness(Path(os.environ["AGENTGATE_STATE_DIR"]) / "evals")
    results = []
    for s in scenarios:
        h.reset_data()
        before = {a["id"] for a in h.approvals.list()}
        gateway = h.gateway(s["agent"])
        checks = [check_call(gateway, step) for step in s.get("calls", [])]
        new_approvals = [a for a in h.approvals.list() if a["id"] not in before]
        checks += check_outcome(h, s.get("expect") or {}, new_approvals)
        passed = all(ok for _, ok, _ in checks)
        results.append({"id": s["id"], "title": s["title"], "agent": s["agent"], "passed": passed,
                        "checks": [{"name": n, "passed": ok, "detail": d} for n, ok, d in checks]})
        print(f"{'PASS' if passed else 'FAIL'}  {s['id']}  {s['title']}")
        for name, ok, detail in checks:
            if not ok:
                print(f"        x {name}: got {detail}")

    chain_ok, chain_msg = verify(h.audit.path)
    args.out.mkdir(parents=True, exist_ok=True)
    if h.audit.path.exists():
        shutil.copy(h.audit.path, args.out / "eval-audit.jsonl")
        shutil.copy(head_path(h.audit.path), args.out / "eval-audit.jsonl.head")
    report = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "passed": all(r["passed"] for r in results) and chain_ok,
              "passed_count": sum(r["passed"] for r in results), "total": len(results),
              "audit_chain": chain_msg, "scenarios": results}
    (args.out / "eval-report.json").write_text(json.dumps(report, indent=2))

    summary = f"Agent scenarios: {report['passed_count']}/{report['total']} passed. Audit log: {chain_msg}"
    print("\n" + summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(f"## {summary}\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
