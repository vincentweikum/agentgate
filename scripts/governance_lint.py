"""Run the API governance linter and apply approved exceptions.

    python scripts/governance_lint.py
    python scripts/governance_lint.py --spec path/to/openapi.yaml --exceptions path/to/exceptions.yaml

Steps:
  1. Run Spectral with our ruleset (STANDARDS.md as code + OWASP API Top 10).
  2. Load governance/exceptions.yaml and validate every exception.
  3. Waive findings covered by an approved, unexpired exception.
  4. Print a summary, write reports/lint-report.json,
     and add a summary to the GitHub Actions job page when running in CI.
  5. Exit 1 if any blocking finding is left, or the exceptions file is invalid.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEVERITY = {0: "error", 1: "warn", 2: "info", 3: "hint"}
MAX_EXCEPTION_DAYS = 366
REQUIRED_FIELDS = ["id", "rules", "target", "reason", "compensating_controls", "requested_by",
                   "approved_by", "approved_on", "expires_on"]


def run_spectral(spec: Path, ruleset: Path) -> list[dict]:
    """Run Spectral and return its findings. Fails closed: if Spectral can't run, the check fails."""
    for label, path in (("spec", spec), ("ruleset", ruleset)):
        if not path.is_file():
            sys.exit(f"FAILED: {label} file not found: {path}")
    npx = shutil.which("npx")
    if not npx:
        sys.exit("FAILED: npx not found. Install Node.js and run `npm ci`.")
    proc = subprocess.run(
        [npx, "--no-install", "spectral", "lint", str(spec), "--ruleset", str(ruleset), "-f", "json", "--quiet"],
        capture_output=True, text=True, cwd=ROOT,
    )
    # Spectral exits 0 (clean) or 1 (findings) on a real run, and 2 when it couldn't lint at all.
    out = proc.stdout.strip()
    if proc.returncode >= 2 or (out and not out.startswith("[")):
        sys.exit(f"FAILED: Spectral could not lint the spec (exit {proc.returncode}).\n{proc.stdout}\n{proc.stderr}")
    return json.loads(out) if out else []


def _as_date(value) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def load_exceptions(path: Path, today: date) -> tuple[list[dict], list[str]]:
    """Return (exceptions, problems). Each exception gets a computed 'state'."""
    if not path.exists():
        return [], []
    raw = yaml.safe_load(path.read_text()) or {}
    problems, seen = [], set()
    items = raw.get("exceptions") or []
    for exc in items:
        eid = exc.get("id", "<missing id>")
        missing = [f for f in REQUIRED_FIELDS if not exc.get(f)]
        if missing:
            problems.append(f"{eid}: missing required field(s): {', '.join(missing)}")
            exc["state"] = "invalid"
            continue
        if eid in seen:
            problems.append(f"{eid}: duplicate exception ID")
        seen.add(eid)
        approved, expires = _as_date(exc["approved_on"]), _as_date(exc["expires_on"])
        if (expires - approved).days > MAX_EXCEPTION_DAYS:
            problems.append(f"{eid}: exceptions can last at most 12 months (approved {approved}, expires {expires})")
        if len(str(exc["reason"]).strip()) < 20:
            problems.append(f"{eid}: reason is too short to justify an exception")
        days_left = (expires - today).days
        exc["days_left"] = days_left
        exc["state"] = "expired" if days_left < 0 else ("expiring_soon" if days_left <= 30 else "active")
    return items, problems


def finding_target(finding: dict) -> str:
    return ".".join(str(p) for p in finding.get("path", []))


def apply_exceptions(findings: list[dict], exceptions: list[dict]) -> None:
    for f in findings:
        f["severity_name"] = SEVERITY.get(f.get("severity", 0), "error")
        f["target"] = finding_target(f)
        f["waived_by"] = None
        for exc in exceptions:
            if exc.get("state") not in ("active", "expiring_soon"):
                continue
            if f["code"] in exc["rules"] and (f["target"] == exc["target"] or f["target"].startswith(exc["target"] + ".")):
                f["waived_by"] = exc["id"]
                exc.setdefault("matched", 0)
                exc["matched"] += 1
                break


def build_report(spec_display: str, findings: list[dict], exceptions: list[dict], problems: list[str]) -> dict:
    blocking = [f for f in findings if f["severity_name"] == "error" and not f["waived_by"]]
    warnings = [f for f in findings if f["severity_name"] == "warn" and not f["waived_by"]]
    waived = [f for f in findings if f["waived_by"]]
    for exc in exceptions:
        if exc.get("state") in ("active", "expiring_soon") and not exc.get("matched"):
            exc["state"] = "unused"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "spec": spec_display,
        "passed": not blocking and not problems,
        "totals": {"blocking": len(blocking), "warnings": len(warnings), "waived": len(waived),
                   "exceptions": len(exceptions), "exception_problems": len(problems)},
        "by_rule": dict(Counter(f["code"] for f in findings if not f["waived_by"])),
        "findings": [
            {"rule": f["code"], "severity": f["severity_name"], "message": f["message"], "target": f["target"],
             "line": f.get("range", {}).get("start", {}).get("line", 0) + 1, "waived_by": f["waived_by"]}
            for f in findings
        ],
        "exceptions": [
            {"id": e.get("id"), "rules": e.get("rules"), "target": e.get("target"), "state": e.get("state"),
             "expires_on": str(e.get("expires_on")), "days_left": e.get("days_left"),
             "approved_by": e.get("approved_by"), "matched": e.get("matched", 0)}
            for e in exceptions
        ],
        "exception_problems": problems,
    }


def markdown_summary(report: dict) -> str:
    t = report["totals"]
    lines = [
        f"## API governance: {'PASSED' if report['passed'] else 'FAILED'}",
        "",
        f"| Blocking | Warnings | Waived by exception |",
        f"|---|---|---|",
        f"| {t['blocking']} | {t['warnings']} | {t['waived']} |",
        "",
    ]
    blocking = [f for f in report["findings"] if f["severity"] == "error" and not f["waived_by"]]
    if blocking:
        lines += ["### Blocking findings", "", "| Rule | Where | Message |", "|---|---|---|"]
        lines += [f"| `{f['rule']}` | line {f['line']} | {f['message']} |" for f in blocking[:50]]
        lines.append("")
    if report["exceptions"]:
        lines += ["### Exceptions", "", "| ID | State | Expires | Waived findings |", "|---|---|---|---|"]
        lines += [f"| {e['id']} | {e['state']} | {e['expires_on']} | {e['matched']} |" for e in report["exceptions"]]
        lines.append("")
    if report["exception_problems"]:
        lines += ["### Exception file problems", ""] + [f"- {p}" for p in report["exception_problems"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", type=Path, default=Path("openapi/agentgate-claims.yaml"))
    parser.add_argument("--ruleset", type=Path, default=ROOT / "governance" / ".spectral.yaml")
    parser.add_argument("--exceptions", type=Path, default=Path("governance/exceptions.yaml"))
    parser.add_argument("--report", type=Path, default=Path("reports/lint-report.json"))
    parser.add_argument("--today", type=date.fromisoformat, default=date.today(), help="override today's date (testing)")
    args = parser.parse_args()

    findings = run_spectral(args.spec.resolve(), args.ruleset.resolve())
    exceptions, problems = load_exceptions(args.exceptions, args.today)
    apply_exceptions(findings, exceptions)
    # Paths in the report and in PR annotations stay relative to the repo being checked.
    report = build_report(str(args.spec), findings, exceptions, problems)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))
    summary = markdown_summary(report)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(summary)
    for f in report["findings"]:
        if f["severity"] == "error" and not f["waived_by"] and os.environ.get("GITHUB_ACTIONS"):
            # Shows the finding inline on the pull request's changed file.
            print(f"::error file={report['spec']},line={f['line']},title={f['rule']}::{f['message']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
