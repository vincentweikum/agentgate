"""Block breaking API changes (STD-VER-01).

    python scripts/check_breaking.py --base base.yaml --revision openapi/agentgate-claims.yaml

Compares the spec on the target branch with the spec in the pull request using
oasdiff. Removing a field, making a parameter required, changing a type, and
deleting an endpoint are all breaking changes that would crash existing
callers, so they fail the build. To make a breaking change on purpose, ship it
as a new major version (/v3) and deprecate the old one; leaving the old
version's paths unchanged is what keeps this check green.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LEVELS = {1: "info", 2: "warning", 3: "error"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--revision", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=Path("reports/breaking-changes.json"))
    args = parser.parse_args()

    oasdiff = shutil.which("oasdiff")
    if not oasdiff:
        sys.exit("oasdiff not found on PATH. See https://github.com/oasdiff/oasdiff")
    if not args.base.exists():
        print(f"No base spec at {args.base} (new API?). Nothing to compare.")
        changes = []
    else:
        out = subprocess.run([oasdiff, "breaking", str(args.base), str(args.revision), "-f", "json"],
                             capture_output=True, text=True, check=True).stdout
        changes = json.loads(out or "[]")

    errors = [c for c in changes if c.get("level") == 3]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "passed": not errors,
        "changes": [{"id": c["id"], "level": LEVELS.get(c.get("level"), "info"), "operation": c.get("operation"),
                     "path": c.get("path"), "text": c.get("text")} for c in changes],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))

    lines = [f"## Breaking-change check: {'PASSED' if not errors else 'FAILED'}", ""]
    if changes:
        lines += ["| Level | Endpoint | Change |", "|---|---|---|"]
        lines += [f"| {r['level']} | `{r['operation']} {r['path']}` | {r['text']} |" for r in report["changes"]]
    else:
        lines.append("No breaking changes.")
    if errors:
        lines += ["", "Breaking changes crash existing callers. Ship them as a new major version (for example /v3) "
                  "and deprecate the old one instead (STD-VER-01)."]
    summary = "\n".join(lines) + "\n"
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(summary)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
