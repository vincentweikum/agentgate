"""Export the OpenAPI spec from the code, or check that the committed spec is up to date.

    python scripts/export_openapi.py          # write openapi/agentgate-claims.yaml
    python scripts/export_openapi.py --check  # fail if the committed spec is stale (used in CI)

The committed spec is the reviewed contract. CI fails if someone changes the
code without regenerating and committing the spec, so the contract can never
silently drift from what the service actually does.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SPEC_PATH = ROOT / "openapi" / "agentgate-claims.yaml"


def render() -> str:
    from app.main import create_app

    spec = create_app().openapi()
    header = "# GENERATED from the code by scripts/export_openapi.py. Do not edit by hand.\n"
    return header + yaml.safe_dump(spec, sort_keys=False, allow_unicode=True, width=120)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed spec differs from the code")
    args = parser.parse_args()

    fresh = render()
    if args.check:
        current = SPEC_PATH.read_text() if SPEC_PATH.exists() else ""
        if current != fresh:
            diff = difflib.unified_diff(current.splitlines(), fresh.splitlines(), "committed", "from code", lineterm="", n=2)
            print("\n".join(list(diff)[:80]))
            print("\nSpec drift: run `python scripts/export_openapi.py` and commit the result.", file=sys.stderr)
            return 1
        print("OpenAPI spec is up to date with the code.")
        return 0

    SPEC_PATH.parent.mkdir(exist_ok=True)
    SPEC_PATH.write_text(fresh)
    print(f"Wrote {SPEC_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
