"""API catalog: validate entries and list the inventory.

    python scripts/catalog.py validate   # used in CI (STD-CAT-01)
    python scripts/catalog.py list       # print the inventory

Validation checks each catalog/*.yaml file against governance/catalog.schema.json,
then cross-checks it against reality:
  - the spec file exists and its x-api-id / x-owner / x-lifecycle-status match
  - every version in the spec's paths (/v1, /v2) is in the catalog, and vice versa
  - deprecated versions in the catalog are marked deprecated in the spec
  - the spec's x-sunset dates match the catalog's sunset_on
  - every consumer is a registered OAuth client in config/clients.yaml
"""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = ROOT / "catalog"
SCHEMA = json.loads((ROOT / "governance" / "catalog.schema.json").read_text())


def _jsonable(obj):
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj.isoformat() if isinstance(obj, date) else obj


def load_entries() -> list[tuple[Path, dict]]:
    return [(p, _jsonable(yaml.safe_load(p.read_text()))) for p in sorted(CATALOG_DIR.glob("*.yaml"))]


def validate_entry(path: Path, entry: dict, clients: set[str]) -> list[str]:
    problems = [f"schema: {e.message} (at {'/'.join(map(str, e.path)) or 'root'})"
                for e in jsonschema.Draft202012Validator(SCHEMA).iter_errors(entry)]
    if problems:
        return problems

    spec_path = ROOT / entry["spec"]
    if not spec_path.exists():
        return [f"spec file not found: {entry['spec']}"]
    spec = yaml.safe_load(spec_path.read_text())
    info = spec.get("info", {})
    for key, expected in [("x-api-id", entry["api_id"]), ("x-owner", entry["owner"]["team"]),
                          ("x-lifecycle-status", entry["lifecycle_status"])]:
        if info.get(key) != expected:
            problems.append(f"spec info.{key} is {info.get(key)!r}, catalog says {expected!r}")

    spec_versions: dict[str, list[bool]] = {}
    spec_sunsets: dict[str, set[str]] = {}
    for p, item in spec.get("paths", {}).items():
        m = re.match(r"^/(v[0-9]+)/", p)
        if m:
            for op in item.values():
                if isinstance(op, dict):
                    spec_versions.setdefault(m.group(1), []).append(bool(op.get("deprecated")))
                    if op.get("x-sunset"):
                        spec_sunsets.setdefault(m.group(1), set()).add(str(op["x-sunset"]))
    catalog_versions = {v["version"]: v for v in entry["versions"]}
    for v, dates in spec_sunsets.items():
        expected = catalog_versions.get(v, {}).get("sunset_on")
        if dates != {expected}:
            problems.append(f"spec x-sunset for {v} is {sorted(dates)} but the catalog says {expected}")
    for v in sorted(set(spec_versions) - set(catalog_versions)):
        problems.append(f"spec has {v} endpoints that aren't in the catalog")
    for v, info_v in catalog_versions.items():
        if info_v["status"] in ("active", "deprecated") and v not in spec_versions:
            problems.append(f"catalog lists {v} as {info_v['status']} but the spec has no {v} endpoints")
        if info_v["status"] == "deprecated" and v in spec_versions and not all(spec_versions[v]):
            problems.append(f"{v} is deprecated in the catalog but not every {v} operation is marked deprecated")
        if info_v.get("successor") and info_v["successor"] not in catalog_versions:
            problems.append(f"{v} successor {info_v['successor']} isn't in the catalog")

    for consumer in entry["consumers"]:
        if consumer not in clients:
            problems.append(f"consumer {consumer!r} is not a registered OAuth client")
    return problems


def cmd_validate() -> int:
    clients = set(yaml.safe_load((ROOT / "config" / "clients.yaml").read_text())["clients"])
    entries = load_entries()
    failed = False
    for path, entry in entries:
        problems = validate_entry(path, entry, clients)
        if problems:
            failed = True
            print(f"FAIL {path.relative_to(ROOT)}")
            for p in problems:
                print(f"  - {p}")
        else:
            print(f"ok   {path.relative_to(ROOT)}")
    print(f"{len(entries)} catalog entr{'y' if len(entries) == 1 else 'ies'} checked.")
    return 1 if failed or not entries else 0


def cmd_list() -> int:
    for _, e in load_entries():
        versions = ", ".join(f"{v['version']} ({v['status']}" + (f", sunsets {v['sunset_on']})" if v.get("sunset_on") else ")")
                             for v in e["versions"])
        print(f"{e['api_id']:<22} owner={e['owner']['team']:<18} status={e['lifecycle_status']:<10} versions: {versions}")
    return 0


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "validate"
    sys.exit({"validate": cmd_validate, "list": cmd_list}.get(command, cmd_validate)())
