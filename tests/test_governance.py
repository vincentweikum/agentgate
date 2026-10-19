"""Tests for the governance tooling itself.

Governance rules are code, so they get tests too: we break a copy of the spec
on purpose and check that every custom agentgate-* rule in the ruleset catches
its problem. The list of rules comes from the ruleset file, so a new rule
without a matching broken case fails this test.
"""

import copy
import json
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "openapi" / "agentgate-claims.yaml"
RULESET = ROOT / "governance" / ".spectral.yaml"

needs_spectral = pytest.mark.skipif(
    not shutil.which("npx") or not (ROOT / "node_modules" / "@stoplight" / "spectral-cli").exists(),
    reason="Spectral not installed (run npm ci)",
)


def test_committed_spec_matches_code():
    result = subprocess.run([sys.executable, "scripts/export_openapi.py", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def _lint(spec_path: Path) -> set[str]:
    out = subprocess.run(
        ["npx", "--no-install", "spectral", "lint", str(spec_path), "--ruleset", str(RULESET), "-f", "json", "--quiet"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    return {f["code"] for f in json.loads(out)} if out.strip().startswith("[") else set()


@needs_spectral
def test_every_custom_rule_catches_its_violation(tmp_path):
    spec = yaml.safe_load(SPEC.read_text())
    bad = copy.deepcopy(spec)
    bad["paths"]["/claimsList"] = {"get": {
        "operationId": "List_Claims", "summary": "x", "description": "x", "tags": ["Claims"],
        "security": [{"OAuth2": ["claims:read"]}],
        "responses": {"200": {"description": "ok"},
                      "404": {"description": "nf", "content": {"application/json": {"schema": {"type": "object"}}}}},
    }}
    claim = bad["components"]["schemas"]["Claim"]
    claim["properties"]["payoutAmount"] = {"type": "number", "format": "double", "minimum": 0, "maximum": 10}
    claim["properties"]["refund_cents"] = {"type": "string", "maxLength": 5, "pattern": "^[0-9]+$"}
    claim["additionalProperties"] = True
    bad["components"]["schemas"]["Policyholder"]["properties"]["email"]["description"] = "Email."
    lst = bad["paths"]["/v2/claims"]["get"]
    lst["parameters"] = [p for p in lst["parameters"] if p["name"] != "limit"]
    bad["paths"]["/v2/claims/{claim_id}/payments"]["post"]["security"] = [{"OAuth2": ["claims:write"]}]
    del bad["paths"]["/v1/claims/{claim_id}"]["get"]["x-sunset"]
    bad["paths"]["/v2/claims"]["get"]["security"] = []
    del bad["paths"]["/v2/claims"]["get"]["summary"]
    bad["paths"]["/v2/claims"]["get"]["responses"]["401"]["content"]["application/problem+json"]["schema"] = {
        "$ref": "#/components/schemas/Claim"}
    del bad["info"]["x-owner"]
    bad["components"]["securitySchemes"]["OAuth2"]["description"] = "OAuth."
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(bad, sort_keys=False))

    found = _lint(path)
    custom_rules = {name for name in yaml.safe_load(RULESET.read_text())["rules"] if name.startswith("agentgate-")}
    assert len(custom_rules) == 17
    assert custom_rules <= found, f"rules that failed to fire: {custom_rules - found}"


@needs_spectral
def test_real_spec_passes_with_exceptions():
    # Fixed date so this test doesn't start failing when the v1 exception expires in 2027
    # (that failure is the point of the real CI lint job, not of this test).
    result = subprocess.run([sys.executable, "scripts/governance_lint.py", "--today", "2026-10-20",
                             "--report", "/dev/null"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout


@needs_spectral
def test_expired_exception_fails_the_build(tmp_path):
    result = subprocess.run([sys.executable, "scripts/governance_lint.py", "--today", "2027-04-05",
                             "--report", str(tmp_path / "r.json")], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 1
    report = json.loads((tmp_path / "r.json").read_text())
    assert {e["id"]: e["state"] for e in report["exceptions"]}["EXC-003"] == "expired"


@needs_spectral
def test_lint_fails_closed_when_it_cannot_run(tmp_path):
    for args in (["--spec", "does-not-exist.yaml"], ["--ruleset", "does-not-exist.yaml"]):
        result = subprocess.run([sys.executable, "scripts/governance_lint.py", *args, "--report", str(tmp_path / "r.json")],
                                cwd=ROOT, capture_output=True, text=True)
        assert result.returncode != 0 and "FAILED" in (result.stdout + result.stderr)


def test_exception_validation_rules(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("gl", ROOT / "scripts" / "governance_lint.py")
    gl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gl)

    f = tmp_path / "exc.yaml"
    f.write_text(yaml.safe_dump({"exceptions": [
        {"id": "EXC-900", "rules": ["x"], "target": "paths", "reason": "Long enough reason for the test.",
         "compensating_controls": ["c"], "requested_by": "a", "approved_by": "b",
         "approved_on": "2026-01-01", "expires_on": "2028-01-01"},
        {"id": "EXC-901", "rules": ["x"], "target": "paths"},
    ]}))
    _, problems = gl.load_exceptions(f, date(2026, 6, 1))
    assert any("at most 12 months" in p for p in problems)
    assert any("missing required field" in p for p in problems)
