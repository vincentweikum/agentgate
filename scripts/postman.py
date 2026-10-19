"""Generate a ready-to-use Postman collection and environment from the OpenAPI spec.

    python scripts/postman.py

The collection is generated from the spec (never hand-maintained), so it can't
drift from the API. We then:
  - set OAuth 2.0 client credentials once at the collection level, using variables
  - make every request inherit that auth
  - turn off optional query parameters so requests work out of the box
  - write a local environment file with placeholders (never real secrets)
Import both files into a Postman workspace and pick the "AgentGate local" environment.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "openapi" / "agentgate-claims.yaml"
OUT = ROOT / "postman" / "agentgate-claims.postman_collection.json"
ENV = ROOT / "postman" / "agentgate-local.postman_environment.json"

COLLECTION_AUTH = {
    "type": "oauth2",
    "oauth2": [
        {"key": "grant_type", "value": "client_credentials", "type": "string"},
        {"key": "accessTokenUrl", "value": "{{baseUrl}}/oauth/token", "type": "string"},
        {"key": "clientId", "value": "{{clientId}}", "type": "string"},
        {"key": "clientSecret", "value": "{{clientSecret}}", "type": "string"},
        {"key": "scope", "value": "{{scope}}", "type": "string"},
        {"key": "client_authentication", "value": "body", "type": "string"},
        {"key": "tokenName", "value": "AgentGate token", "type": "string"},
        {"key": "addTokenTo", "value": "header", "type": "string"},
    ],
}


# Known-good values from the seed data, so every request works out of the box and
# regenerating the collection always produces the same file (the converter's own
# examples are random).
PATH_VALUES = {"policy_id": "POL-100231", "claim_id": "CLM-2001"}
QUERY_VALUES = {"status": "open", "policy_id": "POL-100231", "limit": "20", "offset": "0"}
BODIES = {
    ("POST", "/v2/claims"): {"policy_id": "POL-100231", "loss_type": "collision", "loss_date": "2026-10-10",
                             "description": "Rear-ended at a stoplight on I-880. Bumper and trunk damage.",
                             "estimated_loss_cents": 420000},
    ("POST", "/v2/claims/:claim_id/notes"): {"text": "Called the policyholder to confirm the repair shop."},
    ("PATCH", "/v2/claims/:claim_id/status"): {"status": "under_review", "reason": "Photos and police report received."},
    ("POST", "/v2/claims/:claim_id/payments"): {"amount_cents": 225000, "payee_name": "Lena Fischer",
                                                "approved_by": "J. Alvarez (Claims Supervisor)"},
}


def _set_examples(request: dict) -> None:
    url = request.get("url", {})
    route = "/" + "/".join(url.get("path", []))
    for var in url.get("variable", []):
        var["value"] = "CLM-2004" if route.endswith("/payments") else PATH_VALUES.get(var["key"], var.get("value"))
    for q in url.get("query", []):
        q["value"] = QUERY_VALUES.get(q["key"], q.get("value"))
    body = BODIES.get((request.get("method"), route))
    if body is not None:
        request["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2),
                           "options": {"raw": {"language": "json"}}}


def _strip_ids(node):
    """The converter adds random IDs on every run. Drop them so regenerating is deterministic."""
    if isinstance(node, dict):
        node.pop("id", None)
        for v in node.values():
            _strip_ids(v)
    elif isinstance(node, list):
        for v in node:
            _strip_ids(v)


def _walk(items):
    for item in items:
        if "item" in item:
            yield from _walk(item["item"])
        else:
            yield item


def main() -> int:
    npx = shutil.which("npx")
    if not npx:
        sys.exit("npx not found. Install Node.js and run `npm ci`.")
    subprocess.run([npx, "--no-install", "openapi2postmanv2", "-s", str(SPEC), "-o", str(OUT), "-p",
                    "-O", "folderStrategy=Tags,requestParametersResolution=Example"],
                   check=True, cwd=ROOT, capture_output=True)

    collection = json.loads(OUT.read_text())
    _strip_ids(collection["item"])
    collection["info"].pop("_postman_id", None)
    collection["auth"] = COLLECTION_AUTH
    collection["variable"] = [
        {"key": "baseUrl", "value": "http://localhost:8000"},
        {"key": "clientId", "value": "claims-portal"},
        {"key": "clientSecret", "value": ""},
        {"key": "scope", "value": ""},
    ]
    collection["info"]["description"] = (
        "Generated from openapi/agentgate-claims.yaml by scripts/postman.py. Do not edit by hand. "
        "Choose the 'AgentGate local' environment, set clientSecret, then use Authorization > Get New Access Token."
    )
    for item in _walk(collection["item"]):
        request = item["request"]
        if (request.get("auth") or {}).get("type") == "oauth2":
            request["auth"] = {"type": "inherit"}  # use the collection's OAuth settings
        elif request.get("auth") is None:
            request["auth"] = {"type": "noauth"}  # public endpoint (health check)
        _set_examples(request)
        for q in request.get("url", {}).get("query", []):
            if q["key"] not in ("limit", "offset"):
                q["disabled"] = True
        item.pop("response", None)  # example responses add noise and random data
    OUT.write_text(json.dumps(collection, indent=2) + "\n")

    ENV.write_text(json.dumps({
        "name": "AgentGate local",
        "values": [
            {"key": "baseUrl", "value": "http://localhost:8000", "enabled": True},
            {"key": "clientId", "value": "claims-portal", "enabled": True},
            {"key": "clientSecret", "value": "", "type": "secret", "enabled": True},
            {"key": "scope", "value": "", "enabled": True},
        ],
    }, indent=2) + "\n")
    print(f"Wrote {OUT.relative_to(ROOT)} and {ENV.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
