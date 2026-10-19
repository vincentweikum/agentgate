# AgentGate

API and AI agent governance for a mock insurance claims API. The API standards are written as
automated checks that run on every pull request, and AI agents reach the API only through a
gateway that limits what they can do and logs everything.

## What's in it

- **Claims API** (`app/`): FastAPI service for policies, claims, notes, and payments. OAuth 2.0
  client credentials with scoped, 15-minute JWTs. Standard RFC 9457 error responses. A deprecated
  v1 with `Deprecation`/`Sunset` headers that returns 410 after its sunset date.
- **Standards as code** (`STANDARDS.md`, `governance/`): each standard is a Spectral lint rule,
  plus the OWASP API Security Top 10 ruleset. Exceptions need a reason, an approver, and an
  expiry date (max 12 months).
- **CI pipeline** (`.github/workflows/`): a reusable workflow other repos can call, plus this
  repo's tests. See below.
- **API catalog** (`catalog/`): owner, lifecycle status, versions, dependencies, and consumers,
  validated against the spec.
- **Postman collection** (`postman/`): generated from the spec.
- **Agent gateway** (`agent_gateway/`): an MCP server. Each agent only sees the tools on its
  allowlist, arguments are validated, high-risk actions (approving claims, payments) wait for a
  human, payments over $25,000 are refused, personal data is masked, and every call goes to a
  hash-chained audit log.
- **Agent guardrail scenarios** (`evals/`): prompt injection, oversized payments, hidden tools,
  bad arguments, and social engineering, checked on every pull request.

## Run it

Needs Python 3.12+ and Node 20+.

```bash
make setup                  # dependencies + random local secrets in .env
source .venv/bin/activate
make run                    # API at http://localhost:8000, docs at /docs
make check                  # everything CI runs
```

To see the agent guardrails work, keep the API running and in another terminal:

```bash
python scripts/agent_demo.py                 # agent hits an injected note, a payment, and the cap
python -m agent_gateway.approvals list       # the payment is waiting for a human
python -m agent_gateway.approvals approve APR-0001 --by "Your Name"
python -m agent_gateway.audit verify         # the audit log is intact
```

## What CI checks on every pull request

| Check | Tool |
|---|---|
| Spec matches the code | `scripts/export_openapi.py --check` |
| Catalog and Postman collection are current | `scripts/catalog.py`, `scripts/postman.py` |
| API standards + OWASP lint, exceptions applied | Spectral, `scripts/governance_lint.py` |
| No breaking changes | oasdiff, `scripts/check_breaking.py` |
| Unit tests | pytest |
| API matches its spec when running | Schemathesis, `scripts/contract_test.py` |
| Agent guardrails hold | `evals/` |
| Code and dependency security | Bandit, pip-audit |

## Limitations

Some parts stand in for production systems: in-memory data, a built-in token endpoint instead
of an identity provider, single-instance rate limiting, SQLite for approvals, a typed-in approver
name instead of SSO, and keyword-based prompt-injection flagging.

Built with an AI coding assistant under the repo's
[AI-assisted development policy](governance/AI_ASSISTED_DEVELOPMENT.md).
