# AgentGate API Standards

These are the "enterprise policies" for every API and AI agent integration in this repo.
Each standard has an ID, a plain-English rule, the reason for it, and **how it's enforced**.
Wherever possible, enforcement is automated (governance-as-code) so reviews don't depend on
someone remembering to check.

If a standard doesn't fit a specific case, don't turn the rule off. Request an exception in
[`governance/exceptions.yaml`](governance/exceptions.yaml) with a reason, compensating controls,
an approver, and an expiry date of at most 12 months.

## API design

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-VER-01 | Every path starts with a major version (`/v2/...`). Breaking changes require a new major version. | Callers can upgrade on their own schedule instead of breaking overnight. | Spectral `agentgate-paths-versioned` + oasdiff breaking-change check in CI |
| STD-NAME-01 | Path segments are lowercase kebab-case; path parameters are snake_case. | Consistent URLs across teams. | Spectral `agentgate-paths-kebab-case` |
| STD-NAME-02 | Every operation has a camelCase `operationId` (`getClaim`, `listClaims`). | Generated SDKs, Postman collections, and AI agent tools get clean names. | Spectral `agentgate-operation-id-camel-case`, `operation-operationId` |
| STD-NAME-03 | Schema property names are snake_case. | One naming style in every payload. | Spectral `agentgate-properties-snake-case` |
| STD-DOC-01 | Every operation has a summary, description, and tag. | The API docs and the agent tool descriptions come from these. | Spectral `agentgate-operation-summary`, `operation-description`, `operation-tags` |
| STD-PAGE-01 | List operations take a `limit` parameter with a maximum. | Nobody can pull an unbounded amount of data in one call (OWASP API4). | Spectral `agentgate-list-pagination` |

## Errors

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-ERR-01 | All 4xx/5xx responses use `application/problem+json` (RFC 9457). | Client teams and AI agents handle every error with one piece of code. | Spectral `agentgate-errors-problem-json` |
| STD-ERR-02 | Error responses use the shared `Problem` schema with a stable machine-readable `code`. | Error handling doesn't break when wording changes. | Spectral `agentgate-errors-shared-schema` |
| STD-ERR-03 | Errors never expose stack traces or internals. | Leaked internals help attackers (OWASP API8). | Catch-all handler in `app/errors.py` + unit test |

## Security

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-SEC-01 | Every operation requires an OAuth 2.0 token with at least one scope. | No anonymous access to business data (OWASP API2). | Spectral `agentgate-security-scopes` + OWASP rules + unit tests |
| STD-SEC-02 | Payment operations require `payments:write`, which AI agents never hold. | Money only moves on a human's authority. | Spectral `agentgate-payments-scope` + server check + `config/clients.yaml` review |
| STD-SEC-03 | Each app and each AI agent has its own client identity with least-privilege scopes. | You can always tell who did what, and limit the damage if one client is compromised. | `config/clients.yaml` (CODEOWNERS review) + audit log |
| STD-SEC-04 | Access tokens are short-lived (15 min) RS256 JWTs following RFC 8725, and every OAuth2 scheme documents when tokens expire. | Stolen tokens expire quickly; algorithm confusion attacks are blocked. | `app/auth.py` + unit tests + Spectral `agentgate-token-lifetime` and OWASP `jwt-best-practices` |
| STD-SEC-05 | Every caller is rate limited and the limits are advertised in `RateLimit-*` headers. | Protects the service from abuse and runaway agents (OWASP API4). | `app/ratelimit.py` + OWASP `rate-limit` rules |
| STD-SEC-06 | Code and dependencies are scanned on every pull request. | Catch known vulnerabilities before they ship. | Bandit + pip-audit in CI |

## Data contracts

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-DATA-01 | Object schemas reject unknown fields (`additionalProperties: false`). | Prevents mass-assignment bugs and silent contract drift (OWASP API3). | Spectral `agentgate-closed-objects` |
| STD-DATA-02 | Money is an integer number of cents in a field ending in `_cents`. | Floats and strings cause rounding bugs. | Spectral `agentgate-money-in-cents`, `agentgate-cents-are-integers` |
| STD-DATA-03 | Every string has a max length and a format, pattern, or enum. Every integer has bounds and a format. | Bounded input is harder to abuse (OWASP API4). | OWASP `string-limit`, `string-restricted`, `integer-format` rules |
| STD-DATA-04 | The committed OpenAPI spec always matches the code. | The reviewed contract is the real contract. | `scripts/export_openapi.py --check` in CI |
| STD-PII-01 | Personal data (email, phone, etc.) is masked unless the caller has `pii:read`, and the field description says so. | Agents and apps only see personal data when they need it. | Spectral `agentgate-pii-fields-documented` + masking in API and agent gateway |

## Lifecycle and catalog

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-LIFE-01 | Deprecated operations declare `x-sunset` and `x-successor` and return `Deprecation`, `Sunset`, and `Link` headers. | Callers get machine-readable notice before anything is removed. | Spectral `agentgate-deprecated-has-sunset` + `scripts/catalog.py` (sunset dates match the catalog) + unit tests |
| STD-LIFE-02 | After the sunset date a version returns `410 Gone`. | Retirement actually happens instead of dragging on forever. | `app/lifecycle.py` + unit test |
| STD-CAT-01 | Every API has a catalog entry (owner, lifecycle status, versions, dependencies, consumers), and its spec carries `x-api-id`, `x-owner`, and `x-lifecycle-status`. | Anyone can find who owns an API and what depends on it. | `scripts/catalog.py validate` + Spectral `agentgate-info-catalog-metadata` |

## AI agents

| ID | Standard | Why | Enforced by |
|---|---|---|---|
| STD-AI-01 | Agents reach enterprise APIs only through the agent gateway (MCP), never with raw API credentials in a prompt. | One place to enforce and log every agent action. | `agent_gateway/` |
| STD-AI-02 | Each agent has an explicit tool allowlist. Agents can't even see tools they aren't allowed to use. | Least privilege for agents. | `agent_gateway/agent_policy.yaml` + tests |
| STD-AI-03 | High-risk actions (approving/denying claims, payments) require human approval. Agents can propose, never execute. | A human stays accountable for decisions that affect customers and money. | Approval queue in `agent_gateway/approvals.py` + evals |
| STD-AI-04 | Every agent tool call is written to a tamper-evident audit log (who, what, arguments, decision, result). | Full traceability for audits and incident review. | Hash-chained log with a separate head record in `agent_gateway/audit.py` + `verify` command |
| STD-AI-05 | Agent guardrails are tested with scenarios, including prompt-injection attacks, before changes ship. | Guardrails are proven, not assumed. | `evals/` (runs in CI) |
| STD-AI-06 | AI-assisted code is disclosed in the pull request and gets the same checks plus human review. | Safe adoption of AI coding tools. | [AI-assisted development policy](governance/AI_ASSISTED_DEVELOPMENT.md), PR template, CODEOWNERS |
