"""Claims API v2 (current version)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, Security

from ..auth import Principal, authorize
from ..data import ALLOWED_TRANSITIONS, store
from ..errors import APIError, problem_responses
from ..models import (
    CLAIM_ID_PATTERN, POLICY_ID_PATTERN, Claim, ClaimCreate, ClaimNote, ClaimPage, ClaimStatus,
    ClaimSummary, NoteCreate, Payment, PaymentCreate, Policy, StatusUpdate,
)

router = APIRouter(prefix="/v2")

PolicyId = Annotated[str, Path(pattern=POLICY_ID_PATTERN, max_length=10, description="Policy ID, like POL-100231.",
                               examples=["POL-100231"])]
ClaimId = Annotated[str, Path(pattern=CLAIM_ID_PATTERN, max_length=12, description="Claim ID, like CLM-2001.",
                              examples=["CLM-2001"])]
ApprovedClaimId = Annotated[str, Path(pattern=CLAIM_ID_PATTERN, max_length=12,
                                      description="ID of an approved claim, like CLM-2004.", examples=["CLM-2004"])]

COMMON_ERRORS = (401, 403, 429, 500)


def _mask_email(email: str) -> str:
    user, _, domain = email.partition("@")
    return f"{user[:1]}***@{domain}" if domain else "***"


def _mask_phone(phone: str) -> str:
    digits = [c for c in phone if c.isdigit()]
    return f"***-***-{''.join(digits[-4:])}" if len(digits) >= 4 else "***"


def _get_claim_or_404(claim_id: str) -> dict:
    claim = store.get_claim(claim_id)
    if not claim:
        raise APIError(404, "claim_not_found", "Resource not found", f"No claim with ID {claim_id}.")
    return claim


# ---------- Policies ----------

@router.get(
    "/policies/{policy_id}",
    response_model=Policy,
    tags=["Policies"],
    operation_id="getPolicy",
    summary="Get a policy",
    description="Returns policy details. Policyholder email and phone are masked unless the caller has `pii:read`.",
    responses=problem_responses(*COMMON_ERRORS, 404, 422),
)
async def get_policy(
    policy_id: PolicyId,
    principal: Principal = Security(authorize, scopes=["policies:read"]),
) -> Policy:
    policy = store.get_policy(policy_id)
    if not policy:
        raise APIError(404, "policy_not_found", "Resource not found", f"No policy with ID {policy_id}.")
    masked = "pii:read" not in principal.scopes
    if masked:
        ph = policy["policyholder"]
        ph["email"] = _mask_email(ph["email"])
        ph["phone"] = _mask_phone(ph["phone"])
    return Policy(**policy, pii_masked=masked)


# ---------- Claims ----------

@router.get(
    "/claims",
    response_model=ClaimPage,
    tags=["Claims"],
    operation_id="listClaims",
    summary="List claims",
    description="Lists claims, newest IDs last. Filter by status and/or policy. Paginated with limit/offset.",
    responses=problem_responses(*COMMON_ERRORS, 422),
)
async def list_claims(
    status: Annotated[ClaimStatus, Query(description="Only return claims in this status.", examples=["open"])] = None,
    policy_id: Annotated[str, Query(pattern=POLICY_ID_PATTERN, max_length=10, description="Only return claims for this policy.",
                                    examples=["POL-100231"])] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Page size (max 100).", json_schema_extra={"format": "int32"})] = 20,
    offset: Annotated[int, Query(ge=0, le=10_000, description="Number of items to skip.", json_schema_extra={"format": "int32"})] = 0,
    principal: Principal = Security(authorize, scopes=["claims:read"]),
) -> ClaimPage:
    rows = store.list_claims(status.value if status else None, policy_id)
    page = rows[offset: offset + limit]
    next_offset = offset + limit if offset + limit < len(rows) else None
    return ClaimPage(
        items=[ClaimSummary(**{k: r[k] for k in ClaimSummary.model_fields}) for r in page],
        total=len(rows), limit=limit, offset=offset, next_offset=next_offset,
    )


@router.get(
    "/claims/{claim_id}",
    response_model=Claim,
    tags=["Claims"],
    operation_id="getClaim",
    summary="Get a claim",
    description="Returns a claim with its notes and payments.",
    responses=problem_responses(*COMMON_ERRORS, 404, 422),
)
async def get_claim(
    claim_id: ClaimId,
    principal: Principal = Security(authorize, scopes=["claims:read"]),
) -> Claim:
    return Claim(**_get_claim_or_404(claim_id))


@router.post(
    "/claims",
    response_model=Claim,
    status_code=201,
    tags=["Claims"],
    operation_id="createClaim",
    summary="File a new claim",
    description="Creates a claim in `open` status (first notice of loss). The policy must exist and be active.",
    responses=problem_responses(*COMMON_ERRORS, 400, 404, 409, 422),
)
async def create_claim(
    body: ClaimCreate,
    response: Response,
    principal: Principal = Security(authorize, scopes=["claims:write"]),
) -> Claim:
    policy = store.get_policy(body.policy_id)
    if not policy:
        raise APIError(404, "policy_not_found", "Resource not found", f"No policy with ID {body.policy_id}.")
    if policy["status"] != "active":
        raise APIError(409, "policy_not_active", "Conflict",
                       f"Policy {body.policy_id} is {policy['status']}; claims can only be filed on active policies.")
    claim = store.create_claim(body.model_dump(mode="python"), created_by=principal.client_id)
    response.headers["Location"] = f"/v2/claims/{claim['claim_id']}"
    return Claim(**claim)


@router.post(
    "/claims/{claim_id}/notes",
    response_model=ClaimNote,
    status_code=201,
    tags=["Claims"],
    operation_id="addClaimNote",
    summary="Add a note to a claim",
    description="Appends a note. The author is recorded from the caller's token, so notes written by AI agents are always labeled.",
    responses=problem_responses(*COMMON_ERRORS, 400, 404, 422),
)
async def add_claim_note(
    claim_id: ClaimId,
    body: NoteCreate,
    principal: Principal = Security(authorize, scopes=["claims:write"]),
) -> ClaimNote:
    _get_claim_or_404(claim_id)
    return ClaimNote(**store.add_note(claim_id, principal.client_id, principal.client_type, body.text))


@router.patch(
    "/claims/{claim_id}/status",
    response_model=Claim,
    tags=["Claims"],
    operation_id="updateClaimStatus",
    summary="Change a claim's status",
    description=(
        "Moves a claim through its workflow: open -> under_review -> approved/denied -> closed. "
        "Invalid transitions return 409. Approving requires `approved_amount_cents`, which can't exceed the policy's coverage limit."
    ),
    responses=problem_responses(*COMMON_ERRORS, 400, 404, 409, 422),
)
async def update_claim_status(
    claim_id: ClaimId,
    body: StatusUpdate,
    principal: Principal = Security(authorize, scopes=["claims:write"]),
) -> Claim:
    claim = _get_claim_or_404(claim_id)
    current, target = claim["status"], body.status.value
    if target == "paid":
        raise APIError(409, "invalid_transition", "Conflict", "A claim becomes 'paid' only by issuing a payment.")
    if target not in ALLOWED_TRANSITIONS[current]:
        raise APIError(409, "invalid_transition", "Conflict", f"Can't move a claim from '{current}' to '{target}'.")
    if target == "approved":
        if body.approved_amount_cents is None:
            raise APIError(422, "approved_amount_required", "Request validation failed",
                           "approved_amount_cents is required when approving a claim.")
        limit = store.get_policy(claim["policy_id"])["coverage_limit_cents"]
        if body.approved_amount_cents > limit:
            raise APIError(409, "exceeds_coverage", "Conflict", "Approved amount exceeds the policy's coverage limit.")
    updated = store.set_status(claim_id, target, body.approved_amount_cents)
    store.add_note(claim_id, principal.client_id, principal.client_type,
                   f"Status changed {current} -> {target}. Reason: {body.reason}")
    return Claim(**store.get_claim(updated["claim_id"]))


# ---------- Payments ----------

@router.post(
    "/claims/{claim_id}/payments",
    response_model=Payment,
    status_code=201,
    tags=["Payments"],
    operation_id="createPayment",
    summary="Issue a claim payment",
    description=(
        "Issues a payment on an approved claim and marks it paid. Requires `payments:write`, which only "
        "human-operated applications hold. AI agents can propose payments through the agent gateway, "
        "but a human must approve them."
    ),
    responses=problem_responses(*COMMON_ERRORS, 400, 404, 409, 422),
)
async def create_payment(
    claim_id: ApprovedClaimId,
    body: PaymentCreate,
    principal: Principal = Security(authorize, scopes=["payments:write"]),
) -> Payment:
    claim = _get_claim_or_404(claim_id)
    if principal.is_agent:  # defense in depth: agents should never hold payments:write anyway
        raise APIError(403, "agents_cannot_pay", "Forbidden", "AI agents can't issue payments directly.")
    if claim["status"] != "approved":
        raise APIError(409, "claim_not_approved", "Conflict", f"Claim is '{claim['status']}'; only approved claims can be paid.")
    if body.amount_cents > (claim["approved_amount_cents"] or 0):
        raise APIError(409, "exceeds_approved_amount", "Conflict", "Payment exceeds the claim's approved amount.")
    return Payment(**store.add_payment(claim_id, body.amount_cents, body.payee_name, principal.client_id, body.approved_by))
