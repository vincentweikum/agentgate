"""Claims API v1 (DEPRECATED, sunsets 2027-03-31).

Kept running so existing callers don't break, but marked deprecated in the
spec and on every response. The access log flags v1 calls so the owning team
can see who still needs to migrate before retirement.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Response, Security

from ..auth import Principal, authorize
from ..data import store
from ..errors import APIError, problem_responses
from ..lifecycle import deprecation_headers, ensure_not_retired, version_info
from ..models import CLAIM_ID_PATTERN, ClaimV1

router = APIRouter(prefix="/v1")
SUNSET = str(version_info("v1")["sunset_on"])  # from the catalog entry, the single source of lifecycle truth

LIFECYCLE_HEADERS = {
    "Deprecation": {"description": "When this version was deprecated (RFC 9745).",
                    "schema": {"type": "string", "maxLength": 20, "pattern": "^@[0-9]+$"}},
    "Sunset": {"description": "When this version stops working (RFC 8594).",
               "schema": {"type": "string", "maxLength": 40, "pattern": "^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9:]{8} GMT$"}},
    "Link": {"description": "Points to the replacement endpoint (rel=successor-version).",
             "schema": {"type": "string", "maxLength": 200, "pattern": "^<[^>]+>; rel=\"successor-version\"$"}},
}


@router.get(
    "/claims/{claim_id}",
    response_model=ClaimV1,
    tags=["Claims (v1, deprecated)"],
    operation_id="getClaimV1",
    summary="Get a claim (v1, deprecated)",
    description=f"Deprecated. Use `GET /v2/claims/{{claim_id}}`. Sunsets on {SUNSET}, after which it returns 410 Gone.",
    deprecated=True,
    openapi_extra={"x-sunset": SUNSET, "x-successor": "getClaim"},
    responses={
        200: {"description": "The claim, in the v1 shape.", "headers": LIFECYCLE_HEADERS},
        **problem_responses(401, 403, 404, 410, 422, 429, 500),
    },
)
async def get_claim_v1(
    claim_id: Annotated[str, Path(pattern=CLAIM_ID_PATTERN, max_length=12, description="Claim ID, like CLM-2001.")],
    response: Response,
    principal: Principal = Security(authorize, scopes=["claims:read"]),
) -> ClaimV1:
    ensure_not_retired("v1")
    claim = store.get_claim(claim_id)
    if not claim:
        raise APIError(404, "claim_not_found", "Resource not found", f"No claim with ID {claim_id}.")
    response.headers.update(deprecation_headers("v1", successor_path=f"/v2/claims/{claim_id}"))
    cents = claim["estimated_loss_cents"]
    return ClaimV1(
        id=claim["claim_id"], policy=claim["policy_id"], status=claim["status"], type=claim["loss_type"],
        amount=f"{cents // 100}.{cents % 100:02d}", date=claim["loss_date"],
    )
