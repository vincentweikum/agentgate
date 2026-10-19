"""Data contracts for the Claims API.

These Pydantic models ARE the contract: FastAPI turns them into the OpenAPI
spec, validates every request against them, and filters every response through
them. The governance rules (STANDARDS.md) require that:
  - unknown fields are rejected (STD-DATA-01, OWASP API3)
  - every string has a max length and a format/pattern (STD-DATA-03, OWASP API4)
  - every number has bounds and a format (STD-DATA-03, OWASP API4)
  - money is an integer number of cents, never a float or string (STD-DATA-02)
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, WithJsonSchema

POLICY_ID_PATTERN = r"^POL-[0-9]{6}$"
CLAIM_ID_PATTERN = r"^CLM-[0-9]{4,8}$"
CLIENT_ID_PATTERN = r"^[a-z][a-z0-9-]{2,63}$"
# Free text may contain tabs and newlines but no other control characters
# (blocks log injection and terminal escape tricks).
SAFE_TEXT_PATTERN = r"^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$"
MAX_CENTS = 100_000_000  # $1,000,000.00 ceiling on any single amount

def _json_integer(value: Any) -> Any:
    """Accept what JSON Schema calls an integer (7 or 7.0). Pydantic's default would
    also accept `false` and "85000", which the contract says are invalid."""
    if isinstance(value, (bool, str)):
        raise ValueError("must be a JSON integer, not a string or boolean")
    return value


def _json_string(value: Any) -> Any:
    """Dates must arrive as ISO strings (otherwise `0` would become 1970-01-01)."""
    if not isinstance(value, (str, date)):
        raise ValueError("must be an ISO 8601 date string, like 2026-10-19")
    return value


JsonInt = Annotated[int, BeforeValidator(_json_integer)]

# Dates and timestamps: ISO 8601 strings with explicit length limits.
IsoDate = Annotated[date, BeforeValidator(_json_string), WithJsonSchema({"type": "string", "format": "date", "maxLength": 10})]
UtcDateTime = Annotated[datetime, WithJsonSchema({"type": "string", "format": "date-time", "maxLength": 35})]


def text(max_length: int, min_length: int | None = None, **kw: Any):
    """A free-text field: bounded length, no control characters."""
    return Field(max_length=max_length, min_length=min_length, pattern=SAFE_TEXT_PATTERN, **kw)


def cents(minimum: int = 0, **kw: Any):
    """Money in US cents: integer, bounded, 64-bit. Use with the JsonInt type."""
    return Field(ge=minimum, le=MAX_CENTS, json_schema_extra={"format": "int64"}, **kw)


def int32(ge: int, le: int, **kw: Any):
    return Field(ge=ge, le=le, json_schema_extra={"format": "int32"}, **kw)


# Nullable integers: the bounds and format go on the inner integer type.
OptionalCents = Annotated[int, Field(ge=0, le=MAX_CENTS, json_schema_extra={"format": "int64"}),
                          BeforeValidator(_json_integer)] | None
OptionalOffset = Annotated[int, Field(ge=0, le=10_100, json_schema_extra={"format": "int32"}),
                           BeforeValidator(_json_integer)] | None


class Contract(BaseModel):
    """Base class: unknown fields are rejected, never silently accepted."""

    model_config = ConfigDict(extra="forbid")


# ---------- Enums ----------

class ProductLine(str, Enum):
    auto = "auto"
    home = "home"


class PolicyStatus(str, Enum):
    active = "active"
    lapsed = "lapsed"
    cancelled = "cancelled"


class ClaimStatus(str, Enum):
    open = "open"
    under_review = "under_review"
    approved = "approved"
    denied = "denied"
    paid = "paid"
    closed = "closed"


class LossType(str, Enum):
    collision = "collision"
    comprehensive = "comprehensive"
    liability = "liability"
    theft = "theft"
    water_damage = "water_damage"
    fire = "fire"
    wind_hail = "wind_hail"
    falling_object = "falling_object"


class ClientType(str, Enum):
    application = "application"
    ai_agent = "ai_agent"


# ---------- Policies ----------

class Policyholder(Contract):
    name: str = text(120, description="Policyholder's full name.")
    email: str = Field(max_length=254, pattern=r"^[^\s@]+@[^\s@]+$",
                       description="Contact email. Masked unless the caller has the pii:read scope.")
    phone: str = Field(max_length=32, pattern=r"^[0-9()+*. -]{3,32}$",
                       description="Contact phone. Masked unless the caller has the pii:read scope.")


class Policy(Contract):
    policy_id: str = Field(pattern=POLICY_ID_PATTERN, max_length=10, examples=["POL-100231"])
    product: ProductLine
    status: PolicyStatus
    state: str = Field(pattern=r"^[A-Z]{2}$", max_length=2, description="Two-letter US state code.", examples=["CA"])
    effective_date: IsoDate
    expiration_date: IsoDate
    coverage_limit_cents: JsonInt = cents(description="Coverage limit in US cents.")
    deductible_cents: JsonInt = cents(description="Deductible in US cents.")
    policyholder: Policyholder
    pii_masked: bool = Field(description="True when contact details were masked for this caller.")


# ---------- Claims ----------

class ClaimNote(Contract):
    note_id: str = Field(pattern=r"^NOTE-[0-9]{1,10}$", max_length=15)
    author: str = Field(pattern=CLIENT_ID_PATTERN, max_length=64, description="Client ID that wrote the note.")
    author_type: ClientType
    text: str = text(2000)
    created_at: UtcDateTime


class Payment(Contract):
    payment_id: str = Field(pattern=r"^PAY-[0-9]{1,10}$", max_length=15)
    amount_cents: JsonInt = cents(minimum=1)
    payee_name: str = text(120)
    issued_by: str = Field(pattern=CLIENT_ID_PATTERN, max_length=64, description="Client ID that issued the payment.")
    approved_by: str = text(120, description="Human approver of record.")
    created_at: UtcDateTime


class Claim(Contract):
    claim_id: str = Field(pattern=CLAIM_ID_PATTERN, max_length=12, examples=["CLM-2001"])
    policy_id: str = Field(pattern=POLICY_ID_PATTERN, max_length=10)
    status: ClaimStatus
    loss_type: LossType
    loss_date: IsoDate
    description: str = text(2000)
    estimated_loss_cents: JsonInt = cents()
    approved_amount_cents: OptionalCents = Field(default=None, description="Amount approved, in US cents.")
    notes: list[ClaimNote] = Field(default_factory=list, max_length=200)
    payments: list[Payment] = Field(default_factory=list, max_length=50)
    created_by: str = Field(pattern=CLIENT_ID_PATTERN, max_length=64)
    created_at: UtcDateTime
    updated_at: UtcDateTime


class ClaimSummary(Contract):
    claim_id: str = Field(pattern=CLAIM_ID_PATTERN, max_length=12)
    policy_id: str = Field(pattern=POLICY_ID_PATTERN, max_length=10)
    status: ClaimStatus
    loss_type: LossType
    loss_date: IsoDate
    estimated_loss_cents: JsonInt = cents()
    updated_at: UtcDateTime


class ClaimPage(Contract):
    items: list[ClaimSummary] = Field(max_length=100)
    total: JsonInt = int32(0, 1_000_000)
    limit: JsonInt = int32(1, 100)
    offset: JsonInt = int32(0, 10_000)
    next_offset: OptionalOffset = Field(default=None, description="Offset of the next page, or null on the last page.")


# ---------- Requests ----------

class ClaimCreate(Contract):
    policy_id: str = Field(pattern=POLICY_ID_PATTERN, max_length=10, examples=["POL-100231"])
    loss_type: LossType = Field(examples=["collision"])
    loss_date: IsoDate = Field(examples=["2026-10-10"])
    description: str = text(2000, min_length=10, examples=["Rear-ended at a stoplight on I-880. Bumper and trunk damage."])
    estimated_loss_cents: JsonInt = cents(examples=[420000])


class NoteCreate(Contract):
    text: str = text(2000, min_length=1, examples=["Called the policyholder to confirm the repair shop."])


class StatusUpdate(Contract):
    # The schema states the rule too: approved_amount_cents is required when approving.
    model_config = ConfigDict(extra="forbid", json_schema_extra={
        "if": {"properties": {"status": {"const": "approved"}}, "required": ["status"]},
        "then": {"required": ["approved_amount_cents"],
                 "properties": {"approved_amount_cents": {"type": "integer", "format": "int64",
                                                          "minimum": 0, "maximum": MAX_CENTS}}},
    })

    status: ClaimStatus = Field(examples=["under_review"])
    reason: str = text(500, min_length=3, examples=["Photos and police report received."])
    approved_amount_cents: OptionalCents = Field(default=None, description="Required when status is 'approved'.")


class PaymentCreate(Contract):
    amount_cents: JsonInt = cents(minimum=1, examples=[420000])
    payee_name: str = text(120, min_length=2, examples=["Maria Delgado"])
    approved_by: str = text(120, min_length=2, description="Name of the human who approved this payment.",
                            examples=["J. Alvarez (Claims Supervisor)"])


class Health(Contract):
    status: str = Field(pattern=r"^(ok|degraded)$", max_length=8)
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=32)


# ---------- v1 (deprecated) ----------

class ClaimV1(Contract):
    """Original v1 shape: money as a dollar string, terse field names.

    v2 replaced this because string money caused rounding bugs downstream and
    the field names were ambiguous. Changing them was a breaking change, so it
    required a new major version (STD-VER-01).
    """

    id: str = Field(pattern=CLAIM_ID_PATTERN, max_length=12)
    policy: str = Field(pattern=POLICY_ID_PATTERN, max_length=10)
    status: ClaimStatus
    type: LossType
    amount: str = Field(pattern=r"^[0-9]+\.[0-9]{2}$", max_length=16, description="Estimated loss in dollars, as a string.")
    date: IsoDate
