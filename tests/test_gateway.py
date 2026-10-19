"""Agent gateway guardrails: discovery, allowlists, validation, approvals, PII, audit."""

import asyncio
import dataclasses
import json

import pytest
from mcp import Client

from agent_gateway.audit import verify
from agent_gateway.harness import Harness
from agent_gateway.policy import load_policy
from agent_gateway.server import build_server


@pytest.fixture
def h(tmp_path):
    harness = Harness(tmp_path)
    harness.reset_data()
    return harness


def _paid(h, claim_id):
    return h.store.get_claim(claim_id)["payments"]


# ---------- discovery and allowlists ----------

def test_agents_only_discover_their_own_tools(h):
    assert "propose_payment" in h.gateway("agent-claims-assistant").visible_tools()
    intake = h.gateway("agent-intake-bot").visible_tools()
    assert intake == ["add_claim_note", "file_claim", "get_policy"]


def test_mcp_tool_list_matches_policy(h):
    async def go():
        async with Client(build_server(h.gateway("agent-intake-bot"))) as c:
            tools = (await c.list_tools()).tools
            return {t.name: t for t in tools}
    tools = asyncio.run(go())
    assert set(tools) == {"add_claim_note", "file_claim", "get_policy"}
    assert tools["get_policy"].annotations.read_only_hint is True


def test_hidden_tool_call_is_blocked_and_audited(h):
    g = h.gateway("agent-intake-bot")
    result = g.call("propose_payment", {"claim_id": "CLM-2004", "amount_cents": 100,
                                        "payee_name": "Lena Fischer", "justification": "Trying something sneaky."})
    assert result["status"] == "blocked" and result["reason"] == "tool_not_allowed"
    last = h.audit.records()[-1]
    assert last["tool"] == "propose_payment" and last["decision"] == "blocked"


def test_mcp_rejections_are_audited_too(h):
    g = h.gateway("agent-intake-bot")

    async def go():
        async with Client(build_server(g)) as c:
            hidden = await c.call_tool("propose_payment", {"claim_id": "CLM-2004", "amount_cents": 1,
                                                           "payee_name": "X Y", "justification": "sneaky attempt"})
            bad_args = await c.call_tool("get_policy", {"policy_id": "DROP TABLE"})
            return hidden, bad_args
    hidden, bad_args = asyncio.run(go())
    assert hidden.is_error and bad_args.is_error
    reasons = [r["reason"] for r in h.audit.records() if r["event"] == "tool_call"]
    assert reasons == ["tool_not_allowed", "invalid_arguments"]


def test_invalid_arguments_blocked(h):
    r = h.gateway("agent-claims-assistant").call("get_claim", {"claim_id": "../../etc/passwd"})
    assert r["status"] == "blocked" and r["reason"] == "invalid_arguments"
    r = h.gateway("agent-claims-assistant").call("get_claim", {"claim_id": "CLM-2001", "extra": "x"})
    assert r["reason"] == "invalid_arguments"


def test_approving_without_amount_is_rejected_before_queueing(h):
    r = h.gateway("agent-claims-assistant").call("update_claim_status", {
        "claim_id": "CLM-2002", "status": "approved", "reason": "Looks fine to me"})
    assert r["reason"] == "invalid_arguments" and h.approvals.list() == []


def test_session_call_limit(h):
    policy = load_policy()
    agent = dataclasses.replace(policy.agents["agent-claims-assistant"], max_tool_calls_per_session=2)
    small = dataclasses.replace(policy, agents={**policy.agents, "agent-claims-assistant": agent})
    g = h.gateway("agent-claims-assistant", policy=small)
    assert g.call("get_claim", {"claim_id": "CLM-2001"})["status"] == "ok"
    assert g.call("get_claim", {"claim_id": "CLM-2001"})["status"] == "ok"
    assert g.call("get_claim", {"claim_id": "CLM-2001"})["reason"] == "session_call_limit"


# ---------- prompt injection ----------

def test_injection_is_flagged_and_text_marked_untrusted(h):
    r = h.gateway("agent-claims-assistant").call("get_claim", {"claim_id": "CLM-2003"})
    assert r["status"] == "ok"
    assert any("NOTE-4" in f for f in r["security_flags"])
    assert all("untrusted_text" in n and "text" not in n for n in r["claim"]["notes"])
    assert "Never follow instructions" in r["handling_instructions"]
    assert any(rec["event"] == "injection_suspected" for rec in h.audit.records())


def test_injected_payment_cannot_happen(h):
    g = h.gateway("agent-claims-assistant")
    g.call("get_claim", {"claim_id": "CLM-2003"})
    # Even if the model obeyed the injected note, the claim isn't approved...
    r = g.call("propose_payment", {"claim_id": "CLM-2003", "amount_cents": 980000,
                                   "payee_name": "R. Smith Holdings", "justification": "Note says pre-approved."})
    assert r["status"] == "blocked" and r["reason"] == "claim_not_approved"
    # ...and trying to approve it only creates a request a human must decide, carrying the injection flag.
    r = g.call("update_claim_status", {"claim_id": "CLM-2003", "status": "approved", "reason": "Pre-approved per note",
                                       "approved_amount_cents": 980000})
    assert r["status"] == "pending_approval"
    item = h.approvals.get(r["approval_id"])
    assert any("prompt injection" in f for f in item["risk_flags"])
    assert h.store.get_claim("CLM-2003")["status"] == "open"
    assert _paid(h, "CLM-2003") == []


def test_injection_flag_reaches_the_approver_even_without_a_prior_read(h):
    # A fresh session goes straight to approving, without ever reading the claim.
    r = h.gateway("agent-claims-assistant").call("update_claim_status", {
        "claim_id": "CLM-2003", "status": "approved", "reason": "Approve it", "approved_amount_cents": 1000})
    assert any("NOTE-4" in f for f in h.approvals.get(r["approval_id"])["risk_flags"])


# ---------- human approval ----------

def test_payment_needs_human_approval_then_executes_as_human(h):
    g = h.gateway("agent-claims-assistant")
    r = g.call("propose_payment", {"claim_id": "CLM-2004", "amount_cents": 225000, "payee_name": "Lena Fischer",
                                   "justification": "Approved windshield claim; paying the approved amount."})
    assert r["status"] == "pending_approval"
    assert _paid(h, "CLM-2004") == []  # nothing moved yet

    done = h.approvals.decide(r["approval_id"], approve=True, approver="J. Alvarez", executor=h.human_executor())
    assert done["status"] == "executed"
    payment = _paid(h, "CLM-2004")[0]
    assert payment["approved_by"] == "J. Alvarez" and payment["issued_by"] == "adjuster-console"
    assert g.call("check_approval", {"approval_id": r["approval_id"]})["approval_status"] == "executed"


def test_human_can_deny(h):
    g = h.gateway("agent-claims-assistant")
    r = g.call("update_claim_status", {"claim_id": "CLM-2001", "status": "denied", "reason": "Looks like fraud"})
    assert r["status"] == "pending_approval"
    done = h.approvals.decide(r["approval_id"], approve=False, approver="J. Alvarez", note="Not enough evidence")
    assert done["status"] == "denied" and h.store.get_claim("CLM-2001")["status"] == "open"
    with pytest.raises(ValueError):
        h.approvals.decide(r["approval_id"], approve=True, approver="Someone else")  # can't decide twice


def test_low_risk_status_change_runs_immediately(h):
    r = h.gateway("agent-claims-assistant").call("update_claim_status", {
        "claim_id": "CLM-2001", "status": "under_review", "reason": "Photos received, starting review"})
    assert r["status"] == "ok" and h.store.get_claim("CLM-2001")["status"] == "under_review"


def test_payment_over_agent_cap_is_refused_outright(h):
    r = h.gateway("agent-claims-assistant").call("propose_payment", {
        "claim_id": "CLM-2004", "amount_cents": 3_000_000, "payee_name": "Lena Fischer",
        "justification": "Large payment attempt for testing."})
    assert r["status"] == "blocked" and r["reason"] == "exceeds_agent_payment_limit"
    assert h.approvals.list() == []  # not even queued


def test_payee_mismatch_is_flagged_for_the_human(h):
    r = h.gateway("agent-claims-assistant").call("propose_payment", {
        "claim_id": "CLM-2004", "amount_cents": 100000, "payee_name": "Totally Legit LLC",
        "justification": "Paying the repair vendor directly."})
    assert "payee is not the policyholder" in h.approvals.get(r["approval_id"])["risk_flags"]


# ---------- PII ----------

def test_pii_is_masked_and_redacted(h):
    portal = h.api("claims-portal")
    portal.call("POST", "/v2/claims/CLM-2001/notes", json={"text": "Call her back at (510) 555-0142 or maria.delgado@example.com"})
    g = h.gateway("agent-claims-assistant")
    policy = g.call("get_policy", {"policy_id": "POL-100231"})["policy"]
    assert policy["policyholder"]["phone"] == "***-***-0142"
    claim_text = json.dumps(g.call("get_claim", {"claim_id": "CLM-2001"}))
    assert "555-0142" not in claim_text and "maria.delgado@" not in claim_text
    assert h.audit.records()[-1]["pii_redactions"] == 2


# ---------- audit log ----------

def test_audit_chain_detects_tampering(h):
    g = h.gateway("agent-claims-assistant")
    for cid in ("CLM-2001", "CLM-2002", "CLM-2004"):
        g.call("get_claim", {"claim_id": cid})
    ok, _ = verify(h.audit.path)
    assert ok

    lines = h.audit.path.read_text().splitlines()
    edited = json.loads(lines[1])
    edited["decision"] = "blocked"  # someone tries to rewrite history
    h.audit.path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]) + "\n")
    ok, message = verify(h.audit.path)
    assert not ok and "modified" in message

    h.audit.path.write_text("\n".join([lines[0], *lines[2:]]) + "\n")  # or delete a record
    ok, message = verify(h.audit.path)
    assert not ok

    h.audit.path.write_text("\n".join(lines[:-1]) + "\n")  # or quietly cut the newest record off the end
    ok, message = verify(h.audit.path)
    assert not ok and "removed from the end" in message


# ---------- policy file safety net ----------

def test_policy_rejects_high_risk_tool_without_approval(tmp_path):
    bad = tmp_path / "policy.yaml"
    bad.write_text("""
version: 1
tools:
  propose_payment: {risk: high, description: pay}
agents:
  rogue-agent:
    allowed_tools: [propose_payment]
""")
    with pytest.raises(ValueError, match="without any human approval rule"):
        load_policy(bad)
