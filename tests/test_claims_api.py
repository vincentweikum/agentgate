"""Claims API behavior: contracts, workflow rules, payments, PII masking."""

import pytest


def test_list_claims_paginates(client, auth):
    h = auth("claims-portal")
    page1 = client.get("/v2/claims?limit=4", headers=h).json()
    assert len(page1["items"]) == 4 and page1["total"] == 6 and page1["next_offset"] == 4
    page2 = client.get(f"/v2/claims?limit=4&offset={page1['next_offset']}", headers=h).json()
    assert len(page2["items"]) == 2 and page2["next_offset"] is None


def test_list_claims_filters(client, auth):
    items = client.get("/v2/claims?status=open", headers=auth("claims-portal")).json()["items"]
    assert {c["claim_id"] for c in items} == {"CLM-2001", "CLM-2003"}


def test_limit_is_bounded(client, auth):
    resp = client.get("/v2/claims?limit=5000", headers=auth("claims-portal"))
    assert resp.status_code == 422


def test_get_claim_and_404(client, auth):
    h = auth("claims-portal")
    assert client.get("/v2/claims/CLM-2001", headers=h).json()["status"] == "open"
    resp = client.get("/v2/claims/CLM-9999", headers=h)
    assert resp.status_code == 404 and resp.json()["code"] == "claim_not_found"


def _new_claim(**overrides):
    body = {"policy_id": "POL-100231", "loss_type": "collision", "loss_date": "2026-10-10",
            "description": "Hit a pothole on Broadway; front tire and rim damaged.", "estimated_loss_cents": 85000}
    body.update(overrides)
    return body


def test_create_claim(client, auth):
    resp = client.post("/v2/claims", json=_new_claim(), headers=auth("agent-intake-bot"))
    assert resp.status_code == 201
    claim = resp.json()
    assert claim["status"] == "open" and claim["created_by"] == "agent-intake-bot"
    assert resp.headers["location"] == f"/v2/claims/{claim['claim_id']}"


def test_cannot_file_claim_on_lapsed_policy(client, auth):
    resp = client.post("/v2/claims", json=_new_claim(policy_id="POL-100233"), headers=auth("claims-portal"))
    assert resp.status_code == 409 and resp.json()["code"] == "policy_not_active"


def test_unknown_fields_are_rejected(client, auth):
    resp = client.post("/v2/claims", json=_new_claim(status="approved"), headers=auth("claims-portal"))
    assert resp.status_code == 422
    assert any(e["field"] == "status" for e in resp.json()["errors"])


def test_control_characters_are_rejected(client, auth):
    resp = client.post("/v2/claims", json=_new_claim(description="Normal text\x1b[31m with an escape code"),
                       headers=auth("claims-portal"))
    assert resp.status_code == 422


@pytest.mark.parametrize("bad", [850.5, "85000", True, False])
def test_money_must_be_integer_cents(client, auth, bad):
    resp = client.post("/v2/claims", json=_new_claim(estimated_loss_cents=bad), headers=auth("claims-portal"))
    assert resp.status_code == 422


def test_whole_number_floats_are_valid_json_integers(client, auth):
    # JSON Schema says 850.0 IS an integer, so the contract requires accepting it.
    resp = client.post("/v2/claims", json=_new_claim(estimated_loss_cents=85000.0), headers=auth("claims-portal"))
    assert resp.status_code == 201 and resp.json()["estimated_loss_cents"] == 85000


@pytest.mark.parametrize("bad", [0, 1700000000, True])
def test_dates_must_be_strings(client, auth, bad):
    resp = client.post("/v2/claims", json=_new_claim(loss_date=bad), headers=auth("claims-portal"))
    assert resp.status_code == 422


def test_status_workflow(client, auth):
    h = auth("adjuster-console")
    ok = client.patch("/v2/claims/CLM-2001/status", json={"status": "under_review", "reason": "Docs received"}, headers=h)
    assert ok.status_code == 200 and ok.json()["status"] == "under_review"
    assert "open -> under_review" in ok.json()["notes"][-1]["text"]

    bad = client.patch("/v2/claims/CLM-2001/status", json={"status": "closed", "reason": "skip ahead"}, headers=h)
    assert bad.status_code == 409 and bad.json()["code"] == "invalid_transition"

    no_amount = client.patch("/v2/claims/CLM-2001/status", json={"status": "approved", "reason": "Looks good"}, headers=h)
    assert no_amount.status_code == 422

    too_much = client.patch("/v2/claims/CLM-2001/status",
                            json={"status": "approved", "reason": "Looks good", "approved_amount_cents": 99_000_000}, headers=h)
    assert too_much.status_code == 409 and too_much.json()["code"] == "exceeds_coverage"


def test_cannot_mark_paid_directly(client, auth):
    resp = client.patch("/v2/claims/CLM-2004/status", json={"status": "paid", "reason": "shortcut"},
                        headers=auth("adjuster-console"))
    assert resp.status_code == 409


def test_human_can_pay_approved_claim(client, auth):
    resp = client.post("/v2/claims/CLM-2004/payments",
                       json={"amount_cents": 225000, "payee_name": "Lena Fischer", "approved_by": "J. Alvarez"},
                       headers=auth("adjuster-console"))
    assert resp.status_code == 201
    claim = client.get("/v2/claims/CLM-2004", headers=auth("adjuster-console")).json()
    assert claim["status"] == "paid" and claim["payments"][0]["approved_by"] == "J. Alvarez"


def test_cannot_overpay(client, auth):
    resp = client.post("/v2/claims/CLM-2004/payments",
                       json={"amount_cents": 999999, "payee_name": "Lena Fischer", "approved_by": "J. Alvarez"},
                       headers=auth("adjuster-console"))
    assert resp.status_code == 409 and resp.json()["code"] == "exceeds_approved_amount"


def test_cannot_pay_unapproved_claim(client, auth):
    resp = client.post("/v2/claims/CLM-2003/payments",
                       json={"amount_cents": 980000, "payee_name": "R. Smith Holdings", "approved_by": "Nobody"},
                       headers=auth("adjuster-console"))
    assert resp.status_code == 409 and resp.json()["code"] == "claim_not_approved"


def test_ai_agent_cannot_pay(client, auth):
    resp = client.post("/v2/claims/CLM-2004/payments",
                       json={"amount_cents": 1000, "payee_name": "Anyone", "approved_by": "Nobody"},
                       headers=auth("agent-claims-assistant"))
    assert resp.status_code == 403


@pytest.mark.parametrize("client_id,masked", [("agent-claims-assistant", True), ("claims-portal", False)])
def test_pii_masking(client, auth, client_id, masked):
    policy = client.get("/v2/policies/POL-100231", headers=auth(client_id)).json()
    assert policy["pii_masked"] is masked
    if masked:
        assert policy["policyholder"]["phone"] == "***-***-0142"
        assert policy["policyholder"]["email"] == "m***@example.com"
    else:
        assert policy["policyholder"]["phone"] == "(510) 555-0142"


def test_agent_notes_are_labeled(client, auth):
    note = client.post("/v2/claims/CLM-2001/notes", json={"text": "Summarized photos for the adjuster."},
                       headers=auth("agent-claims-assistant")).json()
    assert note["author"] == "agent-claims-assistant" and note["author_type"] == "ai_agent"
