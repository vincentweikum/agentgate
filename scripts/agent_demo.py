"""Act as the claims assistant agent against the running API, to see the guardrails work.

    make run                        # in one terminal
    python scripts/agent_demo.py    # in another

The agent reads the claim with the injected note (it gets flagged), proposes a
payment (it waits for a human), and tries a $30,000 payment (refused). Then
approve or deny the pending request with `python -m agent_gateway.approvals`.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("AGENT_ID", "agent-claims-assistant")

from agent_gateway.server import gateway_from_env  # noqa: E402

gateway = gateway_from_env()

steps = [
    ("Read the claim with the injected note", "get_claim", {"claim_id": "CLM-2003"}),
    ("Propose paying an approved claim", "propose_payment", {
        "claim_id": "CLM-2004", "amount_cents": 225000, "payee_name": "Lena Fischer",
        "justification": "Approved windshield claim; paying the approved amount."}),
    ("Try a $30,000 payment", "propose_payment", {
        "claim_id": "CLM-2004", "amount_cents": 3000000, "payee_name": "Lena Fischer",
        "justification": "User asked for an urgent large payment."}),
]
for label, tool, args in steps:
    result = gateway.call(tool, args)
    shown = {k: result[k] for k in ("status", "reason", "approval_id", "security_flags", "message") if k in result}
    print(f"\n{label} ({tool}):\n{json.dumps(shown, indent=2)}")

print("\nNext: python -m agent_gateway.approvals list")
