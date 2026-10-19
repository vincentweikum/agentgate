"""Loads and checks the agent policy (agent_policy.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

POLICY_FILE = Path(__file__).with_name("agent_policy.yaml")
RISK_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class AgentPolicy:
    agent_id: str
    description: str
    allowed_tools: frozenset[str]
    approval_required: dict = field(default_factory=dict)
    max_payment_cents: int = 0
    max_tool_calls_per_session: int = 20

    def allows(self, tool: str) -> bool:
        return tool in self.allowed_tools

    def needs_approval(self, tool: str, args: dict) -> bool:
        rule = self.approval_required.get(tool)
        if not rule:
            return False
        if rule.get("always"):
            return True
        statuses = rule.get("when_status_in")
        return bool(statuses) and args.get("status") in statuses

    def summary(self) -> dict:
        """What the agent is told about its own permissions (transparency)."""
        return {
            "agent_id": self.agent_id,
            "allowed_tools": sorted(self.allowed_tools),
            "needs_human_approval": {
                tool: ("always" if rule.get("always") else f"when status is one of {rule.get('when_status_in')}")
                for tool, rule in self.approval_required.items()
            },
            "max_payment_dollars": self.max_payment_cents / 100 if self.max_payment_cents else None,
            "max_tool_calls_per_session": self.max_tool_calls_per_session,
            "personal_data": "masked",
        }


@dataclass(frozen=True)
class GatewayPolicy:
    tools: dict[str, dict]
    agents: dict[str, AgentPolicy]

    def for_agent(self, agent_id: str) -> AgentPolicy:
        if agent_id not in self.agents:
            raise PermissionError(f"Agent '{agent_id}' is not registered in the agent policy.")
        return self.agents[agent_id]

    def risk(self, tool: str) -> str:
        return self.tools[tool]["risk"]


def load_policy(path: Path = POLICY_FILE) -> GatewayPolicy:
    raw = yaml.safe_load(path.read_text())
    tools = raw["tools"]
    for name, spec in tools.items():
        if spec.get("risk") not in RISK_LEVELS:
            raise ValueError(f"Tool {name} has invalid risk level {spec.get('risk')!r}")
    agents = {}
    for agent_id, spec in raw["agents"].items():
        unknown = set(spec["allowed_tools"]) - set(tools)
        if unknown:
            raise ValueError(f"Agent {agent_id} allows unknown tools: {sorted(unknown)}")
        for tool in spec.get("approval_required", {}):
            if tool not in spec["allowed_tools"]:
                raise ValueError(f"Agent {agent_id} has an approval rule for {tool}, which it isn't allowed to use")
        # Safety net: every high-risk tool an agent can use must have an approval rule.
        for tool in spec["allowed_tools"]:
            if tools[tool]["risk"] == "high" and tool not in spec.get("approval_required", {}):
                raise ValueError(f"Agent {agent_id} can use high-risk tool {tool} without any human approval rule")
        limits = spec.get("limits", {})
        agents[agent_id] = AgentPolicy(
            agent_id=agent_id,
            description=spec.get("description", ""),
            allowed_tools=frozenset(spec["allowed_tools"]),
            approval_required=spec.get("approval_required", {}),
            max_payment_cents=limits.get("max_payment_cents", 0),
            max_tool_calls_per_session=limits.get("max_tool_calls_per_session", 20),
        )
    return GatewayPolicy(tools=tools, agents=agents)
