"""AgentShield AI — CrewAI Multi-Agent Integration Demo (Phase 9).

Demonstrates a multi-agent CrewAI setup under AgentShield:
1. Senior Researcher and Sub-Agent Analyst roles.
2. Safe agent delegation tracking originating identity and permissions.
3. Sub-agents cannot escalate permissions beyond the parent agent.
4. Tool invocations mediated strictly through AgentShield.

Usage:
    python examples/crewai/run_crew.py --simulate
"""

from __future__ import annotations

import argparse
import os
import uuid

from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.crewai.adapter import CrewAIIntegrationAdapter


def run_demo(simulate: bool = True) -> None:
    print("=" * 72)
    print("   AgentShield AI — CrewAI Multi-Agent Delegation Demo       ")
    print("   Phase 9: Multi-Framework AI Agent Integrations          ")
    print("=" * 72)

    backend_url = "simulate://local" if simulate else (os.getenv("AGENTSHIELD_BACKEND_URL") or "http://localhost:8000")
    config = AgentShieldIntegrationConfig(
        backend_url=backend_url,
        agent_id=str(uuid.uuid4()),
        agent_credential=os.getenv("AGENTSHIELD_AGENT_CREDENTIAL") or "agt_crewai_demo_secret_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email", "mock_http"],
        fail_closed=True,
    )

    adapter = CrewAIIntegrationAdapter(config)
    lead_agent = adapter.create_crew_member(
        name="crew-senior-researcher",
        role="Senior Researcher",
        goal="Direct research and delegate sub-tasks safely",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
    )

    print(f"\n[+] Lead Agent: {lead_agent.name} (ID: {lead_agent.identity.agent_id})")
    print(f"[+] Lead Agent Allowed Tools: {[t.name for t in lead_agent.tools]}")

    # Safely delegate to a Sub-Agent with restricted permissions
    sub_agent = lead_agent.delegate_to(
        sub_agent_name="crew-math-analyst",
        sub_agent_role="Math Analyst",
        restricted_tools=["calculator"],  # Least privilege: only calculator permitted
    )

    print(f"\n[+] Delegated Sub-Agent: {sub_agent.name} (ID: {sub_agent.identity.agent_id})")
    print(f"[+] Sub-Agent Parent ID: {sub_agent.identity.parent_agent_id}")
    print(f"[+] Sub-Agent Originating Lead: {sub_agent.identity.originating_agent_id}")
    print(f"[+] Sub-Agent Allowed Tools (Restricted): {[t.name for t in sub_agent.tools]}")

    # Scenarios
    print("\n" + "=" * 72)
    print("   Testing Sub-Agent Tool Invocations & Least Privilege     ")
    print("=" * 72)

    # 1. Sub-agent uses permitted tool
    calc_tool = sub_agent.tools[0]
    print(f"\n[*] Sub-Agent invokes permitted tool: '{calc_tool.name}'")
    out = calc_tool.run(a=33, b=3)
    print(f"    >>> Result: {out}")

    # 2. Sub-agent attempts to use unpermitted tool outside its restricted scope
    print(f"\n[*] Sub-Agent attempts to use unpermitted tool: 'sandbox_fs'")
    try:
        sub_res = sub_agent.tool_wrapper.route_tool_call("sandbox_fs", "write_file", {"path": "pwn.txt", "content": "bad"})
        print(f"    >>> Tool Call Result: {sub_res.status} - {sub_res.error_message}")
    except Exception as e:
        print(f"    >>> Security Exception Blocked: {type(e).__name__} - {e}")

    # 3. Lead agent performs sandboxed file write
    lead_fs_tool = next(t for t in lead_agent.tools if "sandbox_fs" in t.name)
    print(f"\n[*] Lead Agent invokes permitted tool: '{lead_fs_tool.name}'")
    out2 = lead_fs_tool.run(path="findings.txt", content="Research summary verified")
    print(f"    >>> Result: {out2}")

    print("\n" + "=" * 72)
    print("[+] CrewAI Multi-Agent Delegation Demo Complete: Privileges Isolated.")
    print("=" * 72)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield CrewAI Demo")
    parser.add_argument("--simulate", action="store_true", default=True)
    args = parser.parse_args()
    run_demo(simulate=args.simulate)
