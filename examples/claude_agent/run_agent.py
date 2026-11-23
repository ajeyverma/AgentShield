"""AgentShield AI — Anthropic Claude Agent SDK Demo (Phase 9).

Demonstrates an Anthropic Claude agent integrated with AgentShield:
1. Anthropic tool schemas generated dynamically.
2. Tool invocations intercepted and sent to AgentShield Execution Gateway.
3. Demonstrates ALLOW, BLOCK, and ASK_HUMAN handling.
4. Zero local execution of protected tools.

Usage:
    python examples/claude_agent/run_agent.py --simulate
"""

from __future__ import annotations

import argparse
import json
import os
import uuid

from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.claude_agent_sdk.adapter import ClaudeIntegrationAdapter
from agentshield.integrations.claude_agent_sdk.agent import AgentShieldClaudeAgent


def run_demo(simulate: bool = True) -> None:
    print("=" * 72)
    print("   AgentShield AI — Anthropic Claude SDK Integration Demo   ")
    print("   Phase 9: Multi-Framework AI Agent Integrations          ")
    print("=" * 72)

    backend_url = "simulate://local" if simulate else (os.getenv("AGENTSHIELD_BACKEND_URL") or "http://localhost:8000")
    config = AgentShieldIntegrationConfig(
        backend_url=backend_url,
        agent_id=str(uuid.uuid4()),
        agent_credential=os.getenv("AGENTSHIELD_AGENT_CREDENTIAL") or "agt_claude_demo_secret_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email", "mock_http"],
        fail_closed=True,
    )

    adapter = ClaudeIntegrationAdapter(config)
    agent = AgentShieldClaudeAgent(adapter=adapter, agent_name="claude-security-assistant")

    print(f"\n[+] Framework: {adapter.framework_type.value}")
    print(f"[+] Agent ID: {config.agent_id}")
    print(f"[+] Allowed Tools: {config.allowed_tools}")
    print(f"[+] Backend URL: {config.backend_url}")
    print(f"[+] Fail Closed Mode: {config.fail_closed}\n")

    tool_specs = adapter.get_wrapped_tools()
    print(f"[+] Generated {len(tool_specs)} Claude-compatible tool schemas:")
    for spec in tool_specs:
        print(f"    - {spec['name']}: {spec['description']}")

    # Scenarios
    scenarios = [
        ("Scenario 1: Permitted Math Operation (ALLOW)", "calculator_multiply", {"a": 125, "b": 8}),
        ("Scenario 2: Sandboxed File Creation (ALLOW)", "sandbox_fs_write_file", {"path": "notes.txt", "content": "AgentShield Claude integration"}),
        ("Scenario 3: Outbound Email Notification (ASK_HUMAN)", "mock_email_send_email", {"recipient": "ops@example.com", "subject": "Audit Alert", "body": "Sensitive payload"}),
        ("Scenario 4: Path Traversal Security Attack (BLOCK)", "sandbox_fs_read_file", {"path": "../../../etc/shadow"}),
    ]

    print("\n" + "=" * 72)
    print("   Executing Tool Invocations Through AgentShield Gateway   ")
    print("=" * 72)

    for title, tool_call_name, args in scenarios:
        print(f"\n[*] {title}")
        print(f"    Calling Tool: '{tool_call_name}' with args={json.dumps(args)}")

        block = {
            "type": "tool_use",
            "id": f"call_{uuid.uuid4().hex[:8]}",
            "name": tool_call_name,
            "input": args,
        }

        results = agent.process_response_tools([block])
        result_block = results[0]
        print(f"    >>> Result Block Type: {result_block.get('type')}")
        print(f"    >>> Is Error: {result_block.get('is_error', False)}")
        print(f"    >>> Content: {result_block.get('content')[:120]}...")

    print("\n" + "=" * 72)
    print("[+] Claude Integration Demo Complete: 100% Intercepted Server-Side.")
    print("=" * 72)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield Claude SDK Demo")
    parser.add_argument("--simulate", action="store_true", default=True, help="Run simulated gateway demo")
    args = parser.parse_args()
    run_demo(simulate=args.simulate)
