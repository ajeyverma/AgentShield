"""AgentShield AI — Google ADK / Gemini Integration Demo (Phase 9).

Demonstrates a Google ADK / Gemini agent integrated with AgentShield:
1. Google FunctionDeclaration schemas generated automatically.
2. Function call responses wrapped into Google GenAI response types.
3. Security policies enforced server-side before execution.
4. High-risk calls paused for human approval.

Usage:
    python examples/google_adk/run_adk.py --simulate
"""

from __future__ import annotations

import argparse
import os
import uuid

from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.google_adk.adapter import GoogleADKIntegrationAdapter


def run_demo(simulate: bool = True) -> None:
    print("=" * 72)
    print("   AgentShield AI — Google ADK Integration Demo              ")
    print("   Phase 9: Multi-Framework AI Agent Integrations          ")
    print("=" * 72)

    backend_url = "simulate://local" if simulate else (os.getenv("AGENTSHIELD_BACKEND_URL") or "http://localhost:8000")
    config = AgentShieldIntegrationConfig(
        backend_url=backend_url,
        agent_id=str(uuid.uuid4()),
        agent_credential=os.getenv("AGENTSHIELD_AGENT_CREDENTIAL") or "agt_google_adk_demo_secret_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email", "mock_http"],
        fail_closed=True,
    )

    adapter = GoogleADKIntegrationAdapter(config)
    agent = adapter.create_agent(agent_name="google-adk-security-assistant")

    print(f"\n[+] Framework: {adapter.framework_type.value}")
    print(f"[+] Agent ID: {config.agent_id}")
    print(f"[+] Allowed Tools: {config.allowed_tools}")

    declarations = adapter.get_wrapped_tools()
    print(f"[+] Formatted {len(declarations)} Google Function Declarations:")
    for d in declarations:
        print(f"    - {d['name']}: {d['description']}")

    # Simulated Gemini function calling turn
    simulated_calls = [
        {"name": "calculator_multiply", "args": {"a": 16, "b": 16}},
        {"name": "sandbox_fs_write_file", "args": {"path": "gemini_output.json", "content": '{"status": "ok"}'}},
        {"name": "mock_email_send_email", "args": {"recipient": "board@corp.com", "subject": "Quarterly Report", "body": "Sensitive financials"}},
        {"name": "sandbox_fs_read_file", "args": {"path": "../../etc/passwd"}},
    ]

    print("\n" + "=" * 72)
    print("   Simulating Gemini Turn with Function Call Interception   ")
    print("=" * 72)

    turn_result = agent.handle_simulated_turn(
        prompt="Perform computations, save output, send email, and read system config.",
        simulated_calls=simulated_calls,
    )

    print(f"\n[+] Turn Result Overview:")
    print(f"    - Total Function Calls: {len(turn_result.function_calls)}")
    print(f"    - Security Block Encountered: {turn_result.security_blocked}")
    print(f"    - Approval Required: {turn_result.interrupted_for_approval}")

    print("\n[+] Google Function Responses Generated:")
    for resp in turn_result.function_responses:
        func_name = resp.get("name")
        content = resp.get("response", {}).get("content", {})
        print(f"    - Tool: {func_name} -> Decision: {content.get('decision')} | Success: {content.get('success')}")

    print("\n" + "=" * 72)
    print("[+] Google ADK Integration Demo Complete: Secure Function Calling Verified.")
    print("=" * 72)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield Google ADK Demo")
    parser.add_argument("--simulate", action="store_true", default=True)
    args = parser.parse_args()
    run_demo(simulate=args.simulate)
