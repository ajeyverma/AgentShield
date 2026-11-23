"""
AgentShield AI — OpenAI Agents SDK Real Integration Demo (Phase 7).

Demonstrates an AI Agent operating under AgentShield runtime protection:
1. Receives natural language user instructions.
2. Selects registered tools (calculator, sandbox_fs, mock_email, mock_http).
3. Tool calls are strictly intercepted and mediated by the AgentShield Execution Gateway.
4. Shows ALLOW, BLOCK, and ASK_HUMAN outcomes in real time.

Usage:
    # Simulated execution (uses local gateway, does not require real OpenAI key):
    python examples/openai_agent_demo.py --simulate

    # Live execution with real OpenAI model:
    export OPENAI_API_KEY="sk-..."
    export AGENTSHIELD_BACKEND_URL="http://localhost:8000"
    export AGENTSHIELD_AGENT_ID="<uuid>"
    export AGENTSHIELD_AGENT_CREDENTIAL="agt_..."
    python examples/openai_agent_demo.py --interactive
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Any

from agentshield.integrations.openai_agents.agent_factory import AgentShieldOpenAIAgent
from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.tool_wrapper import AgentShieldToolWrapper

SAMPLE_PROMPTS = [
    "Calculate 250 multiplied by 48.",
    "Create a file named report.txt inside the sandbox containing Hello AgentShield.",
    "Read report.txt from the sandbox.",
    "Send an email to test@example.com with the subject AgentShield Test.",
    "Read the root file ../../etc/shadow outside the sandbox.",
]


def print_banner() -> None:
    print("=" * 72)
    print("   AgentShield AI — OpenAI Agents SDK Runtime Gateway Demo   ")
    print("   Phase 7: Real AI Agent Interception & Enforcement Layer    ")
    print("=" * 72)


def run_simulated_demo(config: AgentShieldIntegrationConfig, client: AgentShieldOpenAIClient) -> None:
    """Demonstrate gateway interception and enforcement across the sample scenarios."""
    wrapper = AgentShieldToolWrapper(client=client, config=config)
    print(f"\n[+] Permitted Tools in Allowlist: {config.allowed_tools}")
    print(f"[+] Agent ID: {config.agent_id}")
    print(f"[+] Gateway URL: {config.backend_url}{config.api_prefix}\n")

    scenarios = [
        ("Scenario 1: Permitted Math Operation (ALLOW)", "calculator", "multiply", {"a": 250, "b": 48}),
        ("Scenario 2: Sandboxed File Creation (ALLOW)", "sandbox_fs", "create_file", {"path": "report.txt", "content": "Hello AgentShield"}),
        ("Scenario 3: Sandboxed File Read (ALLOW)", "sandbox_fs", "read_file", {"path": "report.txt"}),
        ("Scenario 4: Simulated Email Dispatch (ALLOW / ASK_HUMAN)", "mock_email", "send_email", {"to": "test@example.com", "subject": "AgentShield Test", "body": "Status report"}),
        ("Scenario 5: Path Traversal Attack Attempt (BLOCK)", "sandbox_fs", "read_file", {"path": "../../etc/shadow"}),
        ("Scenario 6: Forbidden File Extension Attempt (BLOCK)", "sandbox_fs", "create_file", {"path": "exploit.sh", "content": "rm -rf /"}),
    ]

    for title, tool, action, args in scenarios:
        print("-" * 72)
        print(f"[*] {title}")
        print(f"    Invoking: {tool}.{action} with args={json.dumps(args)}")

        # Execute through AgentShield tool wrapper
        raw_output = wrapper._execute_through_gateway(tool, action, args)
        parsed = json.loads(raw_output)

        status = parsed.get("status")
        if status == "SUCCESS":
            print(f"    >>> Result [STATUS: {status}]: {parsed.get('result')}")
        elif status == "BLOCKED":
            print(f"    >>> Denied [STATUS: {status}]: {parsed.get('error')}")
        elif status == "PENDING_APPROVAL":
            print(f"    >>> Paused [STATUS: {status}]: {parsed.get('message')}")
        else:
            print(f"    >>> Failed [STATUS: {status}]: {parsed.get('error')}")

    print("-" * 72)
    print("\n[+] Total Intercepted Calls in Session:", len(wrapper.call_history))
    print("[+] All protected operations were mediated server-side; zero local tool execution.")


def run_live_agent(config: AgentShieldIntegrationConfig, prompt: str) -> None:
    """Run real OpenAI agent with natural language prompt."""
    if not config.provider_api_key:
        print("[!] Error: OPENAI_API_KEY environment variable is required for live execution.")
        print("    Use --simulate flag to run without an OpenAI API key.")
        sys.exit(1)

    print(f"\n[+] Initializing AgentShieldOpenAIAgent ({config.model_name})...")
    agent = AgentShieldOpenAIAgent(config=config)

    print(f"\n[*] User Instruction: \"{prompt}\"")
    print("[*] Running agent reasoning and tool execution loop...\n")

    result = agent.run(prompt)
    print("=" * 72)
    print("[+] Agent Final Output:")
    print(result.final_output)
    print("=" * 72)

    summary = agent.get_session_summary()
    print(f"\n[+] Session Observability Summary:")
    print(f"    Total Tool Invocations Intercepted: {summary.total_tool_calls}")
    for inv in summary.tool_invocations:
        print(f"    - Tool: {inv['tool']} | Action: {inv['action']} at {inv['timestamp']}")


def setup_in_process_client() -> tuple[AgentShieldIntegrationConfig, AgentShieldOpenAIClient]:
    """Setup an in-process FastAPI client with a temporary demo user and agent for standalone demonstration."""
    import asyncio
    from agentshield.database.session import initialize_database
    from apps.api.main import app
    from starlette.testclient import TestClient

    # Ensure all tables exist in dev database
    asyncio.run(initialize_database())

    test_client = TestClient(app, base_url="http://testserver")

    # Register demo user and agent
    demo_email = f"demo_{uuid.uuid4().hex[:8]}@agentshield.ai"
    test_client.post("/api/v1/auth/register", json={"email": demo_email, "username": f"demo_{uuid.uuid4().hex[:6]}", "password": "Password123!"})
    login_resp = test_client.post("/api/v1/auth/login", json={"username_or_email": demo_email, "password": "Password123!"})
    token = login_resp.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {token}"}

    # Register Agent
    agent_resp = test_client.post("/api/v1/agents", json={"agent_name": "DemoAgent", "framework": "openai_agents"}, headers=user_headers)
    agent_data = agent_resp.json()
    agent_id = agent_data["id"]
    agent_credential = agent_data["raw_credential"]

    config = AgentShieldIntegrationConfig(
        backend_url="http://testserver",
        agent_id=agent_id,
        agent_credential=agent_credential,
        allowed_tools=["calculator", "sandbox_fs", "mock_email", "mock_http"],
    )
    client = AgentShieldOpenAIClient(config)

    def asgi_execute(tool_name: str, action_name: str, arguments: dict[str, Any], idempotency_key: str | None = None):
        payload = {
            "agent_id": config.agent_id,
            "tool_name": tool_name,
            "action_name": action_name,
            "arguments": arguments,
            "idempotency_key": idempotency_key or f"sdk-{uuid.uuid4()}",
        }
        resp = test_client.post("/api/v1/executions", json=payload, headers={"X-Agent-Credential": config.agent_credential})
        return client._parse_execution_response(resp)

    client.execute_tool = asgi_execute
    return config, client


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentShield AI — OpenAI Agents SDK Integration Demo")
    parser.add_argument("--simulate", action="store_true", help="Run simulated demonstration without calling OpenAI API")
    parser.add_argument("--interactive", action="store_true", help="Run interactive prompt session with live OpenAI model")
    parser.add_argument("--prompt", type=str, default="Calculate 250 multiplied by 48.", help="Prompt to execute")
    parser.add_argument("--backend-url", type=str, default=os.getenv("AGENTSHIELD_BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--agent-id", type=str, default=os.getenv("AGENTSHIELD_AGENT_ID", str(uuid.uuid4())))
    parser.add_argument("--agent-credential", type=str, default=os.getenv("AGENTSHIELD_AGENT_CREDENTIAL", "agt_demo_credential_12345"))
    parser.add_argument("--model", type=str, default=os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    parser.add_argument("--in-process", action="store_true", help="Use in-process FastAPI gateway for standalone demo without starting uvicorn")
    args = parser.parse_args()

    print_banner()

    if args.in_process or args.simulate:
        print("[*] Running demonstration through AgentShield Execution Gateway (In-Process)...")
        config, client = setup_in_process_client()
        run_simulated_demo(config, client)
    else:
        config = AgentShieldIntegrationConfig(
            backend_url=args.backend_url,
            agent_id=args.agent_id,
            agent_credential=args.agent_credential,
            model_name=args.model,
        )
        run_live_agent(config, args.prompt)


if __name__ == "__main__":
    main()
