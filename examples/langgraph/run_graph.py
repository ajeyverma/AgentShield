"""AgentShield AI — LangGraph Integration Demo (Phase 9).

Demonstrates a LangGraph state graph agent integrated with AgentShield:
1. LangChain / LangGraph tool interfaces dynamically created.
2. `AgentShieldToolNode` seamlessly integrated into graph workflow.
3. ASK_HUMAN triggers workflow interruption / pause for human approval.
4. Path traversal and unauthorized tools strictly blocked.

Usage:
    python examples/langgraph/run_graph.py --simulate
"""

from __future__ import annotations

import argparse
import json
import os
import uuid

from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.langgraph.adapter import LangGraphIntegrationAdapter


def run_demo(simulate: bool = True) -> None:
    print("=" * 72)
    print("   AgentShield AI — LangGraph StateGraph Integration Demo    ")
    print("   Phase 9: Multi-Framework AI Agent Integrations          ")
    print("=" * 72)

    backend_url = "simulate://local" if simulate else (os.getenv("AGENTSHIELD_BACKEND_URL") or "http://localhost:8000")
    config = AgentShieldIntegrationConfig(
        backend_url=backend_url,
        agent_id=str(uuid.uuid4()),
        agent_credential=os.getenv("AGENTSHIELD_AGENT_CREDENTIAL") or "agt_langgraph_demo_secret_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
        fail_closed=True,
    )

    adapter = LangGraphIntegrationAdapter(config)
    tool_node = adapter.create_tool_node(interrupt_on_approval=True)

    print(f"\n[+] Framework: {adapter.framework_type.value}")
    print(f"[+] Agent ID: {config.agent_id}")
    print(f"[+] Tools in LangGraph Node: {list(tool_node.tools_by_name.keys())}\n")

    # Simulate Graph State with Tool Calls
    scenarios = [
        ("Step 1: Normal Calculator Calculation (ALLOW)", [{"id": "call_1", "name": "calculator_add", "args": {"a": 42, "b": 58}}]),
        ("Step 2: Sandboxed File Creation (ALLOW)", [{"id": "call_2", "name": "sandbox_fs_write_file", "args": {"path": "summary.txt", "content": "LangGraph state data"}}]),
        ("Step 3: High-Risk Action Requiring Approval (ASK_HUMAN -> Pause)", [{"id": "call_3", "name": "mock_email_send_email", "args": {"recipient": "exec@example.com", "subject": "Critical Update", "body": "Sensitive graph data"}}]),
        ("Step 4: Unauthorized Directory Traversal Attack (BLOCK)", [{"id": "call_4", "name": "sandbox_fs_read_file", "args": {"path": "../../../windows/win.ini"}}]),
    ]

    for title, tool_calls in scenarios:
        print("-" * 72)
        print(f"[*] {title}")
        simulated_state = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": tc["id"], "function": {"name": tc["name"], "arguments": json.dumps(tc["args"])}}
                        for tc in tool_calls
                    ],
                }
            ]
        }

        result_state = tool_node(simulated_state)
        print(f"    >>> Graph Interrupted for Approval: {result_state.get('agentshield_interrupted')}")
        for msg in result_state.get("messages", []):
            print(f"    >>> ToolMessage: {msg['name']} -> Status: {msg['status']}")
            print(f"        Content: {msg['content'][:100]}...")

    print("-" * 72)
    print("[+] LangGraph Integration Demo Complete: Secure Tool Nodes Operational.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentShield LangGraph Demo")
    parser.add_argument("--simulate", action="store_true", default=True)
    args = parser.parse_args()
    run_demo(simulate=args.simulate)
