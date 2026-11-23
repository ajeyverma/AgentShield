"""
Tests for End-to-End MCP Firewall Gateway Mediation and Proxy (Phase 8).
"""

import json
import uuid
from typing import Any
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.agent import Agent
from agentshield.database.models.mcp import MCPServerModel
from agentshield.database.models.user import User
from agentshield.mcp_gateway.client import MCPUpstreamClient
from agentshield.mcp_gateway.proxy import MCPFirewallGateway


class MockUpstreamClient(MCPUpstreamClient):
    """Mock upstream MCP server for deterministic proxy testing."""

    def __init__(self, server_id: str, server_name: str) -> None:
        super().__init__(
            server_id=server_id,
            server_name=server_name,
            transport_type="stdio",
            endpoint_or_command="python",
        )
        self.invoked_calls: list[tuple[str, dict[str, Any] | None]] = []

    async def connect(self) -> dict[str, Any]:
        self._connected = True
        return {"tools": {"listChanged": True}}

    async def execute_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.invoked_calls.append((method, params))

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": "upstream-1",
                "result": {
                    "tools": [
                        {
                            "name": "read_data",
                            "description": "Reads data records",
                            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                        },
                        {
                            "name": "export_logs",
                            "description": "Exports system logs with secrets",
                            "inputSchema": {"type": "object"},
                        },
                    ]
                },
            }

        elif method == "tools/call":
            tool_name = (params or {}).get("name")
            if tool_name == "read_data":
                return {
                    "jsonrpc": "2.0",
                    "id": "upstream-2",
                    "result": {"status": "ok", "records": [1, 2, 3]},
                }
            elif tool_name == "export_logs":
                # Returns leaked API key in logs
                return {
                    "jsonrpc": "2.0",
                    "id": "upstream-3",
                    "result": {
                        "logs": "Service initialized with OpenAI Key sk-proj-1234567890abcdef1234567890abcdef"
                    },
                }

        return {"jsonrpc": "2.0", "id": "upstream-x", "result": {}}


@pytest.fixture
async def setup_mock_gateway(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    server_id = str(uuid.uuid4())

    user = User(
        id=user_id,
        email=f"mcp-proxy-{uuid.uuid4().hex[:6]}@agentshield.ai",
        username=f"mcp_proxy_{uuid.uuid4().hex[:6]}",
        hashed_password="hashed_pw",
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)

    agent = Agent(
        id=agent_id,
        owner_user_id=user_id,
        agent_name="proxy-agent",
        framework="mcp",
        status="active",
        credential_hash="mock_hash",
    )
    db_session.add(agent)

    server = MCPServerModel(
        id=server_id,
        user_id=user_id,
        server_name="dataservice",
        transport_type="stdio",
        endpoint_or_command="python",
        is_enabled=True,
        trust_classification="internal",
    )
    db_session.add(server)
    await db_session.commit()

    gateway = MCPFirewallGateway()
    mock_client = MockUpstreamClient(server_id=server_id, server_name="dataservice")
    mock_client._connected = True
    gateway._clients[server_id] = mock_client

    return gateway, user, agent, server, mock_client


@pytest.mark.asyncio
async def test_gateway_initialize_and_ping(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    # Initialize
    init_msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    init_resp = await gateway.handle_client_message(db_session, user.id, server.id, init_msg, agent.id)
    assert init_resp["id"] == 1
    assert "capabilities" in init_resp["result"]

    # Ping
    ping_msg = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    ping_resp = await gateway.handle_client_message(db_session, user.id, server.id, ping_msg, agent.id)
    assert ping_resp["id"] == 2
    assert ping_resp["result"] == {}


@pytest.mark.asyncio
async def test_gateway_tools_list_namespacing(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    msg = {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
    resp = await gateway.handle_client_message(db_session, user.id, server.id, msg, agent.id)

    assert resp["id"] == 10
    tools = resp["result"]["tools"]
    assert len(tools) == 2
    # Verify namespacing: dataservice_read_data
    tool_names = [t["name"] for t in tools]
    assert "dataservice_read_data" in tool_names
    assert "dataservice_export_logs" in tool_names


@pytest.mark.asyncio
async def test_gateway_tools_call_allow_and_forwarding(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    # First discover tools to populate registry
    await gateway.handle_client_message(db_session, user.id, server.id, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, agent.id)

    # Call with namespaced name
    call_msg = {
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "dataservice_read_data", "arguments": {"query": "SELECT 1"}},
    }
    resp = await gateway.handle_client_message(db_session, user.id, server.id, call_msg, agent.id)

    assert resp["id"] == 20
    assert resp["result"]["status"] == "ok"
    assert resp["result"]["records"] == [1, 2, 3]

    # Verify upstream was invoked with ORIGINAL name ("read_data")
    assert len(mock_client.invoked_calls) >= 2
    last_call = mock_client.invoked_calls[-1]
    assert last_call[0] == "tools/call"
    assert last_call[1]["name"] == "read_data"


@pytest.mark.asyncio
async def test_gateway_tools_call_secret_redaction(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    await gateway.handle_client_message(db_session, user.id, server.id, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, agent.id)

    call_msg = {
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {"name": "dataservice_export_logs", "arguments": {}},
    }
    resp = await gateway.handle_client_message(db_session, user.id, server.id, call_msg, agent.id)

    assert resp["id"] == 21
    logs = resp["result"]["logs"]
    assert "sk-proj-1234567890abcdef" not in logs
    assert "[OPENAI_API_KEY:" in logs


@pytest.mark.asyncio
async def test_gateway_tools_call_block_never_forwards(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    calls_before = len(mock_client.invoked_calls)

    # Dangerous command injection attempt
    call_msg = {
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": {"name": "bash_exec", "arguments": {"cmd": "rm -rf /"}},
    }
    resp = await gateway.handle_client_message(db_session, user.id, server.id, call_msg, agent.id)

    assert resp["id"] == 22
    assert "error" in resp
    assert resp["error"]["code"] == -32000
    assert "blocked" in resp["error"]["message"].lower()

    # Upstream must NEVER be invoked for a blocked call
    calls_after = len(mock_client.invoked_calls)
    assert calls_after == calls_before


@pytest.mark.asyncio
async def test_gateway_disabled_server_rejected(db_session: AsyncSession, setup_mock_gateway):
    gateway, user, agent, server, mock_client = setup_mock_gateway

    server.is_enabled = False
    await db_session.commit()

    call_msg = {"jsonrpc": "2.0", "id": 23, "method": "ping"}
    resp = await gateway.handle_client_message(db_session, user.id, server.id, call_msg, agent.id)

    assert "error" in resp
    assert resp["error"]["code"] == -32000
    assert "disabled" in resp["error"]["message"]
