"""
AgentShield AI — Desktop BackendClient Unit Tests.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agentshield.database.base import Base
from agentshield.database.session import engine
from apps.api.main import app
from apps.desktop.services.backend_client import BackendClient


@pytest.fixture(autouse=True)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


class TestDesktopBackendClient:
    def test_client_initialization(self):
        client = BackendClient(base_url="http://localhost:8000")
        assert client.base_url == "http://localhost:8000"
        assert client.is_connected is False
        assert client.token is None
        client.close()

    def test_client_against_asgi_app(self):
        client = BackendClient(base_url="http://testserver")
        client._client = TestClient(app)

        # Health check
        health = client.check_health()
        assert health is not None
        assert client.is_connected is True

        # Register
        user = client.register("clientuser@test.com", "clientuser", "Password123!")
        assert user is not None
        assert user["username"] == "clientuser"

        # Login
        logged_in = client.login("clientuser", "Password123!")
        assert logged_in is True
        assert client.token is not None

        # Dashboard stats
        stats = client.get_dashboard_stats()
        assert stats is not None
        assert "total_agents" in stats

        # Create Agent
        agent = client.create_agent("DesktopBot", "LangGraph")
        assert agent is not None
        assert agent["agent_name"] == "DesktopBot"

        # List Agents
        agents = client.get_agents()
        assert agents is not None
        assert len(agents) == 1

        # WebSocket URL
        ws_url = client.get_websocket_url()
        assert ws_url.startswith("ws://")
        assert "token=" in ws_url

        client.logout()
        assert client.token is None
        client.close()
