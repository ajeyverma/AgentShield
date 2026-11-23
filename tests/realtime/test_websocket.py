"""
AgentShield AI — WebSocket Real-Time Integration Tests.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agentshield.core.security import create_access_token
from agentshield.database.base import Base
from agentshield.database.models import User
from agentshield.database.session import AsyncSessionLocal, engine
from agentshield.realtime.connection_manager import manager
from agentshield.realtime.event_broadcaster import broadcaster
from apps.api.main import app


@pytest.fixture(autouse=True)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


class TestWebSocketEvents:
    def test_websocket_missing_token_rejected(self):
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect("/api/v1/ws/events"):
                pass

    def test_websocket_invalid_token_rejected(self):
        client = TestClient(app)
        with pytest.raises(Exception):
            with client.websocket_connect("/api/v1/ws/events?token=invalid_jwt_token"):
                pass

    async def test_websocket_authenticated_connection_and_user_isolation(self):
        # Create users
        async with AsyncSessionLocal() as session:
            u1 = User(id="user-ws-1", email="ws1@test.com", username="ws1", hashed_password="pwd")
            u2 = User(id="user-ws-2", email="ws2@test.com", username="ws2", hashed_password="pwd")
            session.add_all([u1, u2])
            await session.commit()

        token1 = create_access_token(subject="user-ws-1")
        token2 = create_access_token(subject="user-ws-2")

        client = TestClient(app)

        with client.websocket_connect(f"/api/v1/ws/events?token={token1}") as ws1:
            welcome1 = ws1.receive_json()
            assert welcome1["event_type"] == "system.connected"
            assert welcome1["user_id"] == "user-ws-1"

            # Ping pong
            ws1.send_text("ping")
            pong = ws1.receive_json()
            assert pong.get("type") == "pong"

            # Broadcast event to user-ws-1
            await broadcaster.broadcast_event(
                user_id="user-ws-1",
                event_type="activity.created",
                data={"tool": "test_tool"},
            )
            event = ws1.receive_json()
            assert event["event_type"] == "activity.created"
            assert event["data"]["tool"] == "test_tool"

            # Verify user-ws-2 isolation: broadcasting to user-ws-2 should NOT be received by ws1
            await broadcaster.broadcast_event(
                user_id="user-ws-2",
                event_type="threat.created",
                data={"severity": "CRITICAL"},
            )
            # Send another ping to ws1 to confirm it gets pong, not user-ws-2's event
            ws1.send_text("ping")
            pong2 = ws1.receive_json()
            assert pong2.get("type") == "pong"
