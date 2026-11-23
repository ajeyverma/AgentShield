"""
AgentShield AI — Real-time WebSocket Connection Manager.

Manages active WebSocket client connections grouped by authenticated user_id.
Single-process manager suitable for local/single-worker development.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("agentshield.realtime")


class ConnectionManager:
    """Manages active WebSocket connections grouped by user_id for strict isolation."""

    def __init__(self) -> None:
        # user_id -> set of active WebSockets
        self._connections: dict[str, set[WebSocket]] = {}

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        if user_id not in self._connections:
            self._connections[user_id] = set()
        self._connections[user_id].add(websocket)
        logger.debug(
            "WebSocket client connected",
            extra={"user_id": user_id, "active_clients": len(self._connections[user_id])},
        )

    def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        if user_id in self._connections:
            self._connections[user_id].discard(websocket)
            if not self._connections[user_id]:
                del self._connections[user_id]
        logger.debug("WebSocket client disconnected", extra={"user_id": user_id})

    async def send_personal_message(self, message: dict[str, Any], websocket: WebSocket) -> None:
        try:
            await websocket.send_json(message)
        except Exception as exc:
            logger.warning("Failed to send direct WebSocket message: %s", exc)

    async def broadcast_to_user(self, user_id: str, message: dict[str, Any]) -> None:
        """Broadcast an event ONLY to connections belonging to the specified user."""
        if user_id not in self._connections:
            return

        dead_connections = set()
        for ws in self._connections[user_id]:
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning("Error broadcasting to user %s: %s", user_id, exc)
                dead_connections.add(ws)

        for dead in dead_connections:
            self.disconnect(user_id, dead)

    @property
    def active_user_count(self) -> int:
        return len(self._connections)

    def get_user_connection_count(self, user_id: str) -> int:
        return len(self._connections.get(user_id, set()))


# Global singleton connection manager
manager = ConnectionManager()
