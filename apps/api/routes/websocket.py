"""
AgentShield AI — WebSocket Real-Time Endpoint.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from agentshield.core.exceptions import AuthenticationError
from agentshield.core.security import decode_access_token
from agentshield.database.session import AsyncSessionLocal
from agentshield.identity.service import UserService
from agentshield.realtime.connection_manager import manager

logger = logging.getLogger("agentshield.api.ws")

router = APIRouter(tags=["Real-time"])


@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    token: Annotated[str | None, Query()] = None,
) -> None:
    """Authenticated real-time event subscription endpoint.

    Token may be provided as query parameter: `?token=<access_token>`.
    """
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing token.")
        return

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token.")
            return

        async with AsyncSessionLocal() as session:
            user_service = UserService(session)
            user = await user_service.repo.get_by_id(user_id)
            if not user or not user.is_active:
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason="Inactive or nonexistent user.",
                )
                return

    except AuthenticationError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid access token.")
        return

    # Accept connection and register user
    await manager.connect(user_id, websocket)

    # Send initial welcome envelope
    await manager.send_personal_message(
        {
            "event_type": "system.connected",
            "message": "Connected to AgentShield real-time stream.",
            "user_id": user_id,
        },
        websocket,
    )

    try:
        while True:
            # Handle client heartbeats or messages
            data = await websocket.receive_text()
            if data.strip().lower() in ("ping", '{"type":"ping"}'):
                await manager.send_personal_message({"type": "pong"}, websocket)
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)
    except Exception as exc:
        logger.warning("WebSocket error for user %s: %s", user_id, exc)
        manager.disconnect(user_id, websocket)
