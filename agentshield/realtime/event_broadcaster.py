"""
AgentShield AI — Real-time Event Broadcaster.

Constructs standardized event envelopes and broadcasts them via the
ConnectionManager strictly to authorized users.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from agentshield.realtime.connection_manager import manager


class EventBroadcaster:
    """Helper to publish structured real-time events."""

    def __init__(self, connection_manager=manager) -> None:
        self.manager = connection_manager

    async def broadcast_event(
        self,
        user_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Wrap and broadcast an event to an authenticated user's active clients."""
        envelope = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        await self.manager.broadcast_to_user(user_id, envelope)
        return envelope


broadcaster = EventBroadcaster()
