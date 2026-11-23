"""
AgentShield AI — Mock Email Adapter (Phase 6).

Simulates drafting and sending emails without contacting any external mail server.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from agentshield.execution.adapters.base import BaseToolAdapter
from agentshield.execution.exceptions import ActionNotFoundError, InvalidArgumentsError

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")


class MockEmailAdapter(BaseToolAdapter):
    """Simulated email delivery tool."""

    tool_name = "mock_email"
    tool_version = "1.0.0"

    def run_action(self, action_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> Any:
        to_addr = str(arguments.get("to", "")).strip()
        subject = str(arguments.get("subject", "")).strip()
        body = str(arguments.get("body", "")).strip()

        if not EMAIL_REGEX.match(to_addr):
            raise InvalidArgumentsError(f"Invalid recipient email format: '{to_addr}'.")
        if not subject:
            raise InvalidArgumentsError("Email subject cannot be empty.")

        if action_name == "create_draft":
            draft_id = f"draft-{uuid.uuid4().hex[:12]}"
            return {
                "draft_id": draft_id,
                "status": "draft_saved",
                "to": to_addr,
                "subject": subject,
                "body_snippet": body[:80],
            }
        elif action_name == "send_email":
            msg_id = f"mock-msg-{uuid.uuid4().hex[:12]}"
            return {
                "message_id": msg_id,
                "status": "simulated_sent",
                "to": to_addr,
                "subject": subject,
                "delivered": True,
            }
        else:
            raise ActionNotFoundError(self.tool_name, action_name)
