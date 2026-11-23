"""
AgentShield AI — Execution Authorization Manager (Phase 6).

Generates, binds, and cryptographically validates short-lived, single-use server-side
authorization grants before invoking tool adapters.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from agentshield.contracts.execution import ExecutionAuthorizationGrant, ExecutionRequest
from agentshield.execution.exceptions import ApprovalVerificationError

logger = logging.getLogger("agentshield.execution.authorization")


class ExecutionAuthorizationManager:
    """Manages secure, short-lived, single-use server-side execution grants."""

    def __init__(self, default_ttl_seconds: int = 60) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._grants: dict[str, ExecutionAuthorizationGrant] = {}

    def issue_grant(
        self,
        request: ExecutionRequest,
        decision_id: str,
        ttl_seconds: int | None = None,
    ) -> ExecutionAuthorizationGrant:
        """Issue a short-lived execution grant bound to request, identity, and argument hash."""
        now = datetime.now(UTC)
        ttl = ttl_seconds or self.default_ttl_seconds
        grant = ExecutionAuthorizationGrant(
            grant_id=uuid.uuid4(),
            request_id=request.request_id,
            agent_id=str(request.agent_id),
            user_id=str(request.user_id or "system"),
            tool_name=request.tool_name,
            action_name=request.action_name,
            argument_hash=request.canonical_argument_hash,
            decision_id=decision_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
            is_used=False,
        )
        self._grants[str(grant.grant_id)] = grant
        logger.debug("Issued execution grant %s for request %s", grant.grant_id, request.request_id)
        return grant

    def consume_grant(
        self,
        grant_id: str | uuid.UUID,
        request: ExecutionRequest,
    ) -> ExecutionAuthorizationGrant:
        """Verify and mark grant as used. Rejects replays, altered arguments, or expired grants."""
        g_id = str(grant_id)
        grant = self._grants.get(g_id)
        if not grant:
            raise ApprovalVerificationError("Execution authorization grant not found or invalid.")

        if grant.is_used:
            raise ApprovalVerificationError("Replay attack detected: execution grant was already consumed.")

        if datetime.now(UTC) > grant.expires_at:
            raise ApprovalVerificationError("Execution authorization grant has expired.")

        if not grant.is_valid_for(request):
            raise ApprovalVerificationError(
                "Tampering detected: execution request parameters or identity mismatch with authorized grant."
            )

        # Mark consumed atomically
        grant.is_used = True
        return grant

    def clean_expired(self) -> None:
        """Prune expired grants from in-memory cache."""
        now = datetime.now(UTC)
        expired_keys = [k for k, v in self._grants.items() if v.expires_at < now or v.is_used]
        for k in expired_keys:
            self._grants.pop(k, None)


# Global singleton authorization manager
authorization_manager = ExecutionAuthorizationManager()
