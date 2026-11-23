"""
AgentShield AI — Emergency Controls Service (Phase 10).

Manages system lockdown, agent disabling, tool disabling, MCP firewall halts,
and execution pauses for rapid incident response.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError, ValidationError
from agentshield.database.models.emergency import EmergencyControlModel
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.security.rbac import UserRole, can_manage_emergency_controls

logger = logging.getLogger("agentshield.services.emergency")

VALID_CONTROL_TYPES = {
    "PAUSE_EXECUTIONS",
    "EMERGENCY_DENY_MODE",
    "DISABLE_AGENT",
    "DISABLE_TOOL",
    "DISABLE_INTEGRATION",
    "REVOKE_CREDENTIAL",
    "DISABLE_MCP_SERVER",
}


class EmergencyControlService:
    """Authoritative service for managing and evaluating active emergency controls."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def activate_control(
        self,
        user_id: str,
        user_role: str | UserRole,
        control_type: str,
        target_identifier: str,
        reason: str,
        tenant_id: str | None = None,
    ) -> EmergencyControlModel:
        """Activate an emergency control. Requires SECURITY_ADMIN or OWNER role."""
        if not can_manage_emergency_controls(user_role):
            raise AuthorizationError(
                f"Role '{user_role}' is not authorized to activate emergency controls. OWNER or SECURITY_ADMIN required."
            )

        c_type = control_type.upper().strip()
        if c_type not in VALID_CONTROL_TYPES:
            raise ValidationError(
                f"Invalid control_type '{control_type}'. Valid types: {sorted(VALID_CONTROL_TYPES)}"
            )

        if not reason or not reason.strip():
            raise ValidationError("Reason is required when activating an emergency control.")

        target = target_identifier.strip()
        if not target:
            raise ValidationError("Target identifier is required.")

        control = EmergencyControlModel(
            user_id=user_id,
            tenant_id=tenant_id,
            control_type=c_type,
            target_identifier=target,
            is_active=True,
            reason=reason.strip(),
            activated_by=user_id,
            activated_at=datetime.now(UTC),
        )
        self.session.add(control)
        await self.session.commit()
        await self.session.refresh(control)

        # Broadcast emergency control event
        await broadcaster.broadcast_event(
            user_id,
            "security.emergency_control.activated",
            {
                "control_id": control.id,
                "control_type": control.control_type,
                "target_identifier": control.target_identifier,
                "reason": control.reason,
                "activated_by": control.activated_by,
                "activated_at": control.activated_at.isoformat() if control.activated_at else None,
            },
        )

        logger.warning(
            "Emergency control '%s' activated on target '%s' by user '%s' (%s): %s",
            c_type,
            target,
            user_id,
            user_role,
            reason,
        )
        return control

    async def revoke_control(
        self,
        control_id: str,
        user_id: str,
        user_role: str | UserRole,
        revocation_reason: str,
    ) -> EmergencyControlModel:
        """Revoke an active emergency control. Requires SECURITY_ADMIN or OWNER role."""
        if not can_manage_emergency_controls(user_role):
            raise AuthorizationError(
                f"Role '{user_role}' is not authorized to revoke emergency controls. OWNER or SECURITY_ADMIN required."
            )

        stmt = select(EmergencyControlModel).where(
            EmergencyControlModel.id == control_id,
            EmergencyControlModel.user_id == user_id,
        )
        control = (await self.session.execute(stmt)).scalar_one_or_none()
        if not control:
            raise ValidationError(f"Emergency control '{control_id}' not found.")

        if not control.is_active:
            return control

        control.is_active = False
        control.revoked_by = user_id
        control.revoked_at = datetime.now(UTC)
        control.revocation_reason = revocation_reason.strip() or "Revoked by administrator."

        await self.session.commit()
        await self.session.refresh(control)

        await broadcaster.broadcast_event(
            user_id,
            "security.emergency_control.revoked",
            {
                "control_id": control.id,
                "control_type": control.control_type,
                "target_identifier": control.target_identifier,
                "revoked_by": control.revoked_by,
                "revoked_at": control.revoked_at.isoformat() if control.revoked_at else None,
                "revocation_reason": control.revocation_reason,
            },
        )

        logger.info("Emergency control '%s' (%s) revoked by '%s'", control.id, control.control_type, user_id)
        return control

    async def list_controls(
        self,
        user_id: str,
        active_only: bool = False,
    ) -> list[EmergencyControlModel]:
        """List emergency controls for user/tenant."""
        stmt = select(EmergencyControlModel).where(EmergencyControlModel.user_id == user_id)
        if active_only:
            stmt = stmt.where(EmergencyControlModel.is_active == True)
        stmt = stmt.order_by(EmergencyControlModel.activated_at.desc())
        return list((await self.session.execute(stmt)).scalars().all())

    async def check_is_blocked(
        self,
        user_id: str,
        agent_id: str | None = None,
        tool_name: str | None = None,
        integration_type: str | None = None,
    ) -> tuple[bool, str | None]:
        """Evaluate whether any active emergency control blocks the operation.

        Returns:
            (is_blocked, blocking_reason)
        """
        stmt = select(EmergencyControlModel).where(
            EmergencyControlModel.user_id == user_id,
            EmergencyControlModel.is_active == True,
        )
        active_controls = (await self.session.execute(stmt)).scalars().all()

        for c in active_controls:
            # Global halts
            if c.control_type in ("PAUSE_EXECUTIONS", "EMERGENCY_DENY_MODE"):
                return True, f"Global lockdown active ({c.control_type}): {c.reason}"

            # Agent block
            if c.control_type in ("DISABLE_AGENT", "REVOKE_CREDENTIAL"):
                if c.target_identifier == "*" or (agent_id and c.target_identifier == agent_id):
                    return True, f"Agent '{agent_id}' disabled by emergency control: {c.reason}"

            # Tool block
            if c.control_type == "DISABLE_TOOL":
                if c.target_identifier == "*" or (tool_name and c.target_identifier.lower() == tool_name.lower()):
                    return True, f"Tool '{tool_name}' disabled by emergency control: {c.reason}"

            # Integration / MCP block
            if c.control_type in ("DISABLE_INTEGRATION", "DISABLE_MCP_SERVER"):
                if c.target_identifier == "*" or (
                    integration_type and c.target_identifier.lower() == integration_type.lower()
                ):
                    return True, f"Integration/MCP '{integration_type}' disabled by emergency control: {c.reason}"

        return False, None
