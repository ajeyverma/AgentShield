"""
AgentShield AI — Incident Management Service (Phase 11).

Provides full lifecycle management for security incidents (OPEN, ACKNOWLEDGED,
INVESTIGATING, RESOLVED, CLOSED) with investigator notes, transition history,
and tamper-evident audit trail integration.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError, ValidationError
from agentshield.database.models.incident import (
    IncidentHistoryModel,
    IncidentModel,
    IncidentNoteModel,
)
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService

logger = logging.getLogger("agentshield.services.incident")

VALID_STATUSES = {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class IncidentService:
    """Manages incident lifecycle, notes, assignees, and audit history."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_incident(
        self,
        tenant_id: str,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        affected_agent_ids: list[str] | None = None,
        related_alert_ids: list[str] | None = None,
        related_event_ids: list[str] | None = None,
        assigned_to: str | None = None,
        creator_id: str = "system",
    ) -> IncidentModel:
        """Create a new security incident and log an audit record."""
        sev = severity.upper().strip()
        if sev not in VALID_SEVERITIES:
            raise ValidationError(f"Invalid severity '{severity}'. Allowed: {sorted(VALID_SEVERITIES)}")

        if not title or not title.strip():
            raise ValidationError("Incident title cannot be blank.")

        incident = IncidentModel(
            tenant_id=tenant_id,
            title=title.strip(),
            description=description.strip() if description else "",
            severity=sev,
            status="OPEN",
            affected_agent_ids_json=json.dumps(affected_agent_ids) if affected_agent_ids else None,
            related_alert_ids_json=json.dumps(related_alert_ids) if related_alert_ids else None,
            related_event_ids_json=json.dumps(related_event_ids) if related_event_ids else None,
            assigned_to=assigned_to,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self.session.add(incident)
        await self.session.flush()

        # Record initial history entry
        hist = IncidentHistoryModel(
            incident_id=incident.id,
            previous_status=None,
            new_status="OPEN",
            changed_by=creator_id,
            reason="Incident created",
            created_at=datetime.now(UTC),
        )
        self.session.add(hist)

        # Audit log entry
        audit_svc = TamperEvidentAuditService(self.session)
        await audit_svc.record_audit_entry(
            tenant_id=tenant_id,
            actor_id=creator_id,
            action="incident.created",
            target=incident.id,
            result="SUCCESS",
            description=f"Incident '{incident.title}' created with severity {sev}",
        )

        await self.session.commit()
        await self.session.refresh(incident)

        # Broadcast real-time event
        await broadcaster.broadcast_event(
            user_id=tenant_id,
            event_type="incident.created",
            data={
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
            },
        )
        return incident

    async def update_status(
        self,
        incident_id: str,
        tenant_id: str,
        new_status: str,
        changed_by: str,
        reason: str | None = None,
        resolution_summary: str | None = None,
    ) -> IncidentModel:
        """Transition incident status with strict state validation and auditing."""
        st = new_status.upper().strip()
        if st not in VALID_STATUSES:
            raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}")

        stmt = select(IncidentModel).where(IncidentModel.id == incident_id, IncidentModel.tenant_id == tenant_id)
        incident = (await self.session.execute(stmt)).scalar_one_or_none()
        if not incident:
            raise ValidationError(f"Incident '{incident_id}' not found.")

        old_status = incident.status
        if old_status == st:
            return incident

        # Reopening closed/resolved incident requires reason
        if old_status in ("RESOLVED", "CLOSED") and st in ("OPEN", "INVESTIGATING", "ACKNOWLEDGED"):
            if not reason or not reason.strip():
                raise ValidationError("A reason must be provided when reopening a resolved/closed incident.")

        incident.status = st
        incident.updated_at = datetime.now(UTC)
        if resolution_summary:
            incident.resolution_summary = resolution_summary.strip()

        history = IncidentHistoryModel(
            incident_id=incident.id,
            previous_status=old_status,
            new_status=st,
            changed_by=changed_by,
            reason=reason or f"Transitioned from {old_status} to {st}",
            created_at=datetime.now(UTC),
        )
        self.session.add(history)

        audit_svc = TamperEvidentAuditService(self.session)
        await audit_svc.record_audit_entry(
            tenant_id=tenant_id,
            actor_id=changed_by,
            action="incident.status_updated",
            target=incident.id,
            result="SUCCESS",
            description=f"Incident '{incident.id}' transitioned from {old_status} to {st}: {reason or ''}",
        )

        await self.session.commit()
        await self.session.refresh(incident)

        await broadcaster.broadcast_event(
            user_id=tenant_id,
            event_type="incident.updated",
            data={
                "incident_id": incident.id,
                "previous_status": old_status,
                "status": incident.status,
                "changed_by": changed_by,
            },
        )
        return incident

    async def add_note(
        self,
        incident_id: str,
        tenant_id: str,
        author_id: str,
        author_role: str | None,
        note: str,
    ) -> IncidentNoteModel:
        """Add an investigation note to an incident."""
        if not note or not note.strip():
            raise ValidationError("Incident note cannot be empty.")

        stmt = select(IncidentModel.id).where(IncidentModel.id == incident_id, IncidentModel.tenant_id == tenant_id)
        if not (await self.session.execute(stmt)).scalar_one_or_none():
            raise ValidationError(f"Incident '{incident_id}' not found.")

        note_model = IncidentNoteModel(
            incident_id=incident_id,
            author_id=author_id,
            author_role=author_role,
            note=note.strip(),
            created_at=datetime.now(UTC),
        )
        self.session.add(note_model)
        await self.session.commit()
        await self.session.refresh(note_model)
        return note_model

    async def list_incidents(
        self,
        tenant_id: str,
        status: str | None = None,
        severity: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> dict[str, Any]:
        """List incidents for tenant with pagination and filters."""
        query = select(IncidentModel).where(IncidentModel.tenant_id == tenant_id)
        count_query = select(func.count(IncidentModel.id)).where(IncidentModel.tenant_id == tenant_id)

        if status:
            query = query.where(IncidentModel.status == status.upper())
            count_query = count_query.where(IncidentModel.status == status.upper())
        if severity:
            query = query.where(IncidentModel.severity == severity.upper())
            count_query = count_query.where(IncidentModel.severity == severity.upper())

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(IncidentModel.created_at.desc()).offset(offset).limit(size)
        items = list((await self.session.execute(query)).scalars().all())

        pages = math.ceil(total / size) if size > 0 else 0
        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
        }

    async def get_incident_detail(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve full incident detail including notes and transition history."""
        stmt = select(IncidentModel).where(IncidentModel.id == incident_id, IncidentModel.tenant_id == tenant_id)
        incident = (await self.session.execute(stmt)).scalar_one_or_none()
        if not incident:
            return None

        notes_stmt = (
            select(IncidentNoteModel)
            .where(IncidentNoteModel.incident_id == incident_id)
            .order_by(IncidentNoteModel.created_at.asc())
        )
        notes = list((await self.session.execute(notes_stmt)).scalars().all())

        history_stmt = (
            select(IncidentHistoryModel)
            .where(IncidentHistoryModel.incident_id == incident_id)
            .order_by(IncidentHistoryModel.created_at.asc())
        )
        history = list((await self.session.execute(history_stmt)).scalars().all())

        return {
            "incident": incident,
            "notes": notes,
            "history": history,
        }
