"""
AgentShield AI — Audit Logs Routes (Enhanced Phase 11).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.services.audit_service import AuditService
from agentshield.services.schemas import (
    AuditCheckpointCreate,
    AuditCheckpointResponse,
    AuditExportResponse,
    AuditLogCreate,
    AuditLogResponse,
    AuditVerifyResponse,
    PaginatedResponse,
)
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    event_type: str | None = None,
) -> PaginatedResponse[AuditLogResponse]:
    """Retrieve immutable audit log records for the authenticated user."""
    service = AuditService(db)
    return await service.list_audit_logs(user.id, page=page, size=size, event_type=event_type)


@router.get("/verify", response_model=AuditVerifyResponse)
async def verify_audit_chain(
    user: CurrentUser,
    db: DbSession,
) -> AuditVerifyResponse:
    """Verify cryptographic hash chain integrity for the authenticated tenant."""
    service = TamperEvidentAuditService(db)
    return await service.verify_chain(tenant_id=user.id)


@router.get("/export", response_model=AuditExportResponse)
async def export_audit_trail(
    user: CurrentUser,
    db: DbSession,
) -> AuditExportResponse:
    """Export complete verifiable audit trail for compliance verification."""
    service = TamperEvidentAuditService(db)
    return await service.export_audit_trail(tenant_id=user.id)


@router.post("/checkpoint", response_model=AuditCheckpointResponse, status_code=status.HTTP_201_CREATED)
async def create_checkpoint(
    payload: AuditCheckpointCreate,
    user: CurrentUser,
    db: DbSession,
) -> AuditCheckpointResponse:
    """Generate a tamper-evident audit checkpoint anchoring verified log state."""
    service = TamperEvidentAuditService(db)
    checkpoint = await service.create_checkpoint(tenant_id=user.id, notes=payload.notes)
    return AuditCheckpointResponse.model_validate(checkpoint)


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: str,
    user: CurrentUser,
    db: DbSession,
) -> AuditLogResponse:
    """Retrieve a specific audit log record."""
    service = AuditService(db)
    log = await service.get_by_id(log_id, user.id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log entry not found.")
    return log


@router.post("", response_model=AuditLogResponse, status_code=status.HTTP_201_CREATED)
async def record_audit_log(
    data: AuditLogCreate,
    user: CurrentUser,
    db: DbSession,
) -> AuditLogResponse:
    """Record an audit trail event."""
    service = AuditService(db)
    return await service.record_log(user.id, data)
