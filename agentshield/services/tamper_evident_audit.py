"""
AgentShield AI — Tamper-Evident Audit Service (Phase 11).

Implements cryptographically chained, append-only audit logging where each record
is cryptographically bound to the preceding record via SHA-256 hash chaining.
Provides deterministic verification endpoints to detect unauthorized modifications,
deletions, or re-ordering within the audit trail.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.audit_checkpoint import AuditCheckpointModel
from agentshield.database.models.audit_log import AuditLog
from agentshield.security.sanitization import redact_secrets

logger = logging.getLogger("agentshield.services.tamper_evident_audit")

GENESIS_HASH = "0" * 64


class AuditVerifyResult:
    """Result object supporting both attribute access and tuple unpacking."""

    def __init__(self, is_valid: bool, error_message: str | None, verified_count: int, details: dict[str, Any]):
        self.is_valid = is_valid
        self.error_message = error_message
        self.message = error_message or "Audit chain integrity verified."
        self.verified_count = verified_count
        self.details = details
        self.broken_index = details.get("sequence") or details.get("failed_sequence") or details.get("broken_index")
        self.last_verified_at = datetime.now(UTC)

    def __iter__(self):
        return iter((self.is_valid, self.error_message, self.verified_count, self.details))

    def __getitem__(self, idx: int):
        return (self.is_valid, self.error_message, self.verified_count, self.details)[idx]


def compute_record_hash(
    sequence_number: int,
    previous_hash: str,
    tenant_id: str,
    actor_id: str,
    action: str,
    target: str,
    result: str,
    description: str,
    timestamp_iso: str,
) -> tuple[str, str]:
    """Compute canonical representation and SHA-256 hash for an audit log record.

    Returns:
        (canonical_payload, current_hash)
    """
    canonical_payload = (
        f"seq={sequence_number}|prev={previous_hash}|tenant={tenant_id}|"
        f"actor={actor_id}|action={action}|target={target}|result={result}|"
        f"desc={description}|time={timestamp_iso}"
    )
    current_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    return canonical_payload, current_hash


class TamperEvidentAuditService:
    """Manages append-only cryptographic audit logging and chain integrity validation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record_audit_entry(
        self,
        tenant_id: str,
        actor_id: str,
        action: str,
        target: str,
        result: str,
        description: str = "",
        agent_id: str | None = None,
        event_type: str = "audit.action_logged",
        metadata: dict[str, Any] | None = None,
        actor_role: str | None = None,
        target_type: str | None = None,
        details: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuditLog:
        """Create a new tamper-evident audit record appended to the tenant's hash chain."""
        clean_desc = redact_secrets(description) if description else (action or "")
        clean_target = redact_secrets(target) if target else ""

        # 1. Fetch latest record for this tenant to acquire sequence and previous hash
        stmt = (
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(1)
        )
        latest = (await self.session.execute(stmt)).scalar_one_or_none()

        sequence_number = (latest.sequence_number + 1) if (latest and latest.sequence_number is not None) else 1
        previous_hash = latest.current_hash if (latest and latest.current_hash) else GENESIS_HASH

        now_utc = datetime.now(UTC)
        time_iso = now_utc.isoformat()

        # 2. Compute canonical payload and cryptographic hash
        canonical_payload, current_hash = compute_record_hash(
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            tenant_id=tenant_id,
            actor_id=actor_id,
            action=action,
            target=clean_target,
            result=result,
            description=clean_desc,
            timestamp_iso=time_iso,
        )

        record = AuditLog(
            user_id=tenant_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            agent_id=agent_id,
            event_type=event_type,
            resource_type=action,
            resource_id=clean_target[:36] if clean_target else None,
            action=action,
            target=clean_target,
            result=result,
            description=clean_desc,
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            current_hash=current_hash,
            canonical_payload=canonical_payload,
            created_at=now_utc,
        )
        self.session.add(record)
        await self.session.flush()

        logger.debug(
            "Audit record #%d created for tenant %s (hash=%s)",
            sequence_number,
            tenant_id,
            current_hash[:12],
        )
        return record

    async def verify_chain(
        self,
        tenant_id: str,
    ) -> AuditVerifyResult:
        """Verify the cryptographic integrity of the tenant's audit trail.

        Returns:
            AuditVerifyResult supporting tuple unpacking and attribute access.
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id, AuditLog.sequence_number.isnot(None))
            .order_by(AuditLog.sequence_number.asc())
        )
        records = list((await self.session.execute(stmt)).scalars().all())

        if not records:
            return AuditVerifyResult(True, None, 0, {"status": "EMPTY_CHAIN", "root_hash": GENESIS_HASH})

        expected_previous_hash = GENESIS_HASH
        expected_seq = 1

        for idx, rec in enumerate(records):
            # Check sequential ordering
            if rec.sequence_number != expected_seq:
                err = (
                    f"Sequence discontinuity at record index {idx}: expected #{expected_seq}, "
                    f"found #{rec.sequence_number} (Record ID: {rec.id})"
                )
                logger.error("Audit verification failure: %s", err)
                return AuditVerifyResult(False, err, idx, {"failed_record_id": rec.id, "sequence": rec.sequence_number})

            # Check previous hash connection
            if rec.previous_hash != expected_previous_hash:
                err = (
                    f"Broken hash chain at record #{rec.sequence_number}: stored previous_hash "
                    f"'{rec.previous_hash[:12]}...' does not match expected '{expected_previous_hash[:12]}...'"
                )
                logger.error("Audit verification failure: %s", err)
                return AuditVerifyResult(False, err, idx, {"failed_record_id": rec.id, "sequence": rec.sequence_number})

            # Recompute hash from record content
            if rec.created_at:
                c_time = rec.created_at if rec.created_at.tzinfo else rec.created_at.replace(tzinfo=UTC)
                time_iso = c_time.isoformat()
            else:
                time_iso = ""
            _, computed_hash = compute_record_hash(
                sequence_number=rec.sequence_number,
                previous_hash=rec.previous_hash,
                tenant_id=rec.tenant_id or tenant_id,
                actor_id=rec.actor_id or "",
                action=rec.action or "",
                target=rec.target or "",
                result=rec.result or "",
                description=rec.description or "",
                timestamp_iso=time_iso,
            )

            if computed_hash != rec.current_hash:
                err = (
                    f"Record content tampering at record #{rec.sequence_number}: recomputed hash "
                    f"'{computed_hash[:12]}...' does not match stored hash '{rec.current_hash[:12]}...'"
                )
                logger.error("Audit verification failure: %s", err)
                return AuditVerifyResult(False, err, idx, {"failed_record_id": rec.id, "sequence": rec.sequence_number})

            expected_previous_hash = rec.current_hash
            expected_seq += 1

        latest_hash = records[-1].current_hash
        return AuditVerifyResult(
            True,
            None,
            len(records),
            {
                "status": "VALID",
                "record_count": len(records),
                "head_hash": latest_hash,
                "verified_at": datetime.now(UTC).isoformat(),
            },
        )

    async def create_checkpoint(self, tenant_id: str) -> AuditCheckpointModel:
        """Create a cryptographic checkpoint anchoring the verified audit log state."""
        is_valid, err, count, details = await self.verify_chain(tenant_id)
        if not is_valid:
            raise ValueError(f"Cannot checkpoint invalid or tampered audit chain: {err}")

        head_hash = details.get("head_hash", GENESIS_HASH)
        checkpoint = AuditCheckpointModel(
            tenant_id=tenant_id,
            start_sequence=1,
            end_sequence=count,
            root_hash=head_hash,
            record_count=count,
            is_verified=True,
            created_at=datetime.now(UTC),
        )
        self.session.add(checkpoint)
        await self.session.commit()
        await self.session.refresh(checkpoint)
        return checkpoint

    async def export_audit_trail(
        self,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Export tamper-evident audit records with cryptographic proofs."""
        is_valid, err, count, details = await self.verify_chain(tenant_id)

        stmt = (
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.sequence_number.asc())
        )
        records = list((await self.session.execute(stmt)).scalars().all())

        return {
            "tenant_id": tenant_id,
            "export_timestamp": datetime.now(UTC).isoformat(),
            "chain_valid": is_valid,
            "verification_error": err,
            "record_count": count,
            "head_hash": details.get("head_hash"),
            "records": [
                {
                    "id": r.id,
                    "sequence_number": r.sequence_number,
                    "timestamp": r.created_at.isoformat() if r.created_at else None,
                    "actor_id": r.actor_id,
                    "action": r.action,
                    "target": r.target,
                    "result": r.result,
                    "description": r.description,
                    "previous_hash": r.previous_hash,
                    "current_hash": r.current_hash,
                }
                for r in records
            ],
        }
