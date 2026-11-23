"""
AgentShield AI — Central Security Event Publisher (Phase 11).

Publishes unified security events, writes to database persistence, records metrics,
triggers alert evaluation, and broadcasts real-time WebSocket events.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.events import EventComponent, EventSeverity, SecurityEvent
from agentshield.database.models.security_event import SecurityEventModel
from agentshield.observability.metrics import metrics_collector
from agentshield.observability.tracing import (
    get_current_correlation_id,
    get_current_span_id,
    get_current_trace_id,
)
from agentshield.realtime.event_broadcaster import broadcaster

logger = logging.getLogger("agentshield.observability.event_publisher")


class EventPublisher:
    """Central publication and persistence hub for all AgentShield security events."""

    def __init__(self) -> None:
        pass

    async def publish(
        self,
        event: SecurityEvent | None = None,
        session: AsyncSession | None = None,
        **kwargs: Any,
    ) -> SecurityEvent:
        """Process, persist, measure, and broadcast a security event."""
        if event is None:
            event_type = kwargs.pop("event_type", "security.event")
            severity = kwargs.pop("severity", EventSeverity.INFO)
            component = kwargs.pop("component", kwargs.pop("source_component", EventComponent.GATEWAY))
            actor_id = kwargs.pop("actor_id", kwargs.get("agent_id") or kwargs.get("tenant_id") or "system")
            metadata = kwargs.pop("metadata", {})
            details = kwargs.pop("details", None)
            if details and isinstance(details, dict):
                metadata = {**metadata, **details}
            event = SecurityEvent(
                event_type=event_type,
                severity=severity,
                source_component=component,
                actor_id=actor_id,
                metadata=metadata,
                **kwargs,
            )

        # 1. Enrich with current tracing context if default
        if not event.trace_id or len(event.trace_id) < 32:
            event.trace_id = get_current_trace_id()
        if not event.span_id or len(event.span_id) < 16:
            event.span_id = get_current_span_id()
        if not event.correlation_id:
            event.correlation_id = get_current_correlation_id()

        # 2. Sanitize any sensitive metadata
        event.sanitize_metadata()

        # 3. Update in-memory metrics
        if event.decision:
            metrics_collector.record_decision(event.decision)
        if event.event_type.startswith("threat."):
            metrics_collector.record_threat(
                severity=event.severity.value,
                category=str(event.sanitized_metadata.get("category", "general")),
            )
        elif event.event_type.startswith("approval."):
            act = event.event_type.split(".")[-1]
            metrics_collector.record_approval_lifecycle(act)

        # 4. Persist to database if session provided
        if session is not None:
            model = SecurityEventModel(
                id=event.event_id,
                event_version=event.event_version,
                timestamp=event.timestamp,
                tenant_id=event.tenant_id,
                actor_id=event.actor_id,
                agent_id=event.agent_id,
                integration_type=event.integration_type,
                session_id=event.session_id,
                request_id=event.request_id,
                execution_id=event.execution_id,
                correlation_id=event.correlation_id,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                event_type=event.event_type,
                severity=event.severity.value,
                source_component=event.source_component.value,
                action=event.action,
                decision=event.decision,
                resource=event.resource,
                metadata_json=json.dumps(event.sanitized_metadata) if event.sanitized_metadata else None,
            )
            session.add(model)
            try:
                await session.flush()
            except Exception as e:
                logger.warning("Failed to flush security event to database: %s", e)

            # 5. Trigger alert engine evaluation
            try:
                from agentshield.alerts.alert_engine import alert_engine
                await alert_engine.evaluate_event(event, session)
            except Exception as err:
                logger.warning("Error evaluating event for alerts: %s", err)

        # 6. Real-time WebSocket broadcast
        await broadcaster.broadcast_event(
            user_id=event.tenant_id,
            event_type=event.event_type,
            data=event.model_dump(mode="json"),
        )

        logger.info(
            "SecurityEvent [%s] %s: %s (actor=%s, decision=%s)",
            event.severity.value,
            event.event_type,
            event.action,
            event.actor_id,
            event.decision,
            extra={
                "tenant_id": event.tenant_id,
                "component": event.source_component.value,
                "event_type": event.event_type,
            },
        )
        return event


event_publisher = EventPublisher()
