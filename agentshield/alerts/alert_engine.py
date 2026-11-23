"""
AgentShield AI — Deterministic Security Alert Engine (Phase 11).

Evaluates security events against stateful, windowed, deterministic rules without
relying on non-deterministic LLMs. Includes deduplication and cooldown mechanisms
to prevent alert flooding while ensuring critical incident generation.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.events import SecurityEvent
from agentshield.database.models.alert import SecurityAlertModel
from agentshield.realtime.event_broadcaster import broadcaster

logger = logging.getLogger("agentshield.alerts.engine")


@dataclass
class AlertRule:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    threshold: int
    window_seconds: float
    cooldown_seconds: float = 60.0


class SecurityAlertEngine:
    """Stateful, deterministic alert generation engine."""

    def __init__(self) -> None:
        self.rules: dict[str, AlertRule] = {
            "RULE_REPEATED_BLOCKS": AlertRule(
                rule_id="RULE_REPEATED_BLOCKS",
                rule_name="Repeated Security Policy Blocks",
                category="policy_violation",
                severity="HIGH",
                description="Agent attempted multiple prohibited actions in rapid succession.",
                threshold=3,
                window_seconds=60.0,
                cooldown_seconds=60.0,
            ),
            "RULE_HIGH_TOOL_FREQUENCY": AlertRule(
                rule_id="RULE_HIGH_TOOL_FREQUENCY",
                rule_name="Abnormally High Tool-Call Frequency",
                category="rate_anomaly",
                severity="MEDIUM",
                description="Agent is executing tool calls at an abnormally high frequency.",
                threshold=10,
                window_seconds=10.0,
                cooldown_seconds=45.0,
            ),
            "RULE_PROMPT_INJECTION_CLUSTER": AlertRule(
                rule_id="RULE_PROMPT_INJECTION_CLUSTER",
                rule_name="Prompt Injection Attack Cluster",
                category="prompt_injection",
                severity="CRITICAL",
                description="Multiple prompt injection attempts detected targeting the agent.",
                threshold=2,
                window_seconds=120.0,
                cooldown_seconds=60.0,
            ),
            "RULE_DATA_EXFILTRATION": AlertRule(
                rule_id="RULE_DATA_EXFILTRATION",
                rule_name="Potential Sensitive Data Exfiltration Attempt",
                category="data_leakage",
                severity="CRITICAL",
                description="Agent attempted to access or transmit sensitive credentials/PII.",
                threshold=1,
                window_seconds=1.0,
                cooldown_seconds=30.0,
            ),
            "RULE_DANGEROUS_COMMAND": AlertRule(
                rule_id="RULE_DANGEROUS_COMMAND",
                rule_name="Dangerous Terminal Command Attempt",
                category="terminal_threat",
                severity="CRITICAL",
                description="Suspicious or destructive shell command was evaluated.",
                threshold=1,
                window_seconds=1.0,
                cooldown_seconds=30.0,
            ),
            "RULE_CROSS_TENANT": AlertRule(
                rule_id="RULE_CROSS_TENANT",
                rule_name="Cross-Tenant Access Attempt",
                category="authorization",
                severity="CRITICAL",
                description="Unauthorized access across tenant boundaries was prevented.",
                threshold=1,
                window_seconds=1.0,
                cooldown_seconds=30.0,
            ),
            "RULE_EMERGENCY_LOCKDOWN": AlertRule(
                rule_id="RULE_EMERGENCY_LOCKDOWN",
                rule_name="Emergency Security Lockdown Activated",
                category="emergency_control",
                severity="CRITICAL",
                description="An administrator activated an emergency lockdown control.",
                threshold=1,
                window_seconds=1.0,
                cooldown_seconds=10.0,
            ),
        }

        # Sliding window history: rule_id:target_id -> list of float timestamps
        self._history: dict[str, list[float]] = defaultdict(list)
        # Cooldown map: rule_id:target_id -> float last_alert_timestamp
        self._cooldowns: dict[str, float] = {}

    async def evaluate_event(
        self,
        event: SecurityEvent,
        session: AsyncSession | None = None,
    ) -> list[SecurityAlertModel]:
        """Evaluate an incoming security event against active deterministic rules."""
        alerts_generated: list[SecurityAlertModel] = []
        now = time.time()
        target_id = event.agent_id or event.actor_id or "system"

        # 1. Rule: Repeated BLOCK decisions
        if event.decision == "BLOCK":
            alert = await self._check_window_rule(
                rule_id="RULE_REPEATED_BLOCKS",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 2. Rule: High tool call frequency
        if event.action in ("execute_tool", "tool_call", "call_tool"):
            alert = await self._check_window_rule(
                rule_id="RULE_HIGH_TOOL_FREQUENCY",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 3. Rule: Prompt injection cluster
        if event.event_type == "threat.detected" and "prompt_injection" in str(event.sanitized_metadata.get("category", "")).lower():
            alert = await self._check_window_rule(
                rule_id="RULE_PROMPT_INJECTION_CLUSTER",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 4. Rule: Data exfiltration
        if event.event_type == "threat.detected" and "leak" in str(event.sanitized_metadata.get("category", "")).lower():
            alert = await self._check_window_rule(
                rule_id="RULE_DATA_EXFILTRATION",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 5. Rule: Dangerous terminal command
        if "command" in event.action.lower() and event.decision == "BLOCK":
            alert = await self._check_window_rule(
                rule_id="RULE_DANGEROUS_COMMAND",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 6. Rule: Cross-tenant access attempt
        if "cross_tenant" in event.event_type.lower() or "tenant_mismatch" in str(event.sanitized_metadata).lower():
            alert = await self._check_window_rule(
                rule_id="RULE_CROSS_TENANT",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        # 7. Rule: Emergency lockdown
        if event.source_component.value == "emergency_service" and "activate" in event.action.lower():
            alert = await self._check_window_rule(
                rule_id="RULE_EMERGENCY_LOCKDOWN",
                target_id=target_id,
                event=event,
                now=now,
                session=session,
            )
            if alert:
                alerts_generated.append(alert)

        return alerts_generated

    async def _check_window_rule(
        self,
        rule_id: str,
        target_id: str,
        event: SecurityEvent,
        now: float,
        session: AsyncSession | None,
    ) -> SecurityAlertModel | None:
        rule = self.rules.get(rule_id)
        if not rule:
            return None

        key = f"{rule_id}:{target_id}"

        # Clean up timestamps outside window
        window_start = now - rule.window_seconds
        self._history[key] = [t for t in self._history[key] if t >= window_start]
        self._history[key].append(now)

        # Check threshold
        if len(self._history[key]) >= rule.threshold:
            # Check cooldown to prevent duplicate alert spam
            last_alert = self._cooldowns.get(key, 0.0)
            if now - last_alert < rule.cooldown_seconds:
                return None

            self._cooldowns[key] = now
            # Reset window
            self._history[key].clear()

            alert_model = SecurityAlertModel(
                tenant_id=event.tenant_id,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=rule.severity,
                category=rule.category,
                description=f"{rule.description} (Triggered by agent '{target_id}')",
                affected_agent_id=event.agent_id,
                correlation_id=event.correlation_id,
                evidence_json=json.dumps({
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "action": event.action,
                    "resource": event.resource,
                    "metadata": event.sanitized_metadata,
                }),
                status="OPEN",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            if session is not None:
                session.add(alert_model)
                try:
                    await session.flush()
                except Exception as e:
                    logger.warning("Failed to persist security alert: %s", e)

            # Broadcast real-time alert
            await broadcaster.broadcast_event(
                user_id=event.tenant_id,
                event_type="security.alert.generated",
                data={
                    "alert_id": alert_model.id,
                    "rule_id": alert_model.rule_id,
                    "rule_name": alert_model.rule_name,
                    "severity": alert_model.severity,
                    "description": alert_model.description,
                    "affected_agent_id": alert_model.affected_agent_id,
                    "created_at": alert_model.created_at.isoformat() if alert_model.created_at else None,
                },
            )

            logger.warning(
                "Security Alert Generated [%s] %s on target '%s'",
                rule.severity,
                rule.rule_name,
                target_id,
            )
            return alert_model

        return None


alert_engine = SecurityAlertEngine()
