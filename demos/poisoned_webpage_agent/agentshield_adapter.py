"""
AgentShield Adapter for Poisoned Webpage Demo Agent.

Reuses existing AgentShield core components:
- Threat Detection: agentshield.threat_detection.engine.threat_coordinator
- Decision Engine: agentshield.security.engine.security_engine
- Contracts & Provenance: agentshield.contracts.action, provenance, decision, enums
- Permissions & Policies: agentshield.security.permissions, database.models.policy
- Fail-Closed: any error or unreachable state immediately defaults to BLOCK.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import Decision, IntegrationType, RiskLevel, ToolCategory
from agentshield.contracts.provenance import ProvenanceContext, SourceType, TrustLevel
from agentshield.contracts.threat import ThreatAnalysisResult, ThreatFinding, ThreatSeverity
from agentshield.database.models.policy import Policy
from agentshield.security.engine import security_engine
from agentshield.security.permissions import AgentPermissions
from agentshield.threat_detection.engine import threat_coordinator

from demos.poisoned_webpage_agent.config import settings
from demos.poisoned_webpage_agent.mock_tools import mock_tool_manager

logger = logging.getLogger("demos.poisoned_webpage.adapter")


@dataclass
class ThreatScanSummary:
    has_injection: bool
    highest_severity: str
    overall_threat_score: float
    findings_count: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    provenance_context: ProvenanceContext | None = None


@dataclass
class AdapterExecutionResult:
    tool_name: str
    action_name: str
    decision: str  # "ALLOW", "BLOCK", "ASK_HUMAN"
    status: str    # "EXECUTED", "BLOCKED", "REQUIRES_APPROVAL", "ERROR"
    executed: bool
    output: Any
    reasons: list[str] = field(default_factory=list)
    threat_findings: list[dict[str, Any]] = field(default_factory=list)
    request_id: str = ""
    error_message: str | None = None


DEMO_TENANT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
DEMO_AGENT_UUID = uuid.UUID("22222222-2222-2222-2222-222222222222")


class AgentShieldAdapter:
    """Production-grade adapter connecting the demo agent to AgentShield's security runtime."""

    def __init__(
        self,
        agent_id: str | None = None,
        tenant_id: str | None = None,
        backend_url: str | None = None,
    ) -> None:
        self.agent_uuid = DEMO_AGENT_UUID
        self.tenant_uuid = DEMO_TENANT_UUID
        self.agent_id = str(self.agent_uuid)
        self.tenant_id = str(self.tenant_uuid)
        self.backend_url = backend_url or settings.backend_url
        self.active_provenance: ProvenanceContext | None = None
        self.cached_webpage_threats: ThreatAnalysisResult | None = None

        # Build baseline permissions for demo agent
        # Least privilege: demo agent has low allowed risk and only permits benign summarization
        self.agent_permissions = AgentPermissions(
            agent_id=self.agent_id,
            owner_user_id=self.tenant_id,
            allowed_categories={"unknown", "file_system"},
            denied_categories={"email"},
            max_permitted_risk_score=40.0,
        )

        # Baseline policies (Strict exfiltration and prompt injection prevention)
        self.policies: list[Policy] = [
            Policy(
                id=str(uuid.uuid4()),
                user_id=self.tenant_id,
                name="Block Exfiltration & Prompt Injection",
                description="Block email sending and file reading when untrusted input is tainted with injection.",
                is_enabled=True,
                rules_json="""[
                    {
                        "rule_id": "rule-no-untrusted-email",
                        "name": "Disallow email on untrusted provenance",
                        "effect": "BLOCK",
                        "conditions": {"tool_category": "email"},
                        "reasons": ["Direct email transmission is blocked for untrusted context."]
                    }
                ]""",
            )
        ]

    def scan_webpage_content(self, content: str, origin_url: str) -> ThreatScanSummary:
        """Scan webpage content using AgentShield's threat detection pipeline.
        
        Marks input as UNTRUSTED provenance and runs PromptInjectionDetector,
        HiddenTextDetector, and Base64DecoderDetector.
        """
        try:
            # 1. Establish untrusted provenance tracking
            provenance = ProvenanceContext.from_untrusted(
                source_type=SourceType.WEBPAGE,
                origin=origin_url,
                content_snippet=content[:500],
            )
            self.active_provenance = provenance

            # 2. Build ActionRequest representing ingestion of untrusted webpage
            req_id = uuid.uuid4()
            action_req = ActionRequest(
                request_id=req_id,
                tenant_id=self.tenant_uuid,
                agent_id=self.agent_uuid,
                user_id=self.tenant_uuid,
                tool_name="webpage_reader",
                tool_category=ToolCategory.UNKNOWN,
                operation="read",
                arguments={"url": origin_url, "content": content},
                resource=origin_url,
                integration_type=IntegrationType.API,
            )

            # 3. Analyze through AgentShield threat coordinator
            threat_result = threat_coordinator.analyze_action(action_req, provenance=provenance)
            self.cached_webpage_threats = threat_result

            findings_list = [
                {
                    "detector_id": f.detector_id,
                    "threat_type": f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type),
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    "description": f.description,
                }
                for f in threat_result.findings
            ]

            has_injection = any(
                f.get("threat_type") == "PROMPT_INJECTION" or f.get("severity") in ("HIGH", "CRITICAL")
                for f in findings_list
            )

            highest_sev = threat_result.highest_severity.value if threat_result.highest_severity else "NONE"

            return ThreatScanSummary(
                has_injection=has_injection,
                highest_severity=highest_sev,
                overall_threat_score=threat_result.overall_threat_score,
                findings_count=len(findings_list),
                findings=findings_list,
                provenance_context=provenance,
            )
        except Exception as exc:
            logger.error("Error in AgentShield threat scan: %s", exc)
            # Fail closed: treat scan failure as an active threat
            return ThreatScanSummary(
                has_injection=True,
                highest_severity="CRITICAL",
                overall_threat_score=100.0,
                findings_count=1,
                findings=[{"title": "Scan Engine Error (Fail Closed)", "severity": "CRITICAL", "description": str(exc)}],
            )

    def evaluate_and_execute(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        provenance: ProvenanceContext | None = None,
    ) -> AdapterExecutionResult:
        """Route tool execution strictly through AgentShield's Controlled Execution Gateway.
        
        Guarantees:
        - NEVER executes tool before authorization.
        - BLOCK decision stops execution deterministically.
        - ASK_HUMAN decision stops execution pending approval (no auto-approval).
        - Direct calls without this gateway are prevented by mock_tool_manager.
        - Fail closed on any exception.
        """
        request_id = str(uuid.uuid4())
        effective_prov = provenance or self.active_provenance

        try:
            # 1. Map tool category
            if tool_name in ("mock_email", "send_mock_email"):
                category = ToolCategory.EMAIL
            elif tool_name in ("sandbox_fs", "read_dummy_file"):
                category = ToolCategory.FILE_SYSTEM
            else:
                category = ToolCategory.UNKNOWN

            # 2. Build ActionRequest
            action_req = ActionRequest(
                request_id=uuid.UUID(request_id),
                tenant_id=self.tenant_uuid,
                agent_id=self.agent_uuid,
                user_id=self.tenant_uuid,
                tool_name=tool_name,
                tool_category=category,
                operation=action_name,
                arguments=arguments,
                resource=str(arguments.get("path") or arguments.get("to") or ""),
                integration_type=IntegrationType.API,
            )

            # 3. Analyze tool call arguments + untrusted provenance
            tool_threat_result = threat_coordinator.analyze_action(action_req, provenance=effective_prov)

            # Combine with cached webpage threat findings if available
            combined_threats = tool_threat_result
            if self.cached_webpage_threats and self.cached_webpage_threats.findings:
                # Merge findings
                combined_findings = list(tool_threat_result.findings) + list(self.cached_webpage_threats.findings)
                combined_threats = ThreatAnalysisResult(
                    request_id=action_req.request_id,
                    agent_id=str(action_req.agent_id),
                    overall_threat_score=max(tool_threat_result.overall_threat_score, self.cached_webpage_threats.overall_threat_score),
                    highest_severity=self.cached_webpage_threats.highest_severity or tool_threat_result.highest_severity,
                    findings=combined_findings,
                )

            # 4. Authoritative Security Evaluation via DecisionEngine
            decision = security_engine.evaluate_action(
                authenticated_user_id=self.tenant_id,
                authenticated_agent_id=self.agent_id,
                agent_status="active",
                request=action_req,
                permissions=self.agent_permissions,
                db_policies=self.policies,
                threat_result=combined_threats,
            )

            decision_type = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)
            reasons = list(decision.reasons)

            threat_findings_summary = [
                {
                    "detector_id": tf.detector_id,
                    "threat_type": tf.threat_type.value if hasattr(tf.threat_type, "value") else str(tf.threat_type),
                    "title": tf.title,
                    "severity": tf.severity.value if hasattr(tf.severity, "value") else str(tf.severity),
                }
                for tf in combined_threats.findings
            ]

            # 5. Outcome Enforcement
            if decision.decision == Decision.BLOCK:
                # BLOCK: Tool is NEVER invoked
                reason_str = reasons[0] if reasons else "Action blocked by AgentShield policy."
                mock_tool_manager.record_shield_blocked_call(tool_name, action_name, arguments, reason_str)
                logger.warning("AgentShield BLOCKED execution of %s.%s: %s", tool_name, action_name, reason_str)
                return AdapterExecutionResult(
                    tool_name=tool_name,
                    action_name=action_name,
                    decision="BLOCK",
                    status="BLOCKED",
                    executed=False,
                    output=None,
                    reasons=reasons,
                    threat_findings=threat_findings_summary,
                    request_id=request_id,
                    error_message=f"SECURITY_BLOCKED: {reason_str}",
                )

            elif decision.decision == Decision.ASK_HUMAN:
                # ASK_HUMAN: Stop execution; do NOT auto-approve
                reason_str = reasons[0] if reasons else "Action requires human approval."
                mock_tool_manager.record_shield_blocked_call(tool_name, action_name, arguments, f"PENDING_APPROVAL: {reason_str}")
                logger.info("AgentShield REQUIRES_APPROVAL for %s.%s", tool_name, action_name)
                return AdapterExecutionResult(
                    tool_name=tool_name,
                    action_name=action_name,
                    decision="ASK_HUMAN",
                    status="REQUIRES_APPROVAL",
                    executed=False,
                    output=None,
                    reasons=reasons,
                    threat_findings=threat_findings_summary,
                    request_id=request_id,
                    error_message="Action halted: Human-in-the-loop approval required before execution.",
                )

            elif decision.decision == Decision.ALLOW:
                # ALLOW: Execute through mock tool with authorization token
                output = self._dispatch_to_mock_tool(tool_name, action_name, arguments)
                return AdapterExecutionResult(
                    tool_name=tool_name,
                    action_name=action_name,
                    decision="ALLOW",
                    status="EXECUTED",
                    executed=True,
                    output=output,
                    reasons=reasons,
                    threat_findings=threat_findings_summary,
                    request_id=request_id,
                )
            else:
                # Unexpected decision: Fail Closed
                return self._build_fail_closed_result(tool_name, action_name, request_id, "Unknown decision type")

        except Exception as exc:
            logger.error("Exception during AgentShield execution evaluation: %s", exc)
            return self._build_fail_closed_result(tool_name, action_name, request_id, str(exc))

    def _dispatch_to_mock_tool(self, tool_name: str, action_name: str, arguments: dict[str, Any]) -> Any:
        """Dispatch authorized execution to the underlying mock tool."""
        if tool_name in ("read_dummy_file", "sandbox_fs"):
            path = str(arguments.get("path", ""))
            return mock_tool_manager.read_dummy_file(path, authorized_by_shield=True)
        elif tool_name in ("send_mock_email", "mock_email"):
            to = str(arguments.get("to", ""))
            subject = str(arguments.get("subject", "Notice"))
            msg = str(arguments.get("message") or arguments.get("body") or "")
            return mock_tool_manager.send_mock_email(to, msg, subject, authorized_by_shield=True)
        else:
            raise ValueError(f"Unknown tool name: {tool_name}")

    def _build_fail_closed_result(self, tool_name: str, action_name: str, request_id: str, error: str) -> AdapterExecutionResult:
        """Fail-Closed default: any failure is immediately treated as BLOCK with zero tool execution."""
        mock_tool_manager.record_shield_blocked_call(tool_name, action_name, {}, f"FAIL_CLOSED: {error}")
        return AdapterExecutionResult(
            tool_name=tool_name,
            action_name=action_name,
            decision="BLOCK",
            status="BLOCKED",
            executed=False,
            output=None,
            reasons=[f"FAIL_CLOSED: {error}"],
            threat_findings=[],
            request_id=request_id,
            error_message=f"AgentShield Fail-Closed Enforcement: {error}",
        )
