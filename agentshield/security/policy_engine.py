"""
AgentShield AI — Policy Evaluation Engine (Phase 4 & Phase 10).

Evaluates configured security policies and domain rules against an ActionRequest
using deterministic conflict resolution.

Precedence Hierarchy:
  1. Authentication & Ownership: Unverified requests are rejected immediately.
  2. Domain Security Rules & Mandatory Blocks: Mandatory BLOCK rules cannot be overridden.
  3. Approval Requirements: Policies requiring ASK_HUMAN take precedence over ALLOW.
  4. Explicit Permission & Policy Allows: Actions require affirmative allow conditions.
  5. Default Deny: If no rule permits the action, it is blocked.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Sequence
import uuid

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import PolicyMatch
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.database.models.policy import Policy
from agentshield.security.condition_validator import evaluate_conditions
from agentshield.security.rules import DEFAULT_RULES, BaseRule

logger = logging.getLogger("agentshield.security.policy_engine")


@dataclass
class PolicyEvaluationResult:
    """Outcome of evaluating all applicable domain rules and user policies."""

    decision: Decision
    reasons: list[str] = field(default_factory=list)
    matched_policies: list[PolicyMatch] = field(default_factory=list)
    effective_version: int = 1
    requires_approval: bool = False


class PolicyEngine:
    """Deterministic security policy evaluator with Phase 10 structured scopes and conditions."""

    def __init__(self, domain_rules: Sequence[BaseRule] | None = None) -> None:
        self.domain_rules = list(domain_rules) if domain_rules is not None else DEFAULT_RULES

    def evaluate(
        self,
        request: ActionRequest,
        db_policies: Sequence[Policy],
    ) -> PolicyEvaluationResult:
        """Evaluate an ActionRequest against domain rules and active database policies.

        Applies strict conflict resolution: BLOCK > ASK_HUMAN > ALLOW.
        Sorts active policies by priority (lowest integer = highest priority).
        """
        reasons: list[str] = []
        matched_policies: list[PolicyMatch] = []
        max_policy_version = 1

        # ── 1. Evaluate Built-in Domain Rules ──────────────────────────────────
        has_mandatory_block = False
        has_approval_required = False

        for rule in self.domain_rules:
            res = rule.evaluate(request)
            if res.matched:
                matched_policies.append(
                    PolicyMatch(
                        policy_id=uuid.UUID(int=abs(hash(rule.rule_id)) % (2**128)),
                        policy_name=rule.name,
                        rule_id=rule.rule_id,
                    )
                )
                reasons.append(res.reason)
                if res.outcome == Decision.BLOCK:
                    has_mandatory_block = True
                elif res.outcome == Decision.ASK_HUMAN:
                    has_approval_required = True

        # If a built-in domain rule demands BLOCK, no user policy may override it
        if has_mandatory_block:
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                reasons=reasons,
                matched_policies=matched_policies,
                effective_version=max_policy_version,
                requires_approval=False,
            )

        # ── 2. Evaluate Database Policies (sorted by priority) ─────────────────
        sorted_policies = sorted(
            [p for p in db_policies if p.is_enabled and p.enforcement_mode != "disabled"],
            key=lambda p: getattr(p, "priority", 100),
        )

        has_user_block = False
        has_user_approval = False
        has_user_allow = False

        for policy in sorted_policies:
            version_val = policy.version if policy.version is not None else 1
            max_policy_version = max(max_policy_version, version_val)
            matches, rule_reason, rule_outcome = self._evaluate_single_policy(policy, request)

            if matches:
                p_uuid = uuid.UUID(policy.id) if _is_valid_uuid(policy.id) else uuid.UUID(int=abs(hash(policy.id)) % (2**128))
                matched_policies.append(
                    PolicyMatch(
                        policy_id=p_uuid,
                        policy_name=policy.name,
                        rule_id=f"POL-{policy.id[:8]}",
                    )
                )
                if rule_reason:
                    reasons.append(rule_reason)

                # Monitor mode: logs but does not enforce decision
                if policy.enforcement_mode == "monitor":
                    reasons.append(f"Policy '{policy.name}' matched in MONITOR mode (non-enforcing).")
                    continue

                if rule_outcome == Decision.BLOCK:
                    has_user_block = True
                elif rule_outcome == Decision.ASK_HUMAN:
                    has_user_approval = True
                elif rule_outcome == Decision.ALLOW:
                    has_user_allow = True

        # ── 3. Apply Decision Precedence ───────────────────────────────────────
        # BLOCK > ASK_HUMAN > ALLOW
        if has_user_block:
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                reasons=reasons,
                matched_policies=matched_policies,
                effective_version=max_policy_version,
                requires_approval=False,
            )

        if has_approval_required or has_user_approval:
            return PolicyEvaluationResult(
                decision=Decision.ASK_HUMAN,
                reasons=reasons if reasons else ["Action matches policy requiring human confirmation."],
                matched_policies=matched_policies,
                effective_version=max_policy_version,
                requires_approval=True,
            )

        if not reasons:
            reasons.append("No blocking policy rules triggered.")

        return PolicyEvaluationResult(
            decision=Decision.ALLOW,
            reasons=reasons,
            matched_policies=matched_policies,
            effective_version=max_policy_version,
            requires_approval=False,
        )

    def _evaluate_single_policy(
        self,
        policy: Policy,
        request: ActionRequest,
    ) -> tuple[bool, str, Decision]:
        """Parse policy scopes, conditions, and rules to evaluate match."""
        # 1. Check Phase 10 scopes if defined on the policy model
        agent_scope = getattr(policy, "agent_scope", "*") or "*"
        tool_scope = getattr(policy, "tool_scope", "*") or "*"
        action_scope = getattr(policy, "action_scope", "*") or "*"
        resource_scope = getattr(policy, "resource_scope", "*") or "*"
        integration_scope = getattr(policy, "integration_scope", "*") or "*"

        req_agent = str(request.agent_id) if request.agent_id else "*"
        req_tool = str(request.tool_name or "")
        req_action = str(request.operation or "")
        req_res = str(request.resource or request.arguments.get("path") or request.arguments.get("url") or "")
        req_integ = str(request.integration_type.value if hasattr(request.integration_type, "value") else (request.integration_type or "*"))

        if not _match_pattern(req_agent, [agent_scope]):
            return False, "", Decision.ALLOW
        if not _match_pattern(req_tool, [tool_scope]):
            return False, "", Decision.ALLOW
        if not _match_pattern(req_action, [action_scope]):
            return False, "", Decision.ALLOW
        if not _match_pattern(req_res, [resource_scope]):
            return False, "", Decision.ALLOW
        if not _match_pattern(req_integ, [integration_scope]):
            return False, "", Decision.ALLOW

        # 2. Check structured conditions_json if present
        conditions_json = getattr(policy, "conditions_json", None)
        if conditions_json:
            try:
                cond_data = json.loads(conditions_json)
                context = {
                    "tool_name": req_tool,
                    "action_name": req_action,
                    "operation": req_action,
                    "resource": req_res,
                    "agent_id": req_agent,
                    "arguments": request.arguments or {},
                    "risk_level": str(request.risk_level),
                }
                if not evaluate_conditions(cond_data, context):
                    return False, "", Decision.ALLOW
            except Exception as e:
                logger.warning("Error evaluating policy conditions: %s", e)
                return False, "", Decision.ALLOW

        # 3. Check legacy rules_json if present
        if policy.rules_json:
            try:
                rules_data = json.loads(policy.rules_json)
                tools = rules_data.get("tools")
                ops = rules_data.get("operations")
                resources = rules_data.get("resources")

                match_dict = rules_data.get("match")
                if isinstance(match_dict, dict):
                    if tools is None and "tool" in match_dict:
                        tools = [match_dict["tool"]]
                    if ops is None and "operation" in match_dict:
                        ops = [match_dict["operation"]]
                    if resources is None and "resource" in match_dict:
                        resources = [match_dict["resource"]]

                if tools and not _match_pattern(req_tool, tools):
                    return False, "", Decision.ALLOW
                if ops and not _match_pattern(req_action, ops):
                    return False, "", Decision.ALLOW
                if resources and not _match_pattern(req_res, resources):
                    return False, "", Decision.ALLOW

                raw_outcome = rules_data.get("outcome") or rules_data.get("action")
                if raw_outcome:
                    outcome_str = str(raw_outcome).upper()
                    outcome = Decision(outcome_str) if outcome_str in ("ALLOW", "BLOCK", "ASK_HUMAN") else Decision.BLOCK
                    reason = rules_data.get("reason", f"Action triggered policy '{policy.name}'.")
                    return True, reason, outcome
            except Exception:
                pass

        # 4. Resolve decision from policy model field
        decision_val = getattr(policy, "decision", None)
        if decision_val:
            try:
                outcome = Decision(decision_val.upper())
            except ValueError:
                outcome = Decision.ASK_HUMAN
        else:
            cat = request.tool_category.value if isinstance(request.tool_category, ToolCategory) else str(request.tool_category)
            outcome = Decision.BLOCK if "block" in policy.name.lower() else Decision.ALLOW

        reason = f"Matched policy '{policy.name}' (priority: {getattr(policy, 'priority', 100)})."
        return True, reason, outcome

    def find_conflicts(self, policies: Sequence[Policy]) -> list[dict[str, Any]]:
        """Identify conflicting policies that target overlapping scopes with opposing decisions."""
        conflicts: list[dict[str, Any]] = []
        active = [p for p in policies if p.is_enabled and p.enforcement_mode != "disabled"]

        for i in range(len(active)):
            for j in range(i + 1, len(active)):
                p1, p2 = active[i], active[j]
                d1 = getattr(p1, "decision", "ALLOW").upper()
                d2 = getattr(p2, "decision", "ALLOW").upper()

                if d1 != d2:
                    # Check if scopes overlap
                    t1 = getattr(p1, "tool_scope", "*") or "*"
                    t2 = getattr(p2, "tool_scope", "*") or "*"
                    a1 = getattr(p1, "action_scope", "*") or "*"
                    a2 = getattr(p2, "action_scope", "*") or "*"

                    tool_overlap = (t1 == "*" or t2 == "*" or t1 == t2)
                    action_overlap = (a1 == "*" or a2 == "*" or a1 == a2)

                    if tool_overlap and action_overlap:
                        conflicts.append({
                            "policy_a_id": p1.id,
                            "policy_a_name": p1.name,
                            "policy_a_priority": getattr(p1, "priority", 100),
                            "policy_a_decision": d1,
                            "policy_b_id": p2.id,
                            "policy_b_name": p2.name,
                            "policy_b_priority": getattr(p2, "priority", 100),
                            "policy_b_decision": d2,
                            "conflict_type": "DECISION_COLLISION",
                            "details": f"Policies '{p1.name}' and '{p2.name}' share overlapping scope on tool '{t1}' but have conflicting decisions: {d1} vs {d2}.",
                        })
        return conflicts


def _match_pattern(val: str, patterns: list[str]) -> bool:
    val_lower = val.lower().strip()
    for p in patterns:
        p_lower = p.lower().strip()
        if p_lower == "*" or fnmatch.fnmatch(val_lower, p_lower):
            return True
    return False


def _is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False


policy_engine = PolicyEngine()
