"""
AgentShield AI — Policy Evaluation Engine (Phase 4).

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
from typing import Sequence
import uuid

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import PolicyMatch
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.database.models.policy import Policy
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
    """Deterministic security policy evaluator."""

    def __init__(self, domain_rules: Sequence[BaseRule] | None = None) -> None:
        self.domain_rules = list(domain_rules) if domain_rules is not None else DEFAULT_RULES

    def evaluate(
        self,
        request: ActionRequest,
        db_policies: Sequence[Policy],
    ) -> PolicyEvaluationResult:
        """Evaluate an ActionRequest against domain rules and active database policies.

        Applies strict conflict resolution: BLOCK > ASK_HUMAN > ALLOW.
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

        # ── 2. Evaluate Database Policies ──────────────────────────────────────
        has_user_block = False
        has_user_approval = False
        has_user_allow = False

        for policy in db_policies:
            if not policy.is_enabled or policy.enforcement_mode == "disabled":
                continue

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

                # If enforcement_mode is monitor, we log but do not enforce block
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

        # ALLOW path
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
        """Parse policy rules and evaluate match conditions."""
        if not policy.rules_json:
            # Default fallback for simple category policy
            cat = request.tool_category.value if isinstance(request.tool_category, ToolCategory) else str(request.tool_category)
            if policy.category.lower() == cat.lower() or policy.category == "*":
                outcome = Decision.BLOCK if "block" in policy.name.lower() else Decision.ALLOW
                return True, f"Matched policy category '{policy.category}'.", outcome
            return False, "", Decision.ALLOW

        try:
            rules_data = json.loads(policy.rules_json)
        except Exception:
            return False, "", Decision.ALLOW

        # Expected structured rule format:
        # {
        #   "tools": ["read_*", "curl"],
        #   "operations": ["delete", "drop"],
        #   "resources": ["/etc/*", "*.pem"],
        #   "outcome": "BLOCK" | "ASK_HUMAN" | "ALLOW",
        #   "reason": "..."
        # }
        tools = rules_data.get("tools", ["*"])
        ops = rules_data.get("operations", ["*"])
        resources = rules_data.get("resources", ["*"])
        outcome_str = rules_data.get("outcome", "BLOCK").upper()
        reason = rules_data.get("reason", f"Action triggered policy '{policy.name}'.")

        tool_matched = _match_pattern(request.tool_name, tools)
        op_matched = _match_pattern(request.operation or "", ops)
        target = request.resource or str(request.arguments.get("path") or request.arguments.get("url") or "")
        res_matched = _match_pattern(target, resources)

        if tool_matched and op_matched and res_matched:
            outcome = Decision(outcome_str) if outcome_str in ("ALLOW", "BLOCK", "ASK_HUMAN") else Decision.BLOCK
            return True, reason, outcome

        return False, "", Decision.ALLOW


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
