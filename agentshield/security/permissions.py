"""
AgentShield AI — Permission Evaluation Engine (Phase 4).

Evaluates whether an authenticated AI agent has explicit permission to execute
a requested tool, operation, and resource category.

Guiding Security Principles:
  1. Default Deny: When no explicit permission grant exists, access is denied.
  2. Explicit Deny Precedence: A deny specification overrides all allow grants.
  3. Principle of Least Privilege: Agents cannot grant themselves additional permissions.
  4. Ownership Boundary: Requests across user or tenant boundaries are rejected.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Sequence

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import ToolCategory


@dataclass
class AgentPermissions:
    """Configured permissions assigned to a registered AI agent."""

    agent_id: str
    owner_user_id: str
    allowed_tools: set[str] = field(default_factory=lambda: {"*"})
    denied_tools: set[str] = field(default_factory=set)
    allowed_operations: set[str] = field(default_factory=lambda: {"*"})
    denied_operations: set[str] = field(default_factory=set)
    allowed_categories: set[str] = field(default_factory=lambda: {"*"})
    denied_categories: set[str] = field(default_factory=set)
    restricted_resources: list[str] = field(default_factory=list)
    max_permitted_risk_score: float = 70.0  # Operations above this require human approval


@dataclass(frozen=True)
class PermissionResult:
    """Outcome of evaluating an ActionRequest against configured permissions."""

    granted: bool
    reason: str
    explicit_deny: bool = False
    max_permitted_risk: float = 70.0


def _match_any(value: str, patterns: Sequence[str]) -> bool:
    """Return True if value matches any pattern in patterns (supports wildcards * and ?)."""
    val_lower = value.lower().strip()
    for pat in patterns:
        pat_lower = pat.lower().strip()
        if pat_lower == "*" or fnmatch.fnmatch(val_lower, pat_lower):
            return True
    return False


class PermissionEvaluator:
    """Independent evaluator for agent and user permission boundaries."""

    @classmethod
    def evaluate(
        cls,
        permissions: AgentPermissions,
        request: ActionRequest,
        authenticated_user_id: str,
        authenticated_agent_id: str,
    ) -> PermissionResult:
        """Evaluate request against agent permissions and ownership boundaries.

        Returns PermissionResult(granted=True, ...) only when all checks pass.
        """
        # 1. Ownership & Identity Boundary Verification
        if str(permissions.owner_user_id) != str(authenticated_user_id):
            return PermissionResult(
                granted=False,
                reason="Ownership boundary violation: authenticated user does not own this agent.",
                explicit_deny=True,
            )

        if str(permissions.agent_id) != str(authenticated_agent_id):
            return PermissionResult(
                granted=False,
                reason="Identity mismatch: permissions profile does not match authenticated agent.",
                explicit_deny=True,
            )

        # 2. Check Tool Explicit Deny
        tool_name = request.tool_name.lower().strip()
        if _match_any(tool_name, list(permissions.denied_tools)):
            return PermissionResult(
                granted=False,
                reason=f"Tool '{request.tool_name}' is explicitly denied by agent policy.",
                explicit_deny=True,
            )

        # 3. Check Category Explicit Deny
        cat_name = request.tool_category.value if isinstance(request.tool_category, ToolCategory) else str(request.tool_category)
        if _match_any(cat_name, list(permissions.denied_categories)):
            return PermissionResult(
                granted=False,
                reason=f"Tool category '{cat_name}' is explicitly denied by agent policy.",
                explicit_deny=True,
            )

        # 4. Check Operation Explicit Deny
        if request.operation:
            op_name = request.operation.lower().strip()
            if _match_any(op_name, list(permissions.denied_operations)):
                return PermissionResult(
                    granted=False,
                    reason=f"Operation '{request.operation}' on tool '{request.tool_name}' is explicitly denied.",
                    explicit_deny=True,
                )

        # 5. Check Restricted Resources
        if request.resource and permissions.restricted_resources:
            res_str = request.resource.lower().strip()
            for restricted in permissions.restricted_resources:
                if _match_any(res_str, [restricted]):
                    return PermissionResult(
                        granted=False,
                        reason=f"Access to restricted resource pattern '{restricted}' is prohibited.",
                        explicit_deny=True,
                    )

        # 6. Check Tool Explicit Allow (Deny by default)
        if not _match_any(tool_name, list(permissions.allowed_tools)):
            return PermissionResult(
                granted=False,
                reason=f"Tool '{request.tool_name}' is not in the allowed tools list (deny by default).",
                explicit_deny=False,
            )

        # 7. Check Category Allow
        if not _match_any(cat_name, list(permissions.allowed_categories)):
            return PermissionResult(
                granted=False,
                reason=f"Tool category '{cat_name}' is not authorized for this agent.",
                explicit_deny=False,
            )

        # 8. Check Operation Allow if specified
        if request.operation and not _match_any(request.operation.lower().strip(), list(permissions.allowed_operations)):
            return PermissionResult(
                granted=False,
                reason=f"Operation '{request.operation}' is not authorized for this agent.",
                explicit_deny=False,
            )

        # All permission checks passed
        return PermissionResult(
            granted=True,
            reason="Action conforms to configured permissions profile.",
            explicit_deny=False,
            max_permitted_risk=permissions.max_permitted_risk_score,
        )
