"""
AgentShield AI — Role-Based Access Control & Approver Permissions (Phase 10).
"""

from __future__ import annotations

from enum import Enum
from typing import Set

from agentshield.core.exceptions import AuthorizationError


class UserRole(str, Enum):
    """User authorization roles."""
    OWNER = "OWNER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    """Granular system permissions."""
    # Policies
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    POLICY_DELETE = "policy:delete"
    POLICY_SIMULATE = "policy:simulate"
    POLICY_VIEW = "policy:read"
    POLICY_CREATE = "policy:write"
    POLICY_EDIT = "policy:write"

    # Approvals
    APPROVAL_READ = "approval:read"
    APPROVAL_APPROVE = "approval:approve"
    APPROVAL_REJECT = "approval:reject"
    APPROVAL_CANCEL = "approval:cancel"
    APPROVAL_VIEW = "approval:read"
    APPROVAL_DECIDE = "approval:approve"

    # Emergency Controls
    EMERGENCY_READ = "emergency:read"
    EMERGENCY_EXECUTE = "emergency:execute"
    EMERGENCY_REVOKE = "emergency:revoke"
    EMERGENCY_CONTROL = "emergency:execute"

    # Agents & Integrations
    AGENT_READ = "agent:read"
    AGENT_WRITE = "agent:write"
    AGENT_DELETE = "agent:delete"

    # Audit & Monitoring
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[UserRole, Set[Permission]] = {
    UserRole.OWNER: {
        Permission.POLICY_READ,
        Permission.POLICY_WRITE,
        Permission.POLICY_DELETE,
        Permission.POLICY_SIMULATE,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_APPROVE,
        Permission.APPROVAL_REJECT,
        Permission.APPROVAL_CANCEL,
        Permission.EMERGENCY_READ,
        Permission.EMERGENCY_EXECUTE,
        Permission.EMERGENCY_REVOKE,
        Permission.AGENT_READ,
        Permission.AGENT_WRITE,
        Permission.AGENT_DELETE,
        Permission.AUDIT_READ,
    },
    UserRole.SECURITY_ADMIN: {
        Permission.POLICY_READ,
        Permission.POLICY_WRITE,
        Permission.POLICY_DELETE,
        Permission.POLICY_SIMULATE,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_APPROVE,
        Permission.APPROVAL_REJECT,
        Permission.APPROVAL_CANCEL,
        Permission.EMERGENCY_READ,
        Permission.EMERGENCY_EXECUTE,
        Permission.EMERGENCY_REVOKE,
        Permission.AGENT_READ,
        Permission.AGENT_WRITE,
        Permission.AUDIT_READ,
    },
    UserRole.APPROVER: {
        Permission.POLICY_READ,
        Permission.POLICY_SIMULATE,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_APPROVE,
        Permission.APPROVAL_REJECT,
        Permission.APPROVAL_CANCEL,
        Permission.AGENT_READ,
        Permission.AUDIT_READ,
    },
    UserRole.AUDITOR: {
        Permission.POLICY_READ,
        Permission.APPROVAL_READ,
        Permission.AGENT_READ,
        Permission.AUDIT_READ,
        Permission.EMERGENCY_READ,
    },
    UserRole.VIEWER: {
        Permission.POLICY_READ,
        Permission.APPROVAL_READ,
        Permission.AGENT_READ,
    },
}


def parse_user_role(role_str: str | None) -> UserRole:
    """Parse user role string safely into UserRole enum."""
    if not role_str:
        return UserRole.VIEWER
    try:
        return UserRole(role_str.upper())
    except ValueError:
        return UserRole.VIEWER


def has_permission(role: str | UserRole, permission: Permission) -> bool:
    """Check if a given role has a specific permission."""
    r = parse_user_role(role if isinstance(role, str) else role.value)
    return permission in ROLE_PERMISSIONS.get(r, set())


def can_approve_risk(role: str | UserRole, risk_score: float, risk_level: str) -> bool:
    """
    Enforce separation of duties: High or Critical risk approvals
    (risk_score >= 70 or risk_level in HIGH/CRITICAL) require SECURITY_ADMIN or OWNER.
    Ordinary APPROVER can only approve Low or Medium risk requests.
    """
    r = parse_user_role(role if isinstance(role, str) else role.value)
    if r in (UserRole.OWNER, UserRole.SECURITY_ADMIN):
        return True

    if r == UserRole.APPROVER:
        is_high = risk_score >= 70.0 or str(risk_level).upper() in ("HIGH", "CRITICAL")
        return not is_high

    return False


def can_manage_emergency_controls(role: str | UserRole) -> bool:
    """Only OWNER or SECURITY_ADMIN may activate or revoke emergency controls."""
    r = parse_user_role(role if isinstance(role, str) else role.value)
    return r in (UserRole.OWNER, UserRole.SECURITY_ADMIN)


def assert_not_agent_self_approval(
    reviewer_id: str | None = None,
    requesting_agent_id: str | None = None,
    is_agent_caller: bool = False,
) -> None:
    """Prevent agents from self-approving requests or spoofing approval authority."""
    if is_agent_caller:
        raise AuthorizationError("AI agents are strictly forbidden from approving requests (human authorization required).")
    if reviewer_id and requesting_agent_id and reviewer_id == requesting_agent_id:
        raise AuthorizationError("Self-approval violation: An agent cannot approve its own execution request.")
