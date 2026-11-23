"""
AgentShield AI — Permission Engine Unit Tests (Phase 4).
"""

from __future__ import annotations

import uuid
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.security.permissions import AgentPermissions, PermissionEvaluator


USER_ID = str(uuid.uuid4())
AGENT_ID = str(uuid.uuid4())


def _make_req(tool_name="read_file", operation="read", category=ToolCategory.FILE_SYSTEM, resource=None):
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.UUID(AGENT_ID),
        user_id=uuid.UUID(USER_ID),
        integration_type=IntegrationType.SDK_CUSTOM,
        tool_name=tool_name,
        tool_category=category,
        operation=operation,
        resource=resource,
    )


class TestPermissionEngine:
    def test_explicitly_permitted_tool(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id=USER_ID,
            allowed_tools={"read_file", "search"},
        )
        req = _make_req(tool_name="read_file")
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is True

    def test_denied_tool_precedence(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id=USER_ID,
            allowed_tools={"*"},
            denied_tools={"bash", "terminal*"},
        )
        req = _make_req(tool_name="bash", category=ToolCategory.TERMINAL)
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is False
        assert res.explicit_deny is True
        assert "explicitly denied" in res.reason

    def test_denied_operation_precedence(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id=USER_ID,
            allowed_tools={"*"},
            denied_operations={"delete", "drop"},
        )
        req = _make_req(tool_name="file_manager", operation="delete")
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is False
        assert res.explicit_deny is True

    def test_deny_by_default_unknown_tool(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id=USER_ID,
            allowed_tools={"read_file"},  # only read_file allowed
        )
        req = _make_req(tool_name="execute_code")
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is False
        assert "deny by default" in res.reason

    def test_restricted_resource_pattern(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id=USER_ID,
            allowed_tools={"*"},
            restricted_resources=["/etc/*", "*.pem"],
        )
        req = _make_req(tool_name="read_file", resource="/etc/nginx.conf")
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is False
        assert "restricted resource" in res.reason

    def test_ownership_boundary_violation(self):
        perms = AgentPermissions(
            agent_id=AGENT_ID,
            owner_user_id="other-user-999",
        )
        req = _make_req()
        res = PermissionEvaluator.evaluate(perms, req, USER_ID, AGENT_ID)
        assert res.granted is False
        assert "Ownership boundary violation" in res.reason
