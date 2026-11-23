"""
AgentShield AI — Action Request Validation Unit Tests (Phase 4).
"""

from __future__ import annotations

import uuid
import pytest
from pydantic import ValidationError

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory


TENANT_ID = uuid.uuid4()
AGENT_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


def _valid_req(**kwargs) -> ActionRequest:
    base = {
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "user_id": USER_ID,
        "integration_type": IntegrationType.SDK_OPENAI,
        "tool_name": "read_file",
        "tool_category": ToolCategory.FILE_SYSTEM,
        "operation": "read",
        "arguments": {"path": "/home/user/notes.txt"},
        "resource": "/home/user/notes.txt",
    }
    base.update(kwargs)
    return ActionRequest(**base)


class TestActionRequestValidation:
    def test_valid_action_request(self):
        req = _valid_req()
        assert req.tool_name == "read_file"
        assert req.resource == "/home/user/notes.txt"
        assert req.requested_permissions == []

    def test_blank_tool_name_rejected(self):
        with pytest.raises(ValidationError):
            _valid_req(tool_name="   ")

    def test_oversized_arguments_rejected(self):
        huge_args = {"data": "x" * 70_000}
        with pytest.raises(ValidationError) as exc_info:
            _valid_req(arguments=huge_args)
        assert "exceeds maximum allowed size" in str(exc_info.value)

    def test_invalid_integration_type_rejected(self):
        with pytest.raises(ValidationError):
            _valid_req(integration_type="INVALID_INTEGRATION")

    def test_requested_permissions_accepted(self):
        req = _valid_req(requested_permissions=["read", "filesystem:read"])
        assert req.requested_permissions == ["read", "filesystem:read"]
