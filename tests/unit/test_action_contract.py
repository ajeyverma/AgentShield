"""
Unit tests for the ActionRequest contract.

Covers:
  - Valid construction with all required fields.
  - Optional field defaults.
  - Field validators (tool_name, arguments size).
  - Trust-boundary documentation (identity fields).
  - Invalid inputs that must raise ValidationError.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from agentshield.contracts.action import ActionRequest, SourceContext
from agentshield.contracts.enums import IntegrationType, ToolCategory


TENANT_ID = uuid.uuid4()
AGENT_ID = uuid.uuid4()


def _minimal_request(**overrides) -> dict:
    """Return the minimum valid fields for an ActionRequest."""
    base = {
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "integration_type": IntegrationType.SDK_OPENAI,
        "tool_name": "read_file",
    }
    base.update(overrides)
    return base


class TestActionRequestConstruction:
    def test_minimal_valid_request(self):
        req = ActionRequest(**_minimal_request())
        assert req.tool_name == "read_file"
        assert req.tool_category == ToolCategory.UNKNOWN
        assert req.operation is None
        assert req.arguments == {}
        assert req.source is None
        assert req.user_id is None
        assert req.session_id is None
        assert req.request_id is not None  # auto-generated
        assert req.timestamp is not None

    def test_full_request(self):
        req = ActionRequest(
            tenant_id=TENANT_ID,
            agent_id=AGENT_ID,
            user_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            integration_type=IntegrationType.MCP,
            tool_name="delete_file",
            tool_category=ToolCategory.FILE_SYSTEM,
            operation="delete",
            arguments={"path": "/tmp/test.txt"},
            source=SourceContext(
                agent_framework="openai-agents",
                agent_version="1.0.0",
                task_description="Clean up temporary files",
            ),
        )
        assert req.tool_name == "delete_file"
        assert req.tool_category == ToolCategory.FILE_SYSTEM
        assert req.operation == "delete"
        assert req.arguments["path"] == "/tmp/test.txt"
        assert req.source is not None
        assert req.source.agent_framework == "openai-agents"

    def test_request_id_is_uuid(self):
        req = ActionRequest(**_minimal_request())
        assert isinstance(req.request_id, uuid.UUID)

    def test_each_request_gets_unique_id(self):
        req1 = ActionRequest(**_minimal_request())
        req2 = ActionRequest(**_minimal_request())
        assert req1.request_id != req2.request_id


class TestActionRequestValidators:
    def test_blank_tool_name_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            ActionRequest(**_minimal_request(tool_name="   "))
        errors = exc_info.value.errors()
        assert any("tool_name" in str(e) for e in errors)

    def test_empty_tool_name_raises(self):
        with pytest.raises(ValidationError):
            ActionRequest(**_minimal_request(tool_name=""))

    def test_tool_name_is_stripped(self):
        req = ActionRequest(**_minimal_request(tool_name="  read_file  "))
        assert req.tool_name == "read_file"

    def test_oversized_arguments_raise(self):
        # Create a payload that exceeds 65 536 bytes
        huge_args = {"data": "x" * 70_000}
        with pytest.raises(ValidationError) as exc_info:
            ActionRequest(**_minimal_request(arguments=huge_args))
        assert "arguments payload exceeds" in str(exc_info.value)

    def test_valid_large_but_within_limit_arguments(self):
        ok_args = {"data": "x" * 10_000}
        req = ActionRequest(**_minimal_request(arguments=ok_args))
        assert len(req.arguments["data"]) == 10_000

    def test_missing_tenant_id_raises(self):
        data = _minimal_request()
        data.pop("tenant_id")
        with pytest.raises(ValidationError):
            ActionRequest(**data)

    def test_missing_agent_id_raises(self):
        data = _minimal_request()
        data.pop("agent_id")
        with pytest.raises(ValidationError):
            ActionRequest(**data)

    def test_invalid_integration_type_raises(self):
        with pytest.raises(ValidationError):
            ActionRequest(**_minimal_request(integration_type="INVALID_SDK"))

    def test_tool_name_max_length(self):
        with pytest.raises(ValidationError):
            ActionRequest(**_minimal_request(tool_name="a" * 129))

    def test_operation_max_length(self):
        with pytest.raises(ValidationError):
            ActionRequest(**_minimal_request(operation="x" * 129))


class TestActionRequestSerialization:
    def test_model_dump_contains_required_fields(self):
        req = ActionRequest(**_minimal_request())
        data = req.model_dump()
        assert "request_id" in data
        assert "tenant_id" in data
        assert "agent_id" in data
        assert "tool_name" in data
        assert "timestamp" in data

    def test_model_json_round_trip(self):
        req = ActionRequest(**_minimal_request(arguments={"key": "value"}))
        json_str = req.model_dump_json()
        restored = ActionRequest.model_validate_json(json_str)
        assert restored.tool_name == req.tool_name
        assert restored.arguments == req.arguments
        assert restored.request_id == req.request_id
