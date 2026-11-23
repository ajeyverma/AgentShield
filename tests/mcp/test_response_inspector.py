"""
Tests for MCP Upstream Response Inspection and Secret Redaction (Phase 8).
"""

import pytest

from agentshield.mcp_gateway.configuration import MCPGatewayConfig
from agentshield.mcp_gateway.exceptions import MCPResponseInspectionError
from agentshield.mcp_gateway.interception.response_inspector import MCPResponseInspector


def test_response_secret_redaction():
    inspector = MCPResponseInspector()

    # Payload with multiple credentials and secrets
    upstream_payload = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "Credentials retrieved: OpenAI key sk-proj-abcdef1234567890abcdef1234567890 and AWS key AKIA1234567890ABCDEF",
                }
            ],
            "api_key": "Bearer mysecrettoken1234567890",
        },
    }

    sanitized, was_redacted, detected = inspector.inspect_and_sanitize(upstream_payload)

    assert was_redacted is True
    assert len(detected) >= 2

    text = sanitized["result"]["content"][0]["text"]
    assert "sk-proj-abcdef1234567890" not in text
    assert "[OPENAI_API_KEY:" in text
    assert "AKIA1234567890ABCDEF" not in text


def test_clean_response_not_modified():
    inspector = MCPResponseInspector()

    upstream_payload = {
        "jsonrpc": "2.0",
        "id": "req-2",
        "result": {
            "status": "ok",
            "temperature": 72.5,
            "conditions": "sunny",
        },
    }

    sanitized, was_redacted, detected = inspector.inspect_and_sanitize(upstream_payload)
    assert was_redacted is False
    assert len(detected) == 0
    assert sanitized["result"]["temperature"] == 72.5


def test_response_size_limit_enforcement():
    config = MCPGatewayConfig(max_response_size_bytes=500)
    inspector = MCPResponseInspector(config=config)

    oversized_payload = {
        "jsonrpc": "2.0",
        "id": "req-3",
        "result": {"large_data": "x" * 1000},
    }

    with pytest.raises(MCPResponseInspectionError) as exc_info:
        inspector.inspect_and_sanitize(oversized_payload)
    assert "exceeds maximum limit" in exc_info.value.message
