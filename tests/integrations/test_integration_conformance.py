"""
Tests for Universal Integration Conformance across all AI agent frameworks (Phase 9).
Verifies the 24 security conformance requirements:
- ALLOW mediation
- BLOCK mediation & zero local execution
- ASK_HUMAN pausing and approval ID retention
- Allowlist enforcement without network leak
- Fail-closed error handling
- Credential isolation & secret redaction
- Multi-agent identity provenance & restricted delegation
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.conformance import IntegrationConformanceVerifier
from agentshield.integrations.core.exceptions import redact_secrets
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.integration_registry import integration_registry
from agentshield.integrations.claude_agent_sdk.adapter import ClaudeIntegrationAdapter
from agentshield.integrations.langgraph.adapter import LangGraphIntegrationAdapter
from agentshield.integrations.crewai.adapter import CrewAIIntegrationAdapter
from agentshield.integrations.google_adk.adapter import GoogleADKIntegrationAdapter


@pytest.fixture
def base_config() -> AgentShieldIntegrationConfig:
    return AgentShieldIntegrationConfig(
        backend_url="http://localhost:8000",
        agent_id=str(uuid.uuid4()),
        agent_credential="agt_test_secret_credential_token_12345",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
        fail_closed=True,
    )


ADAPTER_CLASSES = [
    (IntegrationType.SDK_CLAUDE, ClaudeIntegrationAdapter),
    (IntegrationType.SDK_LANGGRAPH, LangGraphIntegrationAdapter),
    (IntegrationType.SDK_CREWAI, CrewAIIntegrationAdapter),
    (IntegrationType.SDK_GOOGLE_ADK, GoogleADKIntegrationAdapter),
]


@pytest.mark.parametrize("framework_type,adapter_cls", ADAPTER_CLASSES)
def test_conformance_allow_decision(framework_type, adapter_cls, base_config):
    """Test 1: ALLOW decision executes through gateway and returns success across all adapters."""
    adapter = adapter_cls(base_config)
    ok = IntegrationConformanceVerifier.verify_allow_forwards_to_gateway(
        adapter=adapter,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 10, "b": 20},
    )
    assert ok is True


@pytest.mark.parametrize("framework_type,adapter_cls", ADAPTER_CLASSES)
def test_conformance_block_decision(framework_type, adapter_cls, base_config):
    """Test 2: BLOCK decision strictly halts execution and returns safe error output."""
    adapter = adapter_cls(base_config)
    ok = IntegrationConformanceVerifier.verify_block_never_executes(
        adapter=adapter,
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "../../../etc/shadow"},
    )
    assert ok is True


@pytest.mark.parametrize("framework_type,adapter_cls", ADAPTER_CLASSES)
def test_conformance_ask_human_decision(framework_type, adapter_cls, base_config):
    """Test 3: ASK_HUMAN decision pauses execution and captures approval ID without executing."""
    adapter = adapter_cls(base_config)
    ok = IntegrationConformanceVerifier.verify_ask_human_pauses_execution(
        adapter=adapter,
        tool_name="mock_email",
        action_name="send_email",
        arguments={"recipient": "ceo@corp.com", "subject": "Alert", "body": "Confidential"},
    )
    assert ok is True


@pytest.mark.parametrize("framework_type,adapter_cls", ADAPTER_CLASSES)
def test_conformance_tool_allowlist_enforcement(framework_type, adapter_cls, base_config):
    """Test 4: Tools not in configured allowlist are blocked locally without hitting backend."""
    adapter = adapter_cls(base_config)
    ok = IntegrationConformanceVerifier.verify_tool_not_in_allowlist_is_rejected(
        adapter=adapter,
        forbidden_tool="dangerous_shell_tool",
    )
    assert ok is True


@pytest.mark.parametrize("framework_type,adapter_cls", ADAPTER_CLASSES)
def test_conformance_fail_closed_on_backend_down(framework_type, adapter_cls, base_config):
    """Test 5: Adapters must strictly fail-closed when AgentShield backend is unreachable."""
    adapter = adapter_cls(base_config)
    res = adapter.execute_tool("calculator", "add", {"a": 1, "b": 2})
    assert res.is_blocked()
    assert res.error_code == "BACKEND_UNAVAILABLE"


def test_conformance_secret_redaction():
    """Test 6: Credentials and tokens are redacted from error messages and logs."""
    raw_error = "Failed with token agt_test_secret_credential_token_12345 and sk-ant-api03-abcdef123456789"
    redacted = redact_secrets(raw_error)
    assert "agt_test_secret_credential_token_12345" not in redacted
    assert "sk-ant-api03-abcdef123456789" not in redacted
    assert "[REDACTED]" in redacted


def test_conformance_registry_lookup(base_config):
    """Test 7: Integration registry holds all 4 framework adapters."""
    frameworks = integration_registry.list_supported_frameworks()
    assert IntegrationType.SDK_CLAUDE in frameworks
    assert IntegrationType.SDK_LANGGRAPH in frameworks
    assert IntegrationType.SDK_CREWAI in frameworks
    assert IntegrationType.SDK_GOOGLE_ADK in frameworks


def test_conformance_multi_agent_identity_derivation():
    """Test 8: Delegated sub-agent identity strictly bounds permissions to child subset."""
    parent = AgentIdentity(
        agent_id="agent-parent-1",
        agent_name="ParentAgent",
        framework=IntegrationType.SDK_CREWAI,
        tenant_id="tenant-acme",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
    )

    # Derive child with only calculator
    child = parent.derive_delegated_identity(
        delegated_name="ChildAgent",
        tool_scopes=["calculator", "forbidden_tool"],
    )

    assert child.parent_agent_id == "agent-parent-1"
    assert child.originating_agent_id == "agent-parent-1"
    assert child.tenant_id == "tenant-acme"
    # Child only receives intersection: calculator (forbidden_tool is pruned)
    assert child.allowed_tools == ["calculator"]
    assert "sandbox_fs" not in child.allowed_tools
