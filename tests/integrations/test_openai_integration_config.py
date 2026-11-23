"""
Tests for AgentShield OpenAI Integration Configuration and Credential Security (Phase 7).
"""

import pytest

from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.exceptions import redact_secrets


class TestAgentShieldIntegrationConfig:
    def test_default_configuration(self):
        config = AgentShieldIntegrationConfig(
            agent_id="agt-uuid-1",
            agent_credential="agt_secret_token_12345",
        )
        assert config.backend_url == "http://localhost:8000"
        assert config.api_prefix == "/api/v1"
        assert config.agent_id == "agt-uuid-1"
        assert "calculator" in config.allowed_tools
        assert "sandbox_fs" in config.allowed_tools
        assert config.fail_closed is True

    def test_credentials_masked_in_repr_and_str(self):
        secret = "agt_super_confidential_secret_9999"
        api_key = "sk-live-model-provider-key-1234567890"
        config = AgentShieldIntegrationConfig(
            agent_id="agt-uuid-1",
            agent_credential=secret,
            provider_api_key=api_key,
        )

        repr_str = repr(config)
        assert secret not in repr_str
        assert api_key not in repr_str
        assert "***REDACTED***" in repr_str

        str_repr = str(config)
        assert secret not in str_repr
        assert api_key not in str_repr
        assert "***REDACTED***" in str_repr

    def test_empty_allowed_tools_rejected(self):
        with pytest.raises(ValueError, match="allowed_tools cannot be empty"):
            AgentShieldIntegrationConfig(
                agent_id="agt-1",
                agent_credential="cred",
                allowed_tools=[],
            )

    def test_redact_secrets_utility(self):
        raw = "Error sending with sk-12345678901234567890 and agt_agentcredentialtoken12345"
        sanitized = redact_secrets(raw)
        assert "sk-12345678901234567890" not in sanitized
        assert "agt_agentcredentialtoken12345" not in sanitized
        assert "***REDACTED***" in sanitized
