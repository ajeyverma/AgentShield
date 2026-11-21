"""
Unit tests for AgentShield application configuration.

Verifies that settings are loaded correctly and that validation rules
(log_level, log_format, secret_key in REMOTE mode) work as expected.
"""

from __future__ import annotations

import pytest

from agentshield.contracts.enums import DeploymentMode
from agentshield.core.config import AgentShieldSettings


class TestAgentShieldSettings:
    def test_defaults(self):
        s = AgentShieldSettings()
        assert s.env == DeploymentMode.LOCAL
        assert s.backend_url == "http://localhost:8000"
        assert s.api_prefix == "/api/v1"
        assert s.port == 8000
        assert s.log_level == "INFO"
        assert s.log_format == "console"
        assert s.app_version == "0.1.0"

    def test_effective_database_url_falls_back_to_sqlite(self, monkeypatch):
        monkeypatch.delenv("AGENTSHIELD_DATABASE_URL", raising=False)
        s = AgentShieldSettings()
        url = s.effective_database_url
        assert "sqlite" in url

    def test_effective_database_url_uses_explicit_url(self, monkeypatch):
        pg = "postgresql+asyncpg://user:pass@localhost:5432/agentshield"
        monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", pg)
        s = AgentShieldSettings()
        assert s.effective_database_url == pg

    def test_log_level_normalized_to_uppercase(self):
        s = AgentShieldSettings(log_level="debug")
        assert s.log_level == "DEBUG"

    def test_invalid_log_level_raises(self):
        with pytest.raises(Exception):
            AgentShieldSettings(log_level="VERBOSE")

    def test_invalid_log_format_raises(self):
        with pytest.raises(Exception):
            AgentShieldSettings(log_format="xml")

    def test_valid_json_log_format(self):
        s = AgentShieldSettings(log_format="json")
        assert s.log_format == "json"

    def test_remote_mode_requires_secret_key(self):
        with pytest.raises(Exception, match="AGENTSHIELD_SECRET_KEY"):
            AgentShieldSettings(env=DeploymentMode.REMOTE, secret_key="")

    def test_remote_mode_with_secret_key_passes(self):
        s = AgentShieldSettings(
            env=DeploymentMode.REMOTE,
            secret_key="a" * 64,
        )
        assert s.env == DeploymentMode.REMOTE

    def test_is_development_local(self):
        s = AgentShieldSettings(env=DeploymentMode.LOCAL)
        assert s.is_development is True

    def test_is_development_remote(self):
        s = AgentShieldSettings(env=DeploymentMode.REMOTE, secret_key="x" * 64)
        assert s.is_development is False
