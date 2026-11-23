"""
AgentShield AI — Security and Cryptography Unit Tests.
"""

from __future__ import annotations

from datetime import timedelta
import pytest

from agentshield.core.exceptions import AuthenticationError
from agentshield.core.security import (
    create_access_token,
    decode_access_token,
    generate_agent_credential,
    hash_password,
    verify_agent_credential,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify_success(self):
        password = "SecurePassword123!"
        hashed = hash_password(password)
        assert hashed.startswith("$argon2")
        assert verify_password(password, hashed) is True

    def test_verify_incorrect_password(self):
        hashed = hash_password("CorrectPassword")
        assert verify_password("WrongPassword", hashed) is False

    def test_empty_password_raises(self):
        with pytest.raises(ValueError):
            hash_password("")


class TestAgentCredential:
    def test_generate_and_verify_credential(self):
        token, token_hash = generate_agent_credential()
        assert token.startswith("ash_")
        assert len(token) > 30
        assert verify_agent_credential(token, token_hash) is True

    def test_verify_invalid_credential(self):
        _, token_hash = generate_agent_credential()
        assert verify_agent_credential("ash_invalid_token", token_hash) is False

    def test_empty_credential_rejected(self):
        assert verify_agent_credential("", "some_hash") is False


class TestJWTTokens:
    def test_create_and_decode_token(self):
        user_id = "user-12345"
        token = create_access_token(
            subject=user_id,
            claims={"username": "alice", "role": "admin"},
        )
        payload = decode_access_token(token)
        assert payload["sub"] == user_id
        assert payload["username"] == "alice"
        assert payload["role"] == "admin"
        assert "exp" in payload

    def test_expired_token_raises_error(self):
        user_id = "user-expired"
        token = create_access_token(
            subject=user_id,
            expires_delta=timedelta(seconds=-10),
        )
        with pytest.raises(AuthenticationError) as exc_info:
            decode_access_token(token)
        assert "expired" in str(exc_info.value).lower()

    def test_tampered_token_raises_error(self):
        token = create_access_token(subject="user-1")
        tampered = token[:-4] + "xxxx"
        with pytest.raises(AuthenticationError):
            decode_access_token(tampered)
