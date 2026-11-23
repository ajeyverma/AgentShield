"""
AgentShield AI — Security, Cryptography, and Token Management.

Implements Argon2 password hashing, cryptographically random agent credential
generation and hashing, and JWT token issuing and verification.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt

from agentshield.core.config import settings
from agentshield.core.exceptions import AuthenticationError

logger = logging.getLogger("agentshield.security")

# Initialize Argon2 hasher with secure defaults
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

ALGORITHM = "HS256"
DEV_FALLBACK_SECRET = "agentshield_dev_secret_key_insecure_local_only_1234567890"


def _get_secret_key() -> str:
    """Retrieve configured secret key with dev fallback in local mode."""
    if settings.secret_key:
        return settings.secret_key
    if settings.is_development:
        return DEV_FALLBACK_SECRET
    raise RuntimeError("AGENTSHIELD_SECRET_KEY must be set in non-development environments.")


# ---------------------------------------------------------------------------
# Password hashing (Argon2)
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2 hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except Exception as exc:
        logger.warning("Unexpected password verification error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Agent credential management
# ---------------------------------------------------------------------------


def generate_agent_credential() -> tuple[str, str]:
    """Generate a high-entropy agent credential and its secure hash.

    Returns:
        (raw_credential, credential_hash)
        The raw_credential MUST only be shown to the user once.
    """
    token = f"ash_{secrets.token_urlsafe(32)}"
    token_hash = _hasher.hash(token)
    return token, token_hash


def verify_agent_credential(raw_credential: str, credential_hash: str) -> bool:
    """Verify an agent token against its stored hash."""
    if not raw_credential or not credential_hash:
        return False
    try:
        return _hasher.verify(credential_hash, raw_credential)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT Access Tokens
# ---------------------------------------------------------------------------


def create_access_token(
    subject: str,
    claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        subject: The user_id (sub claim).
        claims: Optional additional claims (e.g. username, role).
        expires_delta: Optional custom lifetime (defaults to settings).
    """
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if claims:
        to_encode.update(claims)

    encoded_jwt = jwt.encode(to_encode, _get_secret_key(), algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a signed JWT access token.

    Returns:
        Claims dict including 'sub' if valid.

    Raises:
        AuthenticationError: If token is expired, tampered, or invalid.
    """
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        user_id: str | None = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Token missing required subject claim.")
        return payload
    except JWTError as exc:
        raise AuthenticationError(f"Invalid or expired access token: {exc}") from exc
