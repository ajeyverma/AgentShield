"""
AgentShield AI — Domain Exception Hierarchy.

Defines a typed exception hierarchy used across the security core,
backend API, and integration layer.  Catching by base class (AgentShieldError)
allows uniform error handling at the API and UI layers.
"""

from __future__ import annotations


class AgentShieldError(Exception):
    """Base class for all AgentShield-specific exceptions."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


class ConfigurationError(AgentShieldError):
    """Raised when required configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Contract / validation errors
# ---------------------------------------------------------------------------


class ContractValidationError(AgentShieldError):
    """Raised when an action request fails schema or semantic validation."""


# ---------------------------------------------------------------------------
# Security / policy errors
# ---------------------------------------------------------------------------


class SecurityEvaluationError(AgentShieldError):
    """Raised when the security core cannot evaluate a request."""


class PolicyNotFoundError(AgentShieldError):
    """Raised when a referenced policy does not exist."""


# ---------------------------------------------------------------------------
# Identity / authentication errors
# ---------------------------------------------------------------------------


class AuthenticationError(AgentShieldError):
    """Raised when authentication fails (invalid or missing credentials)."""


class AuthorizationError(AgentShieldError):
    """Raised when an authenticated identity lacks required permissions."""


class TenantNotFoundError(AgentShieldError):
    """Raised when a tenant cannot be resolved from credentials."""


class AgentNotRegisteredError(AgentShieldError):
    """Raised when an agent_id is not registered with the backend."""


# ---------------------------------------------------------------------------
# Approval workflow errors
# ---------------------------------------------------------------------------


class ApprovalNotFoundError(AgentShieldError):
    """Raised when an approval_id cannot be found."""


class ApprovalExpiredError(AgentShieldError):
    """Raised when an approval request has timed out without a decision."""


# ---------------------------------------------------------------------------
# Integration / adapter errors
# ---------------------------------------------------------------------------


class IntegrationError(AgentShieldError):
    """Raised by an integration adapter when it cannot process a request."""


class BackendUnavailableError(AgentShieldError):
    """Raised when the desktop or integration layer cannot reach the backend.

    Design note: on BLOCK-by-default (fail-closed) behavior, integrations
    should treat this exception as an implicit BLOCK rather than allowing
    the tool call to proceed.
    """


# ---------------------------------------------------------------------------
# Execution errors
# ---------------------------------------------------------------------------


class ExecutionError(AgentShieldError):
    """Raised when an authorized tool call fails during execution."""


class ExecutionForgeryError(AgentShieldError):
    """Raised when an execution request lacks a valid, backend-issued authorization token.

    This protects against clients that attempt to forge an ALLOW decision
    to bypass security evaluation and invoke the execution gateway directly.
    """
