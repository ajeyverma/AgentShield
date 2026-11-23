"""
AgentShield AI — Rule Matcher Base Classes (Phase 4).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision


@dataclass(frozen=True)
class RuleMatchResult:
    """Result of evaluating a domain security rule."""

    matched: bool
    outcome: Decision
    reason: str
    rule_id: str
    severity: str = "HIGH"
    requires_approval: bool = False


class BaseRule(ABC):
    """Abstract base class for all domain-specific security rules."""

    rule_id: str
    name: str
    description: str

    @abstractmethod
    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        """Evaluate the request against this rule.

        Returns RuleMatchResult(matched=False, ...) if rule does not trigger.
        """
        raise NotImplementedError
