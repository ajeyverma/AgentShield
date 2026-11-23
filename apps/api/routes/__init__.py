"""
AgentShield AI — API Routes Package Export.
"""

from apps.api.routes import (
    activity,
    agents,
    approvals,
    audit_logs,
    auth,
    dashboard,
    health,
    integrations,
    policies,
    threats,
    users,
    websocket,
)

__all__ = [
    "health",
    "auth",
    "users",
    "agents",
    "dashboard",
    "activity",
    "threats",
    "approvals",
    "policies",
    "audit_logs",
    "integrations",
    "websocket",
]
