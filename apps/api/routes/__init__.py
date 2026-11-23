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
    security,
    threat_detection,
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
    "threat_detection",
    "approvals",
    "policies",
    "security",
    "audit_logs",
    "integrations",
    "websocket",
]
