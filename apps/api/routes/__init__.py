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
    executions,
    health,
    integrations,
    mcp,
    policies,
    security,
    threat_detection,
    threats,
    tools,
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
    "executions",
    "tools",
    "mcp",
]
