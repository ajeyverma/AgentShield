"""
AgentShield AI — MCP Firewall Gateway (Phase 8).
"""

from agentshield.mcp_gateway.client import MCPUpstreamClient
from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import (
    MCPApprovalRequiredError,
    MCPBlockedError,
    MCPGatewayError,
    MCPProtocolError,
    MCPSecurityError,
    MCPServerConnectionError,
    MCPSSRFError,
    MCPTransportError,
    MCPUntrustedCommandError,
)
from agentshield.mcp_gateway.interception.response_inspector import MCPResponseInspector
from agentshield.mcp_gateway.proxy import MCPFirewallGateway, mcp_gateway
from agentshield.mcp_gateway.registry.server_registry import MCPServerRegistry
from agentshield.mcp_gateway.registry.tool_registry import DiscoveredTool, MCPToolRegistry
from agentshield.mcp_gateway.security.authorization import MCPAuthorizationService
from agentshield.mcp_gateway.security.policy_adapter import MCPPolicyAdapter
from agentshield.mcp_gateway.transports.stdio import StdioTransportManager
from agentshield.mcp_gateway.transports.streamable_http import StreamableHTTPTransportManager

__all__ = [
    "MCPGatewayConfig",
    "default_mcp_gateway_config",
    "MCPGatewayError",
    "MCPProtocolError",
    "MCPSecurityError",
    "MCPBlockedError",
    "MCPApprovalRequiredError",
    "MCPServerConnectionError",
    "MCPTransportError",
    "MCPSSRFError",
    "MCPUntrustedCommandError",
    "MCPServerRegistry",
    "MCPToolRegistry",
    "DiscoveredTool",
    "StdioTransportManager",
    "StreamableHTTPTransportManager",
    "MCPResponseInspector",
    "MCPPolicyAdapter",
    "MCPAuthorizationService",
    "MCPUpstreamClient",
    "MCPFirewallGateway",
    "mcp_gateway",
]
