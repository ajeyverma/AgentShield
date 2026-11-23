"""
AgentShield AI — MCP Gateway top-level alias package (Phase 8).
Forwards to `agentshield.mcp_gateway`.
"""

import sys
from agentshield.mcp_gateway import *  # noqa: F401, F403
import agentshield.mcp_gateway as _pkg

# Ensure submodules can be resolved via mcp_gateway.<submodule>
sys.modules["mcp_gateway.configuration"] = sys.modules.get("agentshield.mcp_gateway.configuration")
sys.modules["mcp_gateway.exceptions"] = sys.modules.get("agentshield.mcp_gateway.exceptions")
sys.modules["mcp_gateway.protocol"] = sys.modules.get("agentshield.mcp_gateway.protocol")
sys.modules["mcp_gateway.registry"] = sys.modules.get("agentshield.mcp_gateway.registry")
sys.modules["mcp_gateway.transports"] = sys.modules.get("agentshield.mcp_gateway.transports")
sys.modules["mcp_gateway.interception"] = sys.modules.get("agentshield.mcp_gateway.interception")
sys.modules["mcp_gateway.security"] = sys.modules.get("agentshield.mcp_gateway.security")
sys.modules["mcp_gateway.client"] = sys.modules.get("agentshield.mcp_gateway.client")
sys.modules["mcp_gateway.proxy"] = sys.modules.get("agentshield.mcp_gateway.proxy")
