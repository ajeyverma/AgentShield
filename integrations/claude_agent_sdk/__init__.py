"""
Forwarding alias for integrations.claude_agent_sdk -> agentshield.integrations.claude_agent_sdk.
"""

from agentshield.integrations.claude_agent_sdk import *  # noqa: F401, F403
import sys

sys.modules["integrations.claude_agent_sdk.adapter"] = sys.modules.get("agentshield.integrations.claude_agent_sdk.adapter")
sys.modules["integrations.claude_agent_sdk.tool_wrapper"] = sys.modules.get("agentshield.integrations.claude_agent_sdk.tool_wrapper")
sys.modules["integrations.claude_agent_sdk.agent"] = sys.modules.get("agentshield.integrations.claude_agent_sdk.agent")
