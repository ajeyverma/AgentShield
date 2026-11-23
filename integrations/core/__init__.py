"""
Forwarding alias for integrations.core -> agentshield.integrations.core.
"""

from agentshield.integrations.core import *  # noqa: F401, F403
import sys

# Ensure submodule resolution
sys.modules["integrations.core.exceptions"] = sys.modules.get("agentshield.integrations.core.exceptions")
sys.modules["integrations.core.integration_config"] = sys.modules.get("agentshield.integrations.core.integration_config")
sys.modules["integrations.core.agent_identity"] = sys.modules.get("agentshield.integrations.core.agent_identity")
sys.modules["integrations.core.result_handler"] = sys.modules.get("agentshield.integrations.core.result_handler")
sys.modules["integrations.core.execution_client"] = sys.modules.get("agentshield.integrations.core.execution_client")
sys.modules["integrations.core.base_adapter"] = sys.modules.get("agentshield.integrations.core.base_adapter")
sys.modules["integrations.core.tool_wrapper"] = sys.modules.get("agentshield.integrations.core.tool_wrapper")
sys.modules["integrations.core.integration_registry"] = sys.modules.get("agentshield.integrations.core.integration_registry")
sys.modules["integrations.core.conformance"] = sys.modules.get("agentshield.integrations.core.conformance")
