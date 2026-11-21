"""
AgentShield AI — Desktop Application Configuration.

This module isolates all desktop-specific configuration from the shared
agentshield.core.config module, following the principle that the desktop
application is only the management interface and must not carry any
security enforcement logic.

The desktop application communicates with the backend through the
configured AGENTSHIELD_BACKEND_URL.  The URL can be changed in the .env
file without modifying any code.
"""

from __future__ import annotations

from agentshield.core.config import settings

# Re-export shared settings for desktop use.
# Desktop widgets import from here so that the coupling to the shared
# settings module is explicit and can be intercepted (e.g. for testing).
__all__ = ["settings", "BACKEND_URL", "API_PREFIX", "APP_NAME", "APP_VERSION"]

BACKEND_URL: str = settings.backend_url
API_PREFIX: str = settings.api_prefix
APP_NAME: str = settings.app_name
APP_VERSION: str = settings.app_version
