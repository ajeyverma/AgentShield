"""
AgentShield AI — Filesystem Threat Rules.
"""

from __future__ import annotations

import re

# Restricted directories across operating systems
RESTRICTED_SYSTEM_DIRS = [
    "/etc", "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/var/log", "/proc", "/sys", "/dev",
    "c:\\windows\\system32", "c:\\windows\\system32\\config",
    "/root", "~/.ssh", "~/.aws", "~/.config",
]

# Traversal detection
TRAVERSAL_PATTERN = re.compile(r"(?:\.\.[\\/]|%2e%2e[\\/]|%2e%2e%2f)", re.IGNORECASE)

# Destructive filesystem operations
DESTRUCTIVE_FS_OPERATIONS = {
    "delete", "remove", "unlink", "rmdir", "delete_file", "remove_directory",
    "format", "wipe", "truncate", "destroy", "erase",
}
