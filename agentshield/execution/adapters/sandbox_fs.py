"""
AgentShield AI — Sandboxed Filesystem Adapter (Phase 6).

Enforces strict filesystem isolation within a configured sandbox root directory.
Guarantees path containment, rejects traversal, symlink escapes, and system directory access.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agentshield.execution.adapters.base import BaseToolAdapter
from agentshield.execution.exceptions import ActionNotFoundError, InvalidArgumentsError

ALLOWED_EXTENSIONS = {".txt", ".json", ".csv", ".md", ".log"}
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB max file size


class SandboxedFilesystemAdapter(BaseToolAdapter):
    """Controlled filesystem adapter restricted strictly to a local sandbox root."""

    tool_name = "sandbox_fs"
    tool_version = "1.0.0"

    def __init__(self, sandbox_root: Path | str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if sandbox_root is None:
            # Default to a designated sandbox workspace in project root
            sandbox_root = Path(os.getcwd()) / ".sandbox_workspace"
        self.sandbox_root = Path(sandbox_root).resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, relative_path: str) -> Path:
        """Resolve path and verify that it strictly resides within sandbox_root without traversal."""
        clean_rel = relative_path.strip().lstrip("/\\")
        if not clean_rel:
            return self.sandbox_root

        # Resolve path
        target = (self.sandbox_root / clean_rel).resolve()

        # Strict containment check (no symlink escape, no path traversal)
        try:
            target.relative_to(self.sandbox_root)
        except ValueError as exc:
            raise InvalidArgumentsError(f"Path traversal escape detected: '{relative_path}' is outside the sandbox.") from exc

        # Check extension for files
        if target.suffix and target.suffix.lower() not in ALLOWED_EXTENSIONS:
            raise InvalidArgumentsError(
                f"File extension '{target.suffix}' is not permitted in sandbox. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
            )

        return target

    def run_action(self, action_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> Any:
        path_arg = str(arguments.get("path", "")).strip()
        safe_path = self._resolve_safe_path(path_arg)

        if action_name == "list_files":
            if not safe_path.exists():
                return {"files": [], "directory": str(path_arg)}
            files = []
            for item in safe_path.iterdir():
                files.append({
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size_bytes": item.stat().st_size if item.is_file() else 0,
                })
            return {"files": files, "count": len(files)}

        elif action_name == "read_file":
            if not safe_path.is_file():
                raise InvalidArgumentsError(f"Target file does not exist: '{path_arg}'.")
            if safe_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                raise InvalidArgumentsError(f"File size exceeds sandbox limit of {MAX_FILE_SIZE_BYTES} bytes.")
            content = safe_path.read_text(encoding="utf-8", errors="replace")
            return {"path": path_arg, "content": content, "size_bytes": len(content)}

        elif action_name == "create_file":
            content = str(arguments.get("content", ""))
            if len(content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
                raise InvalidArgumentsError(f"Content exceeds sandbox write limit of {MAX_FILE_SIZE_BYTES} bytes.")
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            safe_path.write_text(content, encoding="utf-8")
            return {"path": path_arg, "status": "created", "bytes_written": len(content)}

        elif action_name == "modify_file":
            content = str(arguments.get("content", ""))
            append = bool(arguments.get("append", False))
            if not safe_path.is_file():
                raise InvalidArgumentsError(f"Target file does not exist: '{path_arg}'.")
            mode = "a" if append else "w"
            with open(safe_path, mode, encoding="utf-8") as f:
                f.write(content)
            return {"path": path_arg, "status": "modified", "mode": mode}

        else:
            raise ActionNotFoundError(self.tool_name, action_name)
