"""
AgentShield AI — Base Tool Adapter Interface (Phase 6).
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from agentshield.execution.exceptions import (
    ActionNotFoundError,
    ExecutionTimeoutError,
    InvalidArgumentsError,
    OutputSizeExceededError,
)

logger = logging.getLogger("agentshield.execution.adapter")


@dataclass
class ToolExecutionResult:
    """Standardized output produced by a controlled tool adapter."""

    status: str  # "SUCCESS" or "FAILED"
    result: Any | None = None
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: float = 0.0


class BaseToolAdapter(ABC):
    """Abstract base class for all controlled tool execution adapters."""

    tool_name: str
    tool_version: str = "1.0.0"
    timeout_seconds: float = 5.0
    max_output_bytes: int = 65_536  # 64 KB default limit

    def __init__(self, timeout_seconds: float | None = None, max_output_bytes: int | None = None) -> None:
        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        if max_output_bytes is not None:
            self.max_output_bytes = max_output_bytes

    @abstractmethod
    def run_action(self, action_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> Any:
        """Execute the specific tool action and return raw output."""
        raise NotImplementedError

    def execute(
        self,
        action_name: str,
        arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:
        """Execute the tool action wrapped in timeout and size constraints."""
        start_time = time.perf_counter()
        try:
            raw_output = self.run_action(action_name, arguments, context)
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            # Check output size
            try:
                serialized = json.dumps(raw_output, default=str)
                out_size = len(serialized.encode("utf-8"))
                if out_size > self.max_output_bytes:
                    raise OutputSizeExceededError(out_size, self.max_output_bytes)
            except OutputSizeExceededError:
                raise
            except Exception:
                pass

            return ToolExecutionResult(
                status="SUCCESS",
                result=raw_output,
                duration_ms=duration_ms,
            )
        except ActionNotFoundError as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ToolExecutionResult(
                status="FAILED",
                error_code=exc.error_code,
                error_message=exc.message,
                duration_ms=duration_ms,
            )
        except InvalidArgumentsError as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ToolExecutionResult(
                status="FAILED",
                error_code=exc.error_code,
                error_message=exc.message,
                duration_ms=duration_ms,
            )
        except OutputSizeExceededError as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ToolExecutionResult(
                status="FAILED",
                error_code=exc.error_code,
                error_message=exc.message,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.exception("Adapter '%s' execution error: %s", self.tool_name, exc)
            # Never return internal stack traces to callers
            return ToolExecutionResult(
                status="FAILED",
                error_code="ADAPTER_ERROR",
                error_message=f"Tool execution failed: {type(exc).__name__}",
                duration_ms=duration_ms,
            )
