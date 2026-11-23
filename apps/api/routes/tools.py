"""
AgentShield AI — Controlled Tools Metadata Routes (Phase 6).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from agentshield.contracts.execution import ToolMetadataResponse
from agentshield.execution.exceptions import ToolNotFoundError
from agentshield.execution.registry import tool_registry
from apps.api.dependencies import CallerIdentity

router = APIRouter(prefix="/tools", tags=["Tool Registry"])


@router.get("", response_model=list[ToolMetadataResponse])
async def list_registered_tools(
    caller: CallerIdentity,
) -> list[ToolMetadataResponse]:
    """List all registered tools, schemas, supported actions, and operational status."""
    tools = tool_registry.list_all()
    return [t.to_metadata() for t in tools]


@router.get("/{tool_name}", response_model=ToolMetadataResponse)
async def get_tool_metadata(
    tool_name: str,
    caller: CallerIdentity,
) -> ToolMetadataResponse:
    """Get metadata and action schemas for a specific tool."""
    try:
        t = tool_registry.get(tool_name)
        return t.to_metadata()
    except ToolNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.message),
        ) from exc
