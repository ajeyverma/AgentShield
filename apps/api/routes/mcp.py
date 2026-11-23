"""
AgentShield AI — MCP Firewall Gateway Routes (Phase 8).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from agentshield.core.exceptions import AgentShieldError
from agentshield.database.models.mcp import MCPActivityModel, MCPServerModel
from agentshield.mcp_gateway.exceptions import MCPGatewayError, NotFoundError, ValidationError
from agentshield.mcp_gateway.proxy import mcp_gateway
from apps.api.dependencies import CurrentUser, DbSession

router = APIRouter(prefix="/mcp", tags=["MCP Gateway"])


# Schemas
class MCPServerCreate(BaseModel):
    server_name: str = Field(..., min_length=1, max_length=128)
    server_description: str | None = None
    transport_type: str = Field(default="stdio", pattern="^(stdio|streamable_http|sse|http)$")
    endpoint_or_command: str = Field(..., min_length=1, max_length=512)
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    trust_classification: str = Field(default="untrusted")


class MCPServerUpdate(BaseModel):
    server_description: str | None = None
    is_enabled: bool | None = None
    trust_classification: str | None = None


class MCPServerResponse(BaseModel):
    id: str
    server_name: str
    server_description: str | None = None
    transport_type: str
    endpoint_or_command: str
    args: list[str] = Field(default_factory=list)
    protocol_version: str
    connection_status: str
    is_enabled: bool
    trust_classification: str
    last_connected_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime


class MCPActivityResponse(BaseModel):
    id: str
    server_id: str
    client_id: str | None = None
    operation_type: str
    target_name: str
    decision: str
    status: str
    request_summary: str | None = None
    response_summary: str | None = None
    redaction_applied: bool
    threat_count: int
    duration_ms: float | None = None
    created_at: datetime


def _to_server_response(model: MCPServerModel) -> MCPServerResponse:
    args = json.loads(model.args_json) if model.args_json else []
    return MCPServerResponse(
        id=model.id,
        server_name=model.server_name,
        server_description=model.server_description,
        transport_type=model.transport_type,
        endpoint_or_command=model.endpoint_or_command,
        args=args,
        protocol_version=model.protocol_version,
        connection_status=model.connection_status,
        is_enabled=model.is_enabled,
        trust_classification=model.trust_classification,
        last_connected_at=model.last_connected_at,
        error_message=model.error_message,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


# ---------------------------------------------------------------------------
# Server Registry Management
# ---------------------------------------------------------------------------


@router.post("/servers", response_model=MCPServerResponse, status_code=status.HTTP_201_CREATED)
async def register_mcp_server(
    data: MCPServerCreate,
    user: CurrentUser,
    db: DbSession,
) -> MCPServerResponse:
    """Register a new upstream MCP server under the tenant."""
    try:
        server = await mcp_gateway.server_registry.register_server(
            db=db,
            user_id=user.id,
            server_name=data.server_name,
            transport_type=data.transport_type,
            endpoint_or_command=data.endpoint_or_command,
            server_description=data.server_description,
            args=data.args,
            env=data.env,
            trust_classification=data.trust_classification,
        )
        return _to_server_response(server)
    except AgentShieldError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/servers", response_model=list[MCPServerResponse])
async def list_mcp_servers(
    user: CurrentUser,
    db: DbSession,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[MCPServerResponse]:
    """List registered MCP servers for the current user."""
    servers = await mcp_gateway.server_registry.list_servers(db, user_id=user.id, limit=limit, offset=offset)
    return [_to_server_response(s) for s in servers]


@router.get("/servers/{server_id}", response_model=MCPServerResponse)
async def get_mcp_server(
    server_id: str,
    user: CurrentUser,
    db: DbSession,
) -> MCPServerResponse:
    """Get server details ensuring tenant isolation."""
    try:
        server = await mcp_gateway.server_registry.get_server(db, server_id, user.id)
        return _to_server_response(server)
    except AgentShieldError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.patch("/servers/{server_id}", response_model=MCPServerResponse)
async def update_mcp_server(
    server_id: str,
    data: MCPServerUpdate,
    user: CurrentUser,
    db: DbSession,
) -> MCPServerResponse:
    """Update MCP server configuration (enabled/disabled, trust, description)."""
    try:
        server = await mcp_gateway.server_registry.get_server(db, server_id, user.id)
        if data.server_description is not None:
            server.server_description = data.server_description
        if data.is_enabled is not None:
            server.is_enabled = data.is_enabled
        if data.trust_classification is not None:
            server.trust_classification = data.trust_classification

        await db.commit()
        await db.refresh(server)
        return _to_server_response(server)
    except AgentShieldError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_server(
    server_id: str,
    user: CurrentUser,
    db: DbSession,
) -> None:
    """Delete an MCP server registration."""
    try:
        await mcp_gateway.server_registry.delete_server(db, server_id, user.id)
        mcp_gateway.tool_registry.clear_server(server_id)
    except AgentShieldError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/servers/{server_id}/connect")
async def connect_mcp_server(
    server_id: str,
    user: CurrentUser,
    db: DbSession,
) -> dict[str, Any]:
    """Test connection and perform initialization handshake with upstream MCP server."""
    server = await mcp_gateway.server_registry.get_server(db, server_id, user.id)
    client = mcp_gateway.get_or_create_client(server)
    try:
        capabilities = await client.connect()
        await mcp_gateway.server_registry.update_server_status(
            db, server_id, user.id, status="connected", capabilities=capabilities
        )
        return {"status": "connected", "capabilities": capabilities}
    except Exception as e:
        await mcp_gateway.server_registry.update_server_status(
            db, server_id, user.id, status="error", error_message=str(e)
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Connection failed: {e}")


@router.post("/servers/{server_id}/disconnect")
async def disconnect_mcp_server(
    server_id: str,
    user: CurrentUser,
    db: DbSession,
) -> dict[str, Any]:
    """Disconnect active session to upstream MCP server."""
    server = await mcp_gateway.server_registry.get_server(db, server_id, user.id)
    if server.id in mcp_gateway._clients:
        await mcp_gateway._clients[server.id].close()
    await mcp_gateway.server_registry.update_server_status(db, server_id, user.id, status="disconnected")
    return {"status": "disconnected"}


@router.get("/servers/{server_id}/tools")
async def list_server_tools(
    server_id: str,
    user: CurrentUser,
    db: DbSession,
) -> dict[str, Any]:
    """Discover tools from server, apply namespacing, and return."""
    server = await mcp_gateway.server_registry.get_server(db, server_id, user.id)
    client = mcp_gateway.get_or_create_client(server)

    resp = await mcp_gateway.handle_client_message(
        session=db,
        user_id=user.id,
        server_id=server.id,
        raw_payload={"jsonrpc": "2.0", "id": "list-tools-api", "method": "tools/list"},
    )
    return resp


# ---------------------------------------------------------------------------
# Intercepted MCP Activity Audit Log
# ---------------------------------------------------------------------------


@router.get("/activities", response_model=list[MCPActivityResponse])
async def list_mcp_activities(
    user: CurrentUser,
    db: DbSession,
    server_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[MCPActivityResponse]:
    """List intercepted MCP activities."""
    query = select(MCPActivityModel).where(MCPActivityModel.user_id == user.id)
    if server_id:
        query = query.where(MCPActivityModel.server_id == server_id)
    query = query.order_by(MCPActivityModel.created_at.desc()).offset(offset).limit(limit)

    res = await db.execute(query)
    activities = res.scalars().all()
    return [
        MCPActivityResponse(
            id=a.id,
            server_id=a.server_id,
            client_id=a.client_id,
            operation_type=a.operation_type,
            target_name=a.target_name,
            decision=a.decision,
            status=a.status,
            request_summary=a.request_summary,
            response_summary=a.response_summary,
            redaction_applied=a.redaction_applied,
            threat_count=a.threat_count,
            duration_ms=a.duration_ms,
            created_at=a.created_at,
        )
        for a in activities
    ]


# ---------------------------------------------------------------------------
# Primary JSON-RPC Firewall Gateway Interception Endpoint
# ---------------------------------------------------------------------------


@router.post("/gateway/{server_id}/message")
async def gateway_message(
    server_id: str,
    payload: dict[str, Any],
    user: CurrentUser,
    db: DbSession,
    x_agent_id: str | None = Header(None, alias="X-Agent-ID"),
    approval_id: str | None = Query(None),
) -> dict[str, Any]:
    """
    Standard HTTP JSON-RPC 2.0 gateway endpoint.
    Intercepts client operations before forwarding to upstream external server.
    """
    return await mcp_gateway.handle_client_message(
        session=db,
        user_id=user.id,
        server_id=server_id,
        raw_payload=payload,
        agent_id=x_agent_id,
        approval_id=approval_id,
    )
