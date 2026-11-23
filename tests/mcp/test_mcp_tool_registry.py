"""
Tests for MCP Tool Discovery, Namespacing, and Collision Resolution (Phase 8).
"""

from agentshield.mcp_gateway.registry.tool_registry import MCPToolRegistry


def test_tool_registration_and_namespacing():
    registry = MCPToolRegistry()

    tool1 = registry.register_tool(
        server_id="srv-1",
        server_name="filesystem",
        original_name="read_file",
        description="Read file from disk",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )

    assert tool1.namespaced_name == "filesystem_read_file"
    assert tool1.original_name == "read_file"
    assert tool1.server_id == "srv-1"
    assert tool1.server_name == "filesystem"


def test_tool_collision_resolution():
    registry = MCPToolRegistry()

    # Server 1 registers "query"
    tool1 = registry.register_tool(
        server_id="srv-postgres",
        server_name="db",
        original_name="query",
        description="Query PostgreSQL",
    )
    assert tool1.namespaced_name == "db_query"

    # Server 2 (also named "db") registers "query"
    tool2 = registry.register_tool(
        server_id="srv-mysql",
        server_name="db",
        original_name="query",
        description="Query MySQL",
    )
    assert tool2.namespaced_name == "db_query_1"
    assert tool2.original_name == "query"

    # Verify both can be looked up by namespaced name
    assert registry.get_tool("db_query").server_id == "srv-postgres"
    assert registry.get_tool("db_query_1").server_id == "srv-mysql"


def test_tool_lookup_by_server_id_and_original_name():
    registry = MCPToolRegistry()

    registry.register_tool(
        server_id="srv-1",
        server_name="weather_service",
        original_name="get_forecast",
        description="Weather forecast",
    )

    found = registry.get_tool("get_forecast", server_id="srv-1")
    assert found is not None
    assert found.namespaced_name == "weather_service_get_forecast"


def test_tool_registry_clear_server():
    registry = MCPToolRegistry()

    registry.register_tool("srv-1", "srv1", "tool_a")
    registry.register_tool("srv-1", "srv1", "tool_b")
    registry.register_tool("srv-2", "srv2", "tool_c")

    assert len(registry.list_tools()) == 3

    registry.clear_server("srv-1")
    remaining = registry.list_tools()
    assert len(remaining) == 1
    assert remaining[0].original_name == "tool_c"
