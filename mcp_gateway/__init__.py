"""
MCP Gateway Security Module
AI Gateway Enterprise

Model Context Protocol (MCP) Gateway for controlling AI agent access to enterprise tools.

While the main gateway scans outgoing data (User → AI), this module controls
incoming tool access (AI → Enterprise Tools/APIs).
"""

from .mcp_security import (
    MCPGateway,
    ToolPermission,
    ToolCategory,
    AccessDecision,
    MCPRequest,
    init_mcp_db
)

from .tool_registry import (
    ToolRegistry,
    EnterpriseTool,
    ToolStatus
)

__all__ = [
    "MCPGateway",
    "ToolPermission",
    "ToolCategory",
    "AccessDecision",
    "MCPRequest",
    "ToolRegistry",
    "EnterpriseTool",
    "ToolStatus",
    "init_mcp_db"
]
