"""
Enterprise Tool Registry
AI Gateway Enterprise

Catalog of enterprise tools/APIs that AI agents can potentially access.
Each tool has access controls, data classifications, and audit requirements.
"""

import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class ToolStatus(str, Enum):
    """Tool availability status."""
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    MAINTENANCE = "maintenance"


class DataClassification(str, Enum):
    """Data sensitivity classification for tools."""
    PUBLIC = "public"              # Publicly available data
    INTERNAL = "internal"          # Internal company data
    CONFIDENTIAL = "confidential"  # Confidential business data
    RESTRICTED = "restricted"      # Highly sensitive (PII, financial)
    UPSI = "upsi"                  # Unpublished Price Sensitive Info (SEBI)


class ToolCategory(str, Enum):
    """Categories of enterprise tools."""
    DATABASE = "database"          # SQL/NoSQL databases
    API = "api"                    # REST/GraphQL APIs
    FILESYSTEM = "filesystem"      # File system access
    EMAIL = "email"                # Email systems
    CRM = "crm"                    # Customer relationship tools
    ERP = "erp"                    # Enterprise resource planning
    ANALYTICS = "analytics"        # BI and analytics tools
    TRADING = "trading"            # Trading systems
    COMPLIANCE = "compliance"      # Regulatory/compliance systems
    COMMUNICATION = "communication" # Teams/Slack/messaging


@dataclass
class EnterpriseTool:
    """Definition of an enterprise tool that AI agents can access."""
    id: str
    name: str
    description: str
    category: ToolCategory
    status: ToolStatus
    endpoint: str                          # API endpoint or connection string pattern
    data_classification: DataClassification
    required_permissions: List[str]        # Required user permissions to use
    allowed_operations: List[str]          # read, write, delete, execute
    rate_limit_per_minute: int = 60
    requires_approval: bool = False        # Needs explicit admin approval per request
    audit_all_access: bool = True          # Log all access attempts
    allowed_agents: List[str] = None       # Specific agent IDs, None = all approved agents
    blocked_agents: List[str] = None       # Explicitly blocked agents
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.allowed_agents is None:
            self.allowed_agents = []
        if self.blocked_agents is None:
            self.blocked_agents = []
        if self.metadata is None:
            self.metadata = {}
        if not self.created_at:
            self.created_at = now_ist().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["status"] = self.status.value
        data["data_classification"] = self.data_classification.value
        return data


DB_FILE = "gateway_logs.db"


def init_tool_registry_db():
    """Initialize tool registry tables."""
    conn = sqlite3.connect(DB_FILE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS enterprise_tools (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            endpoint TEXT,
            data_classification TEXT DEFAULT 'internal',
            required_permissions TEXT,
            allowed_operations TEXT,
            rate_limit_per_minute INTEGER DEFAULT 60,
            requires_approval INTEGER DEFAULT 0,
            audit_all_access INTEGER DEFAULT 1,
            allowed_agents TEXT,
            blocked_agents TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata TEXT
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_category ON enterprise_tools(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_status ON enterprise_tools(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_classification ON enterprise_tools(data_classification)")

    conn.commit()
    conn.close()


class ToolRegistry:
    """
    Registry of enterprise tools available for AI agent access.
    """

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        init_tool_registry_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    def register_tool(self, tool: EnterpriseTool) -> Dict[str, Any]:
        """Register a new enterprise tool."""
        conn = self._get_conn()

        try:
            conn.execute("""
                INSERT INTO enterprise_tools
                (id, name, description, category, status, endpoint, data_classification,
                 required_permissions, allowed_operations, rate_limit_per_minute,
                 requires_approval, audit_all_access, allowed_agents, blocked_agents,
                 created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tool.id, tool.name, tool.description, tool.category.value,
                tool.status.value, tool.endpoint, tool.data_classification.value,
                json.dumps(tool.required_permissions), json.dumps(tool.allowed_operations),
                tool.rate_limit_per_minute, 1 if tool.requires_approval else 0,
                1 if tool.audit_all_access else 0, json.dumps(tool.allowed_agents),
                json.dumps(tool.blocked_agents), tool.created_at, tool.updated_at,
                json.dumps(tool.metadata)
            ))
            conn.commit()
            return {"success": True, "tool_id": tool.id}

        except sqlite3.IntegrityError:
            return {"success": False, "error": "Tool already exists"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """Get tool by ID."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM enterprise_tools WHERE id = ?", (tool_id,)).fetchone()
        conn.close()

        if not row:
            return None

        tool = dict(row)
        for field in ["required_permissions", "allowed_operations", "allowed_agents", "blocked_agents", "metadata"]:
            tool[field] = json.loads(tool[field] or "[]" if field != "metadata" else "{}")
        return tool

    def list_tools(self, category: Optional[ToolCategory] = None,
                   status: Optional[ToolStatus] = None) -> List[Dict[str, Any]]:
        """List tools with optional filters."""
        conn = self._get_conn()

        query = "SELECT * FROM enterprise_tools WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category.value)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY name"

        rows = conn.execute(query, params).fetchall()
        conn.close()

        tools = []
        for row in rows:
            tool = dict(row)
            for field in ["required_permissions", "allowed_operations", "allowed_agents", "blocked_agents", "metadata"]:
                tool[field] = json.loads(tool[field] or "[]" if field != "metadata" else "{}")
            tools.append(tool)

        return tools

    def update_tool_status(self, tool_id: str, status: ToolStatus) -> bool:
        """Update tool status."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE enterprise_tools SET status = ?, updated_at = ? WHERE id = ?
            """, (status.value, now_ist().isoformat(), tool_id))
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()

    def is_agent_allowed_for_tool(self, tool_id: str, agent_id: str) -> bool:
        """Check if an agent is allowed to use a specific tool."""
        tool = self.get_tool(tool_id)
        if not tool:
            return False

        if tool["status"] != ToolStatus.ACTIVE.value:
            return False

        # Check if explicitly blocked
        if agent_id in tool.get("blocked_agents", []):
            return False

        # If allowed_agents is empty, all agents are allowed
        # Otherwise, check if agent is in allowed list
        allowed = tool.get("allowed_agents", [])
        if allowed and agent_id not in allowed:
            return False

        return True


def seed_default_tools(registry: ToolRegistry):
    """Seed registry with common enterprise tools."""

    default_tools = [
        EnterpriseTool(
            id="tool_salesforce",
            name="Salesforce CRM",
            description="Customer relationship management data",
            category=ToolCategory.CRM,
            status=ToolStatus.ACTIVE,
            endpoint="https://api.salesforce.com/v55.0/*",
            data_classification=DataClassification.CONFIDENTIAL,
            required_permissions=["crm.read", "crm.write"],
            allowed_operations=["read", "write"],
            rate_limit_per_minute=100,
            requires_approval=False,
            audit_all_access=True
        ),
        EnterpriseTool(
            id="tool_trading_db",
            name="Trading Database",
            description="Trading orders and positions database",
            category=ToolCategory.TRADING,
            status=ToolStatus.ACTIVE,
            endpoint="postgresql://trading-db.internal/*",
            data_classification=DataClassification.UPSI,
            required_permissions=["trading.read"],
            allowed_operations=["read"],
            rate_limit_per_minute=30,
            requires_approval=True,  # UPSI requires approval
            audit_all_access=True
        ),
        EnterpriseTool(
            id="tool_email",
            name="Email System",
            description="Corporate email access",
            category=ToolCategory.EMAIL,
            status=ToolStatus.ACTIVE,
            endpoint="https://graph.microsoft.com/v1.0/mail/*",
            data_classification=DataClassification.CONFIDENTIAL,
            required_permissions=["mail.read"],
            allowed_operations=["read"],
            rate_limit_per_minute=50,
            requires_approval=False,
            audit_all_access=True
        ),
        EnterpriseTool(
            id="tool_analytics",
            name="Analytics Dashboard",
            description="Business intelligence and analytics",
            category=ToolCategory.ANALYTICS,
            status=ToolStatus.ACTIVE,
            endpoint="https://analytics.internal/api/*",
            data_classification=DataClassification.INTERNAL,
            required_permissions=["analytics.read"],
            allowed_operations=["read"],
            rate_limit_per_minute=200,
            requires_approval=False,
            audit_all_access=False
        ),
        EnterpriseTool(
            id="tool_compliance",
            name="Compliance System",
            description="Regulatory and compliance data",
            category=ToolCategory.COMPLIANCE,
            status=ToolStatus.ACTIVE,
            endpoint="https://compliance.internal/api/*",
            data_classification=DataClassification.RESTRICTED,
            required_permissions=["compliance.read", "compliance.admin"],
            allowed_operations=["read"],
            rate_limit_per_minute=20,
            requires_approval=True,
            audit_all_access=True
        ),
    ]

    registered = 0
    for tool in default_tools:
        result = registry.register_tool(tool)
        if result["success"]:
            registered += 1

    return {"registered": registered, "total": len(default_tools)}


# Initialize on module load
init_tool_registry_db()
