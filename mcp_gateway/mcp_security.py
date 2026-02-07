"""
MCP Gateway Security - Core Implementation
AI Gateway Enterprise

Controls what tools/APIs AI agents can access within the enterprise.
Implements the Model Context Protocol (MCP) security layer.

Flow:
1. AI Agent requests access to a tool (e.g., "read from Salesforce")
2. MCP Gateway evaluates: Is this agent allowed? What data can it access?
3. Decision: Allow, Deny, or Allow with restrictions
4. All access is logged for audit
"""

import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

from .tool_registry import ToolRegistry, DataClassification, ToolStatus

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class ToolPermission(str, Enum):
    """Permission levels for tool access."""
    NONE = "none"            # No access
    READ = "read"            # Read-only access
    WRITE = "write"          # Read and write
    EXECUTE = "execute"      # Can execute operations
    ADMIN = "admin"          # Full access including delete


class ToolCategory(str, Enum):
    """Tool categories (mirrors tool_registry)."""
    DATABASE = "database"
    API = "api"
    FILESYSTEM = "filesystem"
    EMAIL = "email"
    CRM = "crm"
    ERP = "erp"
    ANALYTICS = "analytics"
    TRADING = "trading"
    COMPLIANCE = "compliance"
    COMMUNICATION = "communication"


class AccessDecision(str, Enum):
    """MCP Gateway access decisions."""
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_RESTRICTED = "allow_restricted"   # Allowed with data masking
    PENDING_APPROVAL = "pending_approval"   # Needs human approval
    RATE_LIMITED = "rate_limited"


@dataclass
class MCPRequest:
    """An AI agent's request to access an enterprise tool."""
    request_id: str
    agent_id: str
    agent_name: str
    tool_id: str
    tool_name: str
    operation: str              # read, write, delete, execute
    resource_path: str          # Specific resource being accessed
    parameters: Dict[str, Any]  # Request parameters
    user_id: str               # User on whose behalf agent is acting
    user_permissions: List[str] # User's permissions
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = now_ist().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MCPResponse:
    """MCP Gateway response to an access request."""
    request_id: str
    decision: AccessDecision
    reason: str
    restrictions: Dict[str, Any] = None   # Data masking, field limits, etc.
    expires_at: str = None                # When this approval expires
    audit_id: str = None

    def __post_init__(self):
        if self.restrictions is None:
            self.restrictions = {}

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data


DB_FILE = "gateway_logs.db"


def init_mcp_db():
    """Initialize MCP Gateway tables."""
    conn = sqlite3.connect(DB_FILE)

    # MCP access policies
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mcp_policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            agent_pattern TEXT,
            tool_pattern TEXT,
            user_group TEXT,
            permission TEXT DEFAULT 'none',
            data_classification_max TEXT DEFAULT 'internal',
            allowed_operations TEXT,
            restrictions TEXT,
            priority INTEGER DEFAULT 100,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # MCP access audit log
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mcp_access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            agent_name TEXT,
            tool_id TEXT NOT NULL,
            tool_name TEXT,
            operation TEXT NOT NULL,
            resource_path TEXT,
            user_id TEXT,
            decision TEXT NOT NULL,
            reason TEXT,
            restrictions TEXT,
            response_time_ms INTEGER,
            timestamp TEXT NOT NULL
        )
    """)

    # Rate limiting state
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mcp_rate_limits (
            agent_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            window_start TEXT NOT NULL,
            request_count INTEGER DEFAULT 0,
            PRIMARY KEY (agent_id, tool_id, window_start)
        )
    """)

    # Pending approvals
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mcp_pending_approvals (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            user_id TEXT NOT NULL,
            request_details TEXT,
            status TEXT DEFAULT 'pending',
            reviewer TEXT,
            reviewed_at TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_log_agent ON mcp_access_log(agent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_log_tool ON mcp_access_log(tool_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_log_time ON mcp_access_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_log_decision ON mcp_access_log(decision)")

    conn.commit()
    conn.close()


class MCPGateway:
    """
    MCP Gateway Security Controller.

    Evaluates AI agent requests to access enterprise tools and makes
    access control decisions based on:
    - Agent permissions and status
    - Tool data classification
    - User permissions (agent acts on behalf of user)
    - Rate limits
    - Custom policies
    """

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self.tool_registry = ToolRegistry(db_file)
        self._rate_limit_cache = defaultdict(list)
        init_mcp_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    def evaluate_request(self, request: MCPRequest) -> MCPResponse:
        """
        Evaluate an MCP access request and return a decision.

        This is the main entry point for all tool access checks.
        """
        start_time = now_ist()
        conn = self._get_conn()

        try:
            # Step 1: Get tool information
            tool = self.tool_registry.get_tool(request.tool_id)
            if not tool:
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    "Tool not found in registry", start_time
                )

            # Step 2: Check tool status
            if tool["status"] != ToolStatus.ACTIVE.value:
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    f"Tool is {tool['status']}", start_time
                )

            # Step 3: Check if agent is blocked for this tool
            if request.agent_id in tool.get("blocked_agents", []):
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    "Agent is explicitly blocked for this tool", start_time
                )

            # Step 4: Check if agent is in allowed list (if specified)
            allowed_agents = tool.get("allowed_agents", [])
            if allowed_agents and request.agent_id not in allowed_agents:
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    "Agent not in allowed list for this tool", start_time
                )

            # Step 5: Check user permissions
            required_perms = set(tool.get("required_permissions", []))
            user_perms = set(request.user_permissions)
            if required_perms and not required_perms.intersection(user_perms):
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    f"User lacks required permissions: {required_perms}", start_time
                )

            # Step 6: Check operation is allowed
            allowed_ops = tool.get("allowed_operations", [])
            if request.operation not in allowed_ops:
                return self._log_and_respond(
                    conn, request, AccessDecision.DENY,
                    f"Operation '{request.operation}' not allowed. Allowed: {allowed_ops}", start_time
                )

            # Step 7: Check rate limits
            rate_limit = tool.get("rate_limit_per_minute", 60)
            if not self._check_rate_limit(request.agent_id, request.tool_id, rate_limit):
                return self._log_and_respond(
                    conn, request, AccessDecision.RATE_LIMITED,
                    f"Rate limit exceeded ({rate_limit}/min)", start_time
                )

            # Step 8: Check if approval is required
            if tool.get("requires_approval"):
                data_class = tool.get("data_classification", "")
                if data_class in [DataClassification.UPSI.value, DataClassification.RESTRICTED.value]:
                    approval_id = self._create_pending_approval(conn, request)
                    return self._log_and_respond(
                        conn, request, AccessDecision.PENDING_APPROVAL,
                        f"Access to {data_class} data requires approval. Approval ID: {approval_id}",
                        start_time
                    )

            # Step 9: Apply data restrictions based on classification
            restrictions = self._get_data_restrictions(tool, request)

            # Step 10: Allow access
            decision = AccessDecision.ALLOW_RESTRICTED if restrictions else AccessDecision.ALLOW
            return self._log_and_respond(
                conn, request, decision,
                "Access granted" if not restrictions else "Access granted with restrictions",
                start_time, restrictions
            )

        except Exception as e:
            return self._log_and_respond(
                conn, request, AccessDecision.DENY,
                f"Error evaluating request: {str(e)}", start_time
            )
        finally:
            conn.close()

    def _log_and_respond(self, conn, request: MCPRequest, decision: AccessDecision,
                         reason: str, start_time, restrictions: Dict = None) -> MCPResponse:
        """Log the access attempt and create response."""
        response_time = int((now_ist() - start_time).total_seconds() * 1000)

        # Log to audit
        conn.execute("""
            INSERT INTO mcp_access_log
            (request_id, agent_id, agent_name, tool_id, tool_name, operation,
             resource_path, user_id, decision, reason, restrictions, response_time_ms, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.request_id, request.agent_id, request.agent_name,
            request.tool_id, request.tool_name, request.operation,
            request.resource_path, request.user_id, decision.value,
            reason, json.dumps(restrictions or {}), response_time, now_ist().isoformat()
        ))
        conn.commit()

        return MCPResponse(
            request_id=request.request_id,
            decision=decision,
            reason=reason,
            restrictions=restrictions
        )

    def _check_rate_limit(self, agent_id: str, tool_id: str, limit: int) -> bool:
        """Check if agent is within rate limit for tool."""
        now = now_ist()
        minute_ago = now - timedelta(minutes=1)

        key = f"{agent_id}:{tool_id}"
        requests = self._rate_limit_cache[key]

        # Clean old requests
        self._rate_limit_cache[key] = [t for t in requests if t > minute_ago]

        if len(self._rate_limit_cache[key]) >= limit:
            return False

        self._rate_limit_cache[key].append(now)
        return True

    def _create_pending_approval(self, conn, request: MCPRequest) -> str:
        """Create a pending approval request."""
        import uuid
        approval_id = f"approval_{uuid.uuid4().hex[:12]}"
        expires = now_ist() + timedelta(hours=24)

        conn.execute("""
            INSERT INTO mcp_pending_approvals
            (id, request_id, agent_id, tool_id, operation, user_id,
             request_details, status, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (
            approval_id, request.request_id, request.agent_id,
            request.tool_id, request.operation, request.user_id,
            json.dumps(request.to_dict()), expires.isoformat(), now_ist().isoformat()
        ))
        conn.commit()

        return approval_id

    def _get_data_restrictions(self, tool: Dict, request: MCPRequest) -> Dict[str, Any]:
        """Get data restrictions based on tool classification."""
        classification = tool.get("data_classification", "internal")
        restrictions = {}

        if classification == DataClassification.CONFIDENTIAL.value:
            restrictions["mask_pii"] = True
            restrictions["max_records"] = 100

        elif classification == DataClassification.RESTRICTED.value:
            restrictions["mask_pii"] = True
            restrictions["mask_financial"] = True
            restrictions["max_records"] = 50
            restrictions["no_export"] = True

        elif classification == DataClassification.UPSI.value:
            restrictions["mask_pii"] = True
            restrictions["mask_financial"] = True
            restrictions["mask_trading"] = True
            restrictions["max_records"] = 25
            restrictions["no_export"] = True
            restrictions["audit_enhanced"] = True

        return restrictions

    def approve_pending_request(self, approval_id: str, reviewer: str) -> Dict[str, Any]:
        """Approve a pending access request."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE mcp_pending_approvals
                SET status = 'approved', reviewer = ?, reviewed_at = ?
                WHERE id = ? AND status = 'pending'
            """, (reviewer, now_ist().isoformat(), approval_id))
            conn.commit()
            return {"success": True, "approval_id": approval_id, "status": "approved"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def deny_pending_request(self, approval_id: str, reviewer: str, reason: str = "") -> Dict[str, Any]:
        """Deny a pending access request."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE mcp_pending_approvals
                SET status = 'denied', reviewer = ?, reviewed_at = ?
                WHERE id = ? AND status = 'pending'
            """, (reviewer, now_ist().isoformat(), approval_id))
            conn.commit()
            return {"success": True, "approval_id": approval_id, "status": "denied"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_pending_approvals(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get pending approval requests."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM mcp_pending_approvals
            WHERE status = 'pending' AND expires_at > ?
            ORDER BY created_at DESC LIMIT ?
        """, (now_ist().isoformat(), limit)).fetchall()
        conn.close()

        approvals = []
        for row in rows:
            approval = dict(row)
            approval["request_details"] = json.loads(approval.get("request_details", "{}"))
            approvals.append(approval)
        return approvals

    def get_access_log(self, agent_id: str = None, tool_id: str = None,
                       decision: AccessDecision = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get MCP access log with optional filters."""
        conn = self._get_conn()

        query = "SELECT * FROM mcp_access_log WHERE 1=1"
        params = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if tool_id:
            query += " AND tool_id = ?"
            params.append(tool_id)

        if decision:
            query += " AND decision = ?"
            params.append(decision.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()

        logs = []
        for row in rows:
            log = dict(row)
            log["restrictions"] = json.loads(log.get("restrictions", "{}"))
            logs.append(log)
        return logs

    def get_access_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get access statistics."""
        conn = self._get_conn()
        cutoff = (now_ist() - timedelta(days=days)).isoformat()

        # By decision
        decision_stats = conn.execute("""
            SELECT decision, COUNT(*) as count
            FROM mcp_access_log WHERE timestamp > ?
            GROUP BY decision
        """, (cutoff,)).fetchall()

        # By tool
        tool_stats = conn.execute("""
            SELECT tool_id, tool_name, COUNT(*) as count
            FROM mcp_access_log WHERE timestamp > ?
            GROUP BY tool_id ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        # By agent
        agent_stats = conn.execute("""
            SELECT agent_id, agent_name, COUNT(*) as count
            FROM mcp_access_log WHERE timestamp > ?
            GROUP BY agent_id ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        # Denials
        denial_reasons = conn.execute("""
            SELECT reason, COUNT(*) as count
            FROM mcp_access_log WHERE timestamp > ? AND decision = 'deny'
            GROUP BY reason ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        conn.close()

        return {
            "period_days": days,
            "by_decision": {row["decision"]: row["count"] for row in decision_stats},
            "top_tools": [{"tool_id": row["tool_id"], "name": row["tool_name"], "count": row["count"]} for row in tool_stats],
            "top_agents": [{"agent_id": row["agent_id"], "name": row["agent_name"], "count": row["count"]} for row in agent_stats],
            "denial_reasons": [{"reason": row["reason"], "count": row["count"]} for row in denial_reasons],
            "generated_at": now_ist().isoformat()
        }


def seed_default_policies(gateway: MCPGateway):
    """Seed default MCP policies."""
    conn = gateway._get_conn()

    policies = [
        {
            "id": "policy_default_deny",
            "name": "Default Deny",
            "description": "Deny all access by default",
            "agent_pattern": "*",
            "tool_pattern": "*",
            "permission": "none",
            "priority": 1000,
            "enabled": True
        },
        {
            "id": "policy_approved_agents_read",
            "name": "Approved Agents Read Access",
            "description": "Allow approved agents to read internal data",
            "agent_pattern": "status:approved",
            "tool_pattern": "*",
            "permission": "read",
            "data_classification_max": "internal",
            "priority": 100,
            "enabled": True
        },
        {
            "id": "policy_block_upsi",
            "name": "Block UPSI Without Approval",
            "description": "Block UPSI access without explicit approval",
            "agent_pattern": "*",
            "tool_pattern": "classification:upsi",
            "permission": "none",
            "priority": 10,
            "enabled": True
        }
    ]

    for policy in policies:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO mcp_policies
                (id, name, description, agent_pattern, tool_pattern, permission,
                 data_classification_max, allowed_operations, priority, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                policy["id"], policy["name"], policy.get("description", ""),
                policy.get("agent_pattern", "*"), policy.get("tool_pattern", "*"),
                policy.get("permission", "none"), policy.get("data_classification_max", "internal"),
                json.dumps(["read"]), policy.get("priority", 100),
                1 if policy.get("enabled", True) else 0,
                now_ist().isoformat(), now_ist().isoformat()
            ))
        except:
            pass

    conn.commit()
    conn.close()


# Initialize on module load
init_mcp_db()
