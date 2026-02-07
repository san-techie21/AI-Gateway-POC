"""
Agent Registry - Core Implementation
AI Gateway Enterprise

Central catalog for managing AI agents/models with:
- Registration and approval workflow
- Version control
- Security classification
- Usage tracking
"""

import sqlite3
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum

# Indian Standard Time
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    return datetime.now(IST)


class AgentStatus(str, Enum):
    """Agent lifecycle status."""
    PENDING = "pending"          # Awaiting approval
    APPROVED = "approved"        # Ready for use
    BLOCKED = "blocked"          # Explicitly blocked
    DEPRECATED = "deprecated"    # No longer recommended
    ARCHIVED = "archived"        # Removed from active use


class RiskLevel(str, Enum):
    """Security risk classification."""
    LOW = "low"                  # General use, no restrictions
    MEDIUM = "medium"            # Some data restrictions
    HIGH = "high"                # Sensitive data handling
    CRITICAL = "critical"        # Requires explicit approval


class AgentCategory(str, Enum):
    """Agent capability category."""
    CHAT = "chat"                # Conversational AI
    CODE = "code"                # Code generation/analysis
    VISION = "vision"            # Image understanding
    EMBEDDING = "embedding"      # Vector embeddings
    AUDIO = "audio"              # Speech/audio processing
    MULTIMODAL = "multimodal"    # Multiple capabilities
    CUSTOM = "custom"            # Custom/specialized


@dataclass
class Agent:
    """AI Agent/Model definition."""
    id: str
    name: str
    provider: str
    model_id: str                # Provider's model identifier
    version: str
    status: AgentStatus
    category: AgentCategory
    risk_level: RiskLevel
    description: str = ""
    capabilities: List[str] = None
    max_tokens: int = 4096
    cost_per_1m_input: float = 0.0
    cost_per_1m_output: float = 0.0
    approved_by: str = ""
    approved_at: str = ""
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.metadata is None:
            self.metadata = {}
        if not self.created_at:
            self.created_at = now_ist().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["category"] = self.category.value
        data["risk_level"] = self.risk_level.value
        return data


DB_FILE = "gateway_logs.db"


def init_registry_db():
    """Initialize agent registry tables."""
    conn = sqlite3.connect(DB_FILE)

    # Main agent registry table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_registry (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            provider TEXT NOT NULL,
            model_id TEXT NOT NULL,
            version TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            category TEXT DEFAULT 'chat',
            risk_level TEXT DEFAULT 'medium',
            description TEXT,
            capabilities TEXT,
            max_tokens INTEGER DEFAULT 4096,
            cost_per_1m_input REAL DEFAULT 0.0,
            cost_per_1m_output REAL DEFAULT 0.0,
            approved_by TEXT,
            approved_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata TEXT,
            UNIQUE(provider, model_id, version)
        )
    """)

    # Agent audit log
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            previous_state TEXT,
            new_state TEXT,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Agent usage statistics (per agent)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            date TEXT NOT NULL,
            total_requests INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            total_cost_usd REAL DEFAULT 0.0,
            unique_users INTEGER DEFAULT 0,
            avg_response_time_ms INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            UNIQUE(agent_id, date)
        )
    """)

    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_status ON agent_registry(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_provider ON agent_registry(provider)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_category ON agent_registry(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_audit_agent ON agent_audit_log(agent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_audit_time ON agent_audit_log(timestamp)")

    conn.commit()
    conn.close()


class AgentRegistry:
    """
    Central registry for AI agents and models.

    Features:
    - Register new agents with approval workflow
    - Version management
    - Security risk classification
    - Usage tracking and statistics
    - Audit logging
    """

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        init_registry_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    def _log_audit(self, conn, agent_id: str, action: str, actor: str,
                   previous_state: str = None, new_state: str = None, reason: str = None):
        """Log an audit event."""
        conn.execute("""
            INSERT INTO agent_audit_log
            (agent_id, action, actor, previous_state, new_state, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (agent_id, action, actor, previous_state, new_state, reason, now_ist().isoformat()))

    def register_agent(self, agent: Agent, registered_by: str) -> Dict[str, Any]:
        """
        Register a new agent in the registry.
        Agent starts in PENDING status awaiting approval.
        """
        conn = self._get_conn()

        try:
            # Check if agent already exists
            existing = conn.execute("""
                SELECT id FROM agent_registry
                WHERE provider = ? AND model_id = ? AND version = ?
            """, (agent.provider, agent.model_id, agent.version)).fetchone()

            if existing:
                return {
                    "success": False,
                    "error": f"Agent already exists with ID: {existing['id']}",
                    "existing_id": existing["id"]
                }

            # Generate ID if not provided
            if not agent.id:
                agent.id = f"agent_{uuid.uuid4().hex[:12]}"

            # Insert agent
            conn.execute("""
                INSERT INTO agent_registry
                (id, name, provider, model_id, version, status, category, risk_level,
                 description, capabilities, max_tokens, cost_per_1m_input, cost_per_1m_output,
                 created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent.id, agent.name, agent.provider, agent.model_id, agent.version,
                AgentStatus.PENDING.value, agent.category.value, agent.risk_level.value,
                agent.description, json.dumps(agent.capabilities), agent.max_tokens,
                agent.cost_per_1m_input, agent.cost_per_1m_output,
                agent.created_at, agent.updated_at, json.dumps(agent.metadata)
            ))

            # Log audit
            self._log_audit(conn, agent.id, "registered", registered_by,
                           new_state=AgentStatus.PENDING.value)

            conn.commit()

            return {
                "success": True,
                "agent_id": agent.id,
                "status": AgentStatus.PENDING.value,
                "message": "Agent registered and pending approval"
            }

        except Exception as e:
            conn.rollback()
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def approve_agent(self, agent_id: str, approved_by: str, reason: str = "") -> Dict[str, Any]:
        """Approve an agent for use."""
        return self._update_status(agent_id, AgentStatus.APPROVED, approved_by, reason)

    def block_agent(self, agent_id: str, blocked_by: str, reason: str = "") -> Dict[str, Any]:
        """Block an agent from use."""
        return self._update_status(agent_id, AgentStatus.BLOCKED, blocked_by, reason)

    def deprecate_agent(self, agent_id: str, deprecated_by: str, reason: str = "") -> Dict[str, Any]:
        """Mark an agent as deprecated."""
        return self._update_status(agent_id, AgentStatus.DEPRECATED, deprecated_by, reason)

    def _update_status(self, agent_id: str, new_status: AgentStatus,
                       actor: str, reason: str = "") -> Dict[str, Any]:
        """Update agent status with audit logging."""
        conn = self._get_conn()

        try:
            # Get current status
            agent = conn.execute(
                "SELECT status FROM agent_registry WHERE id = ?", (agent_id,)
            ).fetchone()

            if not agent:
                return {"success": False, "error": "Agent not found"}

            previous_status = agent["status"]
            timestamp = now_ist().isoformat()

            # Update status
            update_fields = {
                "status": new_status.value,
                "updated_at": timestamp
            }

            if new_status == AgentStatus.APPROVED:
                update_fields["approved_by"] = actor
                update_fields["approved_at"] = timestamp

            set_clause = ", ".join(f"{k} = ?" for k in update_fields.keys())
            values = list(update_fields.values()) + [agent_id]

            conn.execute(f"UPDATE agent_registry SET {set_clause} WHERE id = ?", values)

            # Log audit
            self._log_audit(conn, agent_id, f"status_changed_to_{new_status.value}",
                           actor, previous_status, new_status.value, reason)

            conn.commit()

            return {
                "success": True,
                "agent_id": agent_id,
                "previous_status": previous_status,
                "new_status": new_status.value,
                "updated_by": actor
            }

        except Exception as e:
            conn.rollback()
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent details by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agent_registry WHERE id = ?", (agent_id,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        agent = dict(row)
        agent["capabilities"] = json.loads(agent["capabilities"] or "[]")
        agent["metadata"] = json.loads(agent["metadata"] or "{}")
        return agent

    def get_agent_by_model(self, provider: str, model_id: str) -> Optional[Dict[str, Any]]:
        """Get approved agent by provider and model ID."""
        conn = self._get_conn()
        row = conn.execute("""
            SELECT * FROM agent_registry
            WHERE provider = ? AND model_id = ? AND status = ?
            ORDER BY version DESC LIMIT 1
        """, (provider, model_id, AgentStatus.APPROVED.value)).fetchone()
        conn.close()

        if not row:
            return None

        agent = dict(row)
        agent["capabilities"] = json.loads(agent["capabilities"] or "[]")
        agent["metadata"] = json.loads(agent["metadata"] or "{}")
        return agent

    def list_agents(self, status: Optional[AgentStatus] = None,
                   provider: Optional[str] = None,
                   category: Optional[AgentCategory] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """List agents with optional filters."""
        conn = self._get_conn()

        query = "SELECT * FROM agent_registry WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if provider:
            query += " AND provider = ?"
            params.append(provider)

        if category:
            query += " AND category = ?"
            params.append(category.value)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()

        agents = []
        for row in rows:
            agent = dict(row)
            agent["capabilities"] = json.loads(agent["capabilities"] or "[]")
            agent["metadata"] = json.loads(agent["metadata"] or "{}")
            agents.append(agent)

        return agents

    def list_approved_agents(self) -> List[Dict[str, Any]]:
        """Get all approved agents ready for use."""
        return self.list_agents(status=AgentStatus.APPROVED)

    def is_agent_allowed(self, provider: str, model_id: str) -> bool:
        """Check if an agent is approved for use."""
        agent = self.get_agent_by_model(provider, model_id)
        return agent is not None and agent["status"] == AgentStatus.APPROVED.value

    def get_agent_stats(self, agent_id: str, days: int = 30) -> Dict[str, Any]:
        """Get usage statistics for an agent."""
        conn = self._get_conn()
        cutoff = (now_ist() - timedelta(days=days)).strftime("%Y-%m-%d")

        stats = conn.execute("""
            SELECT
                SUM(total_requests) as total_requests,
                SUM(total_tokens) as total_tokens,
                SUM(total_cost_usd) as total_cost_usd,
                AVG(avg_response_time_ms) as avg_response_time,
                SUM(error_count) as total_errors
            FROM agent_usage_stats
            WHERE agent_id = ? AND date >= ?
        """, (agent_id, cutoff)).fetchone()

        daily = conn.execute("""
            SELECT date, total_requests, total_tokens, total_cost_usd
            FROM agent_usage_stats
            WHERE agent_id = ? AND date >= ?
            ORDER BY date
        """, (agent_id, cutoff)).fetchall()

        conn.close()

        return {
            "agent_id": agent_id,
            "period_days": days,
            "totals": dict(stats) if stats else {},
            "daily": [dict(row) for row in daily]
        }

    def get_audit_log(self, agent_id: Optional[str] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        conn = self._get_conn()

        if agent_id:
            rows = conn.execute("""
                SELECT * FROM agent_audit_log
                WHERE agent_id = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (agent_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM agent_audit_log
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()

        conn.close()
        return [dict(row) for row in rows]

    def get_registry_summary(self) -> Dict[str, Any]:
        """Get summary statistics for the registry."""
        conn = self._get_conn()

        # Count by status
        status_counts = conn.execute("""
            SELECT status, COUNT(*) as count
            FROM agent_registry GROUP BY status
        """).fetchall()

        # Count by provider
        provider_counts = conn.execute("""
            SELECT provider, COUNT(*) as count
            FROM agent_registry WHERE status = 'approved' GROUP BY provider
        """).fetchall()

        # Count by category
        category_counts = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM agent_registry WHERE status = 'approved' GROUP BY category
        """).fetchall()

        # Count by risk level
        risk_counts = conn.execute("""
            SELECT risk_level, COUNT(*) as count
            FROM agent_registry WHERE status = 'approved' GROUP BY risk_level
        """).fetchall()

        conn.close()

        return {
            "by_status": {row["status"]: row["count"] for row in status_counts},
            "by_provider": {row["provider"]: row["count"] for row in provider_counts},
            "by_category": {row["category"]: row["count"] for row in category_counts},
            "by_risk_level": {row["risk_level"]: row["count"] for row in risk_counts},
            "generated_at": now_ist().isoformat()
        }


def seed_default_agents(registry: AgentRegistry, admin_user: str = "system"):
    """Seed the registry with common AI agents (pre-approved)."""

    default_agents = [
        # OpenAI
        Agent(
            id="openai_gpt4o",
            name="GPT-4o",
            provider="openai",
            model_id="gpt-4o",
            version="2024-05-13",
            status=AgentStatus.APPROVED,
            category=AgentCategory.MULTIMODAL,
            risk_level=RiskLevel.MEDIUM,
            description="OpenAI's most advanced multimodal model",
            capabilities=["chat", "vision", "code", "analysis"],
            max_tokens=128000,
            cost_per_1m_input=2.50,
            cost_per_1m_output=10.00
        ),
        Agent(
            id="openai_gpt4_turbo",
            name="GPT-4 Turbo",
            provider="openai",
            model_id="gpt-4-turbo",
            version="2024-04-09",
            status=AgentStatus.APPROVED,
            category=AgentCategory.CHAT,
            risk_level=RiskLevel.MEDIUM,
            description="Fast and capable GPT-4 variant",
            capabilities=["chat", "code", "analysis"],
            max_tokens=128000,
            cost_per_1m_input=10.00,
            cost_per_1m_output=30.00
        ),

        # Anthropic
        Agent(
            id="anthropic_claude_sonnet",
            name="Claude 3.5 Sonnet",
            provider="anthropic",
            model_id="claude-3-5-sonnet-20241022",
            version="20241022",
            status=AgentStatus.APPROVED,
            category=AgentCategory.CHAT,
            risk_level=RiskLevel.MEDIUM,
            description="Anthropic's balanced model for intelligence and speed",
            capabilities=["chat", "code", "analysis", "vision"],
            max_tokens=200000,
            cost_per_1m_input=3.00,
            cost_per_1m_output=15.00
        ),
        Agent(
            id="anthropic_claude_opus",
            name="Claude Opus 4",
            provider="anthropic",
            model_id="claude-opus-4-20250514",
            version="20250514",
            status=AgentStatus.APPROVED,
            category=AgentCategory.MULTIMODAL,
            risk_level=RiskLevel.MEDIUM,
            description="Anthropic's most capable model",
            capabilities=["chat", "code", "analysis", "vision", "research"],
            max_tokens=200000,
            cost_per_1m_input=15.00,
            cost_per_1m_output=75.00
        ),

        # Google
        Agent(
            id="google_gemini_pro",
            name="Gemini 2.0 Pro",
            provider="gemini",
            model_id="gemini-2.0-pro",
            version="2.0",
            status=AgentStatus.APPROVED,
            category=AgentCategory.MULTIMODAL,
            risk_level=RiskLevel.LOW,
            description="Google's advanced multimodal model",
            capabilities=["chat", "code", "vision", "analysis"],
            max_tokens=1000000,
            cost_per_1m_input=0.075,
            cost_per_1m_output=0.30
        ),

        # DeepSeek
        Agent(
            id="deepseek_v3",
            name="DeepSeek V3",
            provider="deepseek",
            model_id="deepseek-chat",
            version="v3",
            status=AgentStatus.APPROVED,
            category=AgentCategory.CHAT,
            risk_level=RiskLevel.MEDIUM,
            description="Cost-effective Chinese AI model",
            capabilities=["chat", "code", "analysis"],
            max_tokens=64000,
            cost_per_1m_input=0.14,
            cost_per_1m_output=0.28
        ),

        # Mistral
        Agent(
            id="mistral_large",
            name="Mistral Large",
            provider="mistral",
            model_id="mistral-large-latest",
            version="2024",
            status=AgentStatus.APPROVED,
            category=AgentCategory.CHAT,
            risk_level=RiskLevel.LOW,
            description="Mistral's flagship model",
            capabilities=["chat", "code", "analysis"],
            max_tokens=32000,
            cost_per_1m_input=2.00,
            cost_per_1m_output=6.00
        ),

        # Groq (fast inference)
        Agent(
            id="groq_llama3",
            name="Llama 3 70B (Groq)",
            provider="groq",
            model_id="llama3-70b-8192",
            version="3.0",
            status=AgentStatus.APPROVED,
            category=AgentCategory.CHAT,
            risk_level=RiskLevel.LOW,
            description="Meta's Llama 3 on Groq's fast inference",
            capabilities=["chat", "code"],
            max_tokens=8192,
            cost_per_1m_input=0.05,
            cost_per_1m_output=0.08
        ),
    ]

    registered = 0
    for agent in default_agents:
        agent.status = AgentStatus.PENDING  # Will be auto-approved
        result = registry.register_agent(agent, admin_user)
        if result["success"]:
            # Auto-approve default agents
            registry.approve_agent(result["agent_id"], admin_user, "Default trusted agent")
            registered += 1

    return {"registered": registered, "total": len(default_agents)}


# Initialize on module load
init_registry_db()
