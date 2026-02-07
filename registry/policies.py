"""
Agent Policy Engine
AI Gateway Enterprise

Defines and enforces policies for AI agent usage:
- Rate limits per user/role
- Data restrictions (what data can be sent to which agents)
- User group permissions
- Cost limits
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


class PolicyType(str, Enum):
    """Types of agent policies."""
    RATE_LIMIT = "rate_limit"              # Request limits
    DATA_RESTRICTION = "data_restriction"   # What data types are allowed
    USER_GROUP = "user_group"              # Which user groups can access
    COST_LIMIT = "cost_limit"              # Maximum cost per period
    TIME_RESTRICTION = "time_restriction"  # When agent can be used
    CONTENT_FILTER = "content_filter"      # Additional content filtering


class PolicyAction(str, Enum):
    """Actions when policy is violated."""
    BLOCK = "block"           # Block the request
    WARN = "warn"             # Allow but log warning
    NOTIFY = "notify"         # Allow but notify admin
    ESCALATE = "escalate"     # Require manager approval


@dataclass
class AgentPolicy:
    """Policy definition for an agent."""
    id: str
    agent_id: str
    policy_type: PolicyType
    policy_value: Dict[str, Any]
    action_on_violation: PolicyAction = PolicyAction.BLOCK
    is_active: bool = True
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = now_ist().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["policy_type"] = self.policy_type.value
        data["action_on_violation"] = self.action_on_violation.value
        return data


DB_FILE = "gateway_logs.db"


def init_policy_db():
    """Initialize policy tables."""
    conn = sqlite3.connect(DB_FILE)

    # Agent policies table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_policies (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            policy_type TEXT NOT NULL,
            policy_value TEXT NOT NULL,
            action_on_violation TEXT DEFAULT 'block',
            is_active INTEGER DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Global policies (apply to all agents)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS global_policies (
            id TEXT PRIMARY KEY,
            policy_type TEXT NOT NULL,
            policy_value TEXT NOT NULL,
            action_on_violation TEXT DEFAULT 'block',
            is_active INTEGER DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # User group definitions
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            permissions TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # User to group mappings
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_group_members (
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            added_at TEXT NOT NULL,
            added_by TEXT,
            PRIMARY KEY (user_id, group_id)
        )
    """)

    # Policy violation log
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policy_violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id TEXT,
            agent_id TEXT,
            user_id TEXT,
            violation_type TEXT,
            details TEXT,
            action_taken TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # Indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_agent ON agent_policies(agent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_type ON agent_policies(policy_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_violation_user ON policy_violations(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_violation_time ON policy_violations(timestamp)")

    conn.commit()
    conn.close()


class PolicyEngine:
    """
    Policy enforcement engine for AI agents.

    Evaluates requests against defined policies and enforces restrictions.
    """

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        init_policy_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    # ==================== POLICY CRUD ====================

    def create_policy(self, policy: AgentPolicy) -> Dict[str, Any]:
        """Create a new agent policy."""
        conn = self._get_conn()

        try:
            conn.execute("""
                INSERT INTO agent_policies
                (id, agent_id, policy_type, policy_value, action_on_violation,
                 is_active, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                policy.id, policy.agent_id, policy.policy_type.value,
                json.dumps(policy.policy_value), policy.action_on_violation.value,
                1 if policy.is_active else 0, policy.created_by,
                policy.created_at, policy.updated_at
            ))
            conn.commit()
            return {"success": True, "policy_id": policy.id}
        except Exception as e:
            conn.rollback()
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_policies(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get all active policies for an agent."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM agent_policies
            WHERE agent_id = ? AND is_active = 1
        """, (agent_id,)).fetchall()
        conn.close()

        policies = []
        for row in rows:
            policy = dict(row)
            policy["policy_value"] = json.loads(policy["policy_value"])
            policies.append(policy)
        return policies

    def get_global_policies(self) -> List[Dict[str, Any]]:
        """Get all active global policies."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM global_policies WHERE is_active = 1
        """).fetchall()
        conn.close()

        policies = []
        for row in rows:
            policy = dict(row)
            policy["policy_value"] = json.loads(policy["policy_value"])
            policies.append(policy)
        return policies

    # ==================== POLICY EVALUATION ====================

    def evaluate_request(self, agent_id: str, user_id: str, user_role: str,
                        content: str, request_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Evaluate a request against all applicable policies.

        Returns:
            {
                "allowed": bool,
                "violations": [...],
                "warnings": [...]
            }
        """
        violations = []
        warnings = []

        # Get agent-specific policies
        agent_policies = self.get_policies(agent_id)

        # Get global policies
        global_policies = self.get_global_policies()

        all_policies = agent_policies + global_policies

        for policy in all_policies:
            result = self._evaluate_policy(policy, agent_id, user_id, user_role, content, request_context)

            if not result["passed"]:
                if policy["action_on_violation"] == PolicyAction.BLOCK.value:
                    violations.append({
                        "policy_id": policy["id"],
                        "policy_type": policy["policy_type"],
                        "reason": result["reason"],
                        "action": "blocked"
                    })
                elif policy["action_on_violation"] == PolicyAction.WARN.value:
                    warnings.append({
                        "policy_id": policy["id"],
                        "policy_type": policy["policy_type"],
                        "reason": result["reason"],
                        "action": "warning"
                    })

        # Log violations
        for violation in violations:
            self._log_violation(
                policy_id=violation["policy_id"],
                agent_id=agent_id,
                user_id=user_id,
                violation_type=violation["policy_type"],
                details=violation["reason"],
                action_taken=violation["action"]
            )

        return {
            "allowed": len(violations) == 0,
            "violations": violations,
            "warnings": warnings,
            "evaluated_policies": len(all_policies)
        }

    def _evaluate_policy(self, policy: Dict, agent_id: str, user_id: str,
                        user_role: str, content: str, context: Dict) -> Dict[str, Any]:
        """Evaluate a single policy."""
        policy_type = policy["policy_type"]
        policy_value = policy["policy_value"]

        if policy_type == PolicyType.RATE_LIMIT.value:
            return self._check_rate_limit(user_id, agent_id, policy_value)

        elif policy_type == PolicyType.USER_GROUP.value:
            return self._check_user_group(user_id, user_role, policy_value)

        elif policy_type == PolicyType.COST_LIMIT.value:
            return self._check_cost_limit(user_id, agent_id, policy_value)

        elif policy_type == PolicyType.DATA_RESTRICTION.value:
            return self._check_data_restriction(content, policy_value)

        elif policy_type == PolicyType.TIME_RESTRICTION.value:
            return self._check_time_restriction(policy_value)

        # Default: pass
        return {"passed": True}

    def _check_rate_limit(self, user_id: str, agent_id: str, policy_value: Dict) -> Dict[str, Any]:
        """Check rate limit policy."""
        conn = self._get_conn()

        period = policy_value.get("period", "hour")  # hour, day, month
        limit = policy_value.get("limit", 100)

        # Calculate time cutoff
        if period == "hour":
            cutoff = (now_ist() - timedelta(hours=1)).isoformat()
        elif period == "day":
            cutoff = (now_ist() - timedelta(days=1)).isoformat()
        elif period == "month":
            cutoff = (now_ist() - timedelta(days=30)).isoformat()
        else:
            cutoff = (now_ist() - timedelta(hours=1)).isoformat()

        # Count recent requests
        count = conn.execute("""
            SELECT COUNT(*) as count FROM token_usage
            WHERE user_id = ? AND provider = ? AND timestamp >= ?
        """, (user_id, agent_id, cutoff)).fetchone()["count"]

        conn.close()

        if count >= limit:
            return {
                "passed": False,
                "reason": f"Rate limit exceeded: {count}/{limit} requests per {period}"
            }

        return {"passed": True}

    def _check_user_group(self, user_id: str, user_role: str, policy_value: Dict) -> Dict[str, Any]:
        """Check if user belongs to allowed groups."""
        allowed_groups = policy_value.get("allowed_groups", [])
        allowed_roles = policy_value.get("allowed_roles", [])

        # Check role
        if allowed_roles and user_role in allowed_roles:
            return {"passed": True}

        # Check group membership
        if allowed_groups:
            conn = self._get_conn()
            member = conn.execute("""
                SELECT 1 FROM user_group_members ugm
                JOIN user_groups ug ON ugm.group_id = ug.id
                WHERE ugm.user_id = ? AND ug.name IN ({})
            """.format(",".join("?" * len(allowed_groups))),
            [user_id] + allowed_groups).fetchone()
            conn.close()

            if member:
                return {"passed": True}

        return {
            "passed": False,
            "reason": f"User not in allowed groups: {allowed_groups} or roles: {allowed_roles}"
        }

    def _check_cost_limit(self, user_id: str, agent_id: str, policy_value: Dict) -> Dict[str, Any]:
        """Check if user has exceeded cost limits."""
        conn = self._get_conn()

        period = policy_value.get("period", "month")
        max_cost = policy_value.get("max_cost_usd", 100.0)

        if period == "day":
            cutoff = (now_ist() - timedelta(days=1)).isoformat()
        elif period == "month":
            cutoff = (now_ist() - timedelta(days=30)).isoformat()
        else:
            cutoff = (now_ist() - timedelta(days=30)).isoformat()

        result = conn.execute("""
            SELECT COALESCE(SUM(cost_usd), 0) as total_cost FROM token_usage
            WHERE user_id = ? AND timestamp >= ?
        """, (user_id, cutoff)).fetchone()

        conn.close()

        total_cost = result["total_cost"]

        if total_cost >= max_cost:
            return {
                "passed": False,
                "reason": f"Cost limit exceeded: ${total_cost:.2f}/${max_cost:.2f} per {period}"
            }

        return {"passed": True}

    def _check_data_restriction(self, content: str, policy_value: Dict) -> Dict[str, Any]:
        """Check for restricted data patterns."""
        blocked_patterns = policy_value.get("blocked_patterns", [])
        blocked_keywords = policy_value.get("blocked_keywords", [])

        content_lower = content.lower()

        # Check keywords
        for keyword in blocked_keywords:
            if keyword.lower() in content_lower:
                return {
                    "passed": False,
                    "reason": f"Content contains restricted keyword: {keyword}"
                }

        return {"passed": True}

    def _check_time_restriction(self, policy_value: Dict) -> Dict[str, Any]:
        """Check if current time is within allowed hours."""
        allowed_hours = policy_value.get("allowed_hours", {"start": 0, "end": 24})
        allowed_days = policy_value.get("allowed_days", [0, 1, 2, 3, 4, 5, 6])  # 0=Monday

        current = now_ist()
        current_hour = current.hour
        current_day = current.weekday()

        if current_day not in allowed_days:
            return {
                "passed": False,
                "reason": f"Agent not available on this day"
            }

        if not (allowed_hours["start"] <= current_hour < allowed_hours["end"]):
            return {
                "passed": False,
                "reason": f"Agent only available between {allowed_hours['start']}:00 and {allowed_hours['end']}:00"
            }

        return {"passed": True}

    def _log_violation(self, policy_id: str, agent_id: str, user_id: str,
                      violation_type: str, details: str, action_taken: str):
        """Log a policy violation."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO policy_violations
            (policy_id, agent_id, user_id, violation_type, details, action_taken, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (policy_id, agent_id, user_id, violation_type, details, action_taken, now_ist().isoformat()))
        conn.commit()
        conn.close()

    # ==================== USER GROUPS ====================

    def create_user_group(self, group_id: str, name: str, description: str = "",
                         permissions: List[str] = None) -> Dict[str, Any]:
        """Create a user group."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO user_groups (id, name, description, permissions, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (group_id, name, description, json.dumps(permissions or []), now_ist().isoformat()))
            conn.commit()
            return {"success": True, "group_id": group_id}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def add_user_to_group(self, user_id: str, group_id: str, added_by: str) -> Dict[str, Any]:
        """Add a user to a group."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO user_group_members
                (user_id, group_id, added_at, added_by)
                VALUES (?, ?, ?, ?)
            """, (user_id, group_id, now_ist().isoformat(), added_by))
            conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all groups a user belongs to."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT ug.* FROM user_groups ug
            JOIN user_group_members ugm ON ug.id = ugm.group_id
            WHERE ugm.user_id = ?
        """, (user_id,)).fetchall()
        conn.close()

        groups = []
        for row in rows:
            group = dict(row)
            group["permissions"] = json.loads(group["permissions"] or "[]")
            groups.append(group)
        return groups

    # ==================== REPORTS ====================

    def get_violation_report(self, days: int = 30) -> Dict[str, Any]:
        """Get policy violation statistics."""
        conn = self._get_conn()
        cutoff = (now_ist() - timedelta(days=days)).strftime("%Y-%m-%d")

        # Total violations
        total = conn.execute("""
            SELECT COUNT(*) as count FROM policy_violations
            WHERE timestamp >= ?
        """, (cutoff,)).fetchone()["count"]

        # By type
        by_type = conn.execute("""
            SELECT violation_type, COUNT(*) as count
            FROM policy_violations
            WHERE timestamp >= ?
            GROUP BY violation_type
            ORDER BY count DESC
        """, (cutoff,)).fetchall()

        # By user (top offenders)
        by_user = conn.execute("""
            SELECT user_id, COUNT(*) as count
            FROM policy_violations
            WHERE timestamp >= ?
            GROUP BY user_id
            ORDER BY count DESC
            LIMIT 10
        """, (cutoff,)).fetchall()

        conn.close()

        return {
            "period_days": days,
            "total_violations": total,
            "by_type": {row["violation_type"]: row["count"] for row in by_type},
            "top_violators": [{"user_id": row["user_id"], "count": row["count"]} for row in by_user],
            "generated_at": now_ist().isoformat()
        }


def seed_default_policies(engine: PolicyEngine, admin_user: str = "system"):
    """Seed default policies."""
    import uuid

    default_policies = [
        # Global rate limit
        AgentPolicy(
            id=f"policy_{uuid.uuid4().hex[:8]}",
            agent_id="*",  # Global
            policy_type=PolicyType.RATE_LIMIT,
            policy_value={"period": "hour", "limit": 50},
            action_on_violation=PolicyAction.BLOCK,
            created_by=admin_user
        ),
        # Global cost limit
        AgentPolicy(
            id=f"policy_{uuid.uuid4().hex[:8]}",
            agent_id="*",
            policy_type=PolicyType.COST_LIMIT,
            policy_value={"period": "month", "max_cost_usd": 500.0},
            action_on_violation=PolicyAction.WARN,
            created_by=admin_user
        ),
    ]

    created = 0
    for policy in default_policies:
        result = engine.create_policy(policy)
        if result["success"]:
            created += 1

    return {"created": created, "total": len(default_policies)}


# Initialize on module load
init_policy_db()
