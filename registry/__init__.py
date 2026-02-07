"""
Agent Registry Module
AI Gateway Enterprise - Motilal Oswal Financial Services

Central repository for managing approved AI agents and models.
Similar to JFrog Artifactory but for AI agents.
"""

from .agent_registry import (
    AgentRegistry,
    Agent,
    AgentStatus,
    RiskLevel,
    init_registry_db
)

from .policies import (
    PolicyEngine,
    AgentPolicy,
    PolicyType
)

__all__ = [
    "AgentRegistry",
    "Agent",
    "AgentStatus",
    "RiskLevel",
    "init_registry_db",
    "PolicyEngine",
    "AgentPolicy",
    "PolicyType"
]
