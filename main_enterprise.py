"""
AI Gateway Enterprise v3.0
Motilal Oswal Financial Services

Complete Enterprise AI Security Layer with:
- 29 AI Provider Support
- KMS Integration (AWS/Azure/HashiCorp/Local)
- Agent Registry & Approval Workflow
- MCP Gateway Security (AI → Enterprise Tools)
- PII Detection & Content Scanning
- Telemetry & Cost Tracking
- Enterprise Integrations (SIEM, Teams, Slack)

This is the enhanced version of main.py with all enterprise features integrated.
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Header, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from enum import Enum
import httpx
import re
import json
import sqlite3
import hashlib
import uuid
import os

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    """Get current time in Indian Standard Time (IST)."""
    return datetime.now(IST)

# ============== ENTERPRISE MODULE IMPORTS ==============

# Import KMS/Secrets Management
try:
    from secrets_integration import (
        init_secrets_manager, get_api_key, set_api_key,
        get_secrets_health, list_configured_providers, migrate_config_to_vault
    )
    KMS_AVAILABLE = True
    print("KMS Integration: Available")
except ImportError as e:
    print(f"Warning: KMS module not available: {e}")
    KMS_AVAILABLE = False
    def get_api_key(provider): return None

# Import Agent Registry
try:
    from registry import (
        AgentRegistry, Agent, AgentStatus, RiskLevel, AgentCategory,
        init_registry_db, seed_default_agents
    )
    from registry.policies import PolicyEngine
    REGISTRY_AVAILABLE = True
    agent_registry = AgentRegistry()
    policy_engine = PolicyEngine()
    print("Agent Registry: Available")
except ImportError as e:
    print(f"Warning: Agent Registry not available: {e}")
    REGISTRY_AVAILABLE = False
    agent_registry = None
    policy_engine = None

# Import MCP Gateway
try:
    from mcp_gateway import (
        MCPGateway, ToolRegistry, ToolPermission, AccessDecision,
        MCPRequest, EnterpriseTool, ToolStatus, ToolCategory as MCPToolCategory,
        init_mcp_db
    )
    from mcp_gateway.tool_registry import seed_default_tools, DataClassification
    MCP_AVAILABLE = True
    mcp_gateway = MCPGateway()
    tool_registry = ToolRegistry()
    print("MCP Gateway: Available")
except ImportError as e:
    print(f"Warning: MCP Gateway not available: {e}")
    MCP_AVAILABLE = False
    mcp_gateway = None
    tool_registry = None

# Import authentication and QRadar modules
try:
    from auth import auth_service, load_auth_config
    from auth_routes import router as auth_router, get_session_from_cookie
    from qradar import qradar_service, log_query_allowed, log_query_blocked, log_query_local, log_rate_limit
    from qradar_routes import router as qradar_router
    AUTH_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Auth/QRadar modules not fully available: {e}")
    AUTH_MODULES_AVAILABLE = False

# Import telemetry module
try:
    from telemetry import (
        log_token_usage, get_user_usage, get_provider_usage,
        get_overall_stats, get_recent_usage, PROVIDER_COSTS
    )
    TELEMETRY_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Telemetry module not available: {e}")
    TELEMETRY_AVAILABLE = False

# ============== APP SETUP ==============

app = FastAPI(
    title="AI Gateway Enterprise",
    description="Enterprise AI Security Layer with KMS, Agent Registry & MCP Gateway",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include authentication and QRadar routers
if AUTH_MODULES_AVAILABLE:
    app.include_router(auth_router)
    app.include_router(qradar_router)

# ============== STARTUP INITIALIZATION ==============

@app.on_event("startup")
async def startup_event():
    """Initialize enterprise components on startup."""
    print("\n" + "="*60)
    print("   AI Gateway Enterprise v3.0 - Initializing")
    print("="*60)

    # Initialize KMS
    if KMS_AVAILABLE:
        secrets_provider = os.environ.get("AI_GATEWAY_SECRETS_PROVIDER", "local")
        if init_secrets_manager(provider=secrets_provider):
            print(f"   KMS: Initialized ({secrets_provider})")
        else:
            print(f"   KMS: Failed to initialize")

    # Initialize Agent Registry with defaults
    if REGISTRY_AVAILABLE:
        result = seed_default_agents(agent_registry, "system")
        print(f"   Agent Registry: {result['registered']} agents seeded")

    # Initialize MCP Gateway with default tools
    if MCP_AVAILABLE:
        result = seed_default_tools(tool_registry)
        print(f"   MCP Gateway: {result['registered']} tools registered")

    print("="*60 + "\n")

# ============== CONFIGURATION ==============

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "active_provider": "openai",
    "local_llm_mode": "mock",
    "enterprise": {
        "kms_provider": "local",
        "agent_registry_enabled": True,
        "mcp_gateway_enabled": True,
        "require_agent_approval": True
    },
    "providers": {
        "openai": {
            "name": "OpenAI",
            "api_key": "YOUR_OPENAI_API_KEY",
            "base_url": "https://api.openai.com/v1/chat/completions",
            "default_model": "gpt-4o-mini",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
            "enabled": True
        },
        "claude": {
            "name": "Anthropic Claude",
            "api_key": "YOUR_CLAUDE_API_KEY",
            "base_url": "https://api.anthropic.com/v1/messages",
            "default_model": "claude-3-5-sonnet-20241022",
            "models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"],
            "enabled": True
        },
        "gemini": {
            "name": "Google Gemini",
            "api_key": "YOUR_GEMINI_API_KEY",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/models",
            "default_model": "gemini-1.5-pro",
            "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.0-pro", "gemini-2.0-flash-exp"],
            "enabled": True
        },
        "deepseek": {
            "name": "DeepSeek",
            "api_key": "YOUR_DEEPSEEK_API_KEY",
            "base_url": "https://api.deepseek.com/v1/chat/completions",
            "default_model": "deepseek-chat",
            "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
            "enabled": True
        },
        "mistral": {
            "name": "Mistral AI",
            "api_key": "YOUR_MISTRAL_API_KEY",
            "base_url": "https://api.mistral.ai/v1/chat/completions",
            "default_model": "mistral-large-latest",
            "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "codestral-latest"],
            "enabled": True
        },
        "groq": {
            "name": "Groq (Fast Inference)",
            "api_key": "YOUR_GROQ_API_KEY",
            "base_url": "https://api.groq.com/openai/v1/chat/completions",
            "default_model": "llama-3.3-70b-versatile",
            "models": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
            "enabled": True
        },
        "openrouter": {
            "name": "OpenRouter (Multi-Provider)",
            "api_key": "YOUR_OPENROUTER_API_KEY",
            "base_url": "https://openrouter.ai/api/v1/chat/completions",
            "default_model": "anthropic/claude-3.5-sonnet",
            "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "google/gemini-pro-1.5", "meta-llama/llama-3.1-405b-instruct"],
            "enabled": True
        },
        "ollama": {
            "name": "Ollama (Local)",
            "api_key": "",
            "base_url": "http://localhost:11434/api/chat",
            "default_model": "llama3.2",
            "models": ["llama3.2", "llama3.1", "mistral", "codellama", "phi3", "gemma2"],
            "enabled": True,
            "is_local": True
        }
    },
    "file_size_limits": {
        "max_content_size_mb": 1,
        "max_file_upload_mb": 5
    },
    "blocked_keywords": [
        "confidential", "internal only", "UPSI", "unpublished price sensitive",
        "trading algorithm", "proprietary", "client list", "salary data"
    ],
    "rate_limiting": {
        "enabled": True,
        "requests_per_minute": 20,
        "requests_per_hour": 200
    }
}

def load_config() -> dict:
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            # Merge with defaults
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
            return config
    except:
        return DEFAULT_CONFIG.copy()

def save_config(config: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# ============== PII DETECTION ==============

DETECTION_PATTERNS = {
    "aadhaar": {
        "pattern": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
        "description": "Aadhaar Number (Indian ID)",
        "severity": "CRITICAL"
    },
    "pan": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "description": "PAN Card Number",
        "severity": "CRITICAL"
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "description": "Credit Card Number",
        "severity": "CRITICAL"
    },
    "api_key_generic": {
        "pattern": r"(?:api[_-]?key|apikey|api_secret|secret_key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
        "description": "API Key/Secret",
        "severity": "CRITICAL"
    },
    "aws_access_key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "description": "AWS Access Key",
        "severity": "CRITICAL"
    },
    "private_key": {
        "pattern": r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        "description": "Private Key",
        "severity": "CRITICAL"
    },
    "db_connection": {
        "pattern": r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s\"']+",
        "description": "Database Connection String",
        "severity": "CRITICAL"
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "description": "Email Address",
        "severity": "MEDIUM"
    },
    "phone_india": {
        "pattern": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "description": "Indian Phone Number",
        "severity": "HIGH"
    }
}

# ============== DATABASE ==============

DB_FILE = "gateway_logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            user_role TEXT,
            action TEXT NOT NULL,
            route TEXT,
            provider TEXT,
            model TEXT,
            agent_id TEXT,
            content_preview TEXT,
            content_hash TEXT,
            content_size_bytes INTEGER,
            detections_json TEXT,
            response_preview TEXT,
            processing_time_ms INTEGER
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON request_logs(action)")
    conn.commit()
    conn.close()

init_db()

# ============== RATE LIMITING ==============

user_requests = defaultdict(list)

def check_rate_limit(user_id: str) -> dict:
    config = load_config()
    rate_config = config.get("rate_limiting", {})

    if not rate_config.get("enabled", False):
        return {"allowed": True}

    now = now_ist()
    user_requests[user_id] = [t for t in user_requests[user_id] if t > now - timedelta(hours=1)]

    minute_ago = now - timedelta(minutes=1)
    reqs_last_minute = sum(1 for t in user_requests[user_id] if t > minute_ago)

    if reqs_last_minute >= rate_config.get("requests_per_minute", 20):
        return {"allowed": False, "reason": "Rate limit exceeded (per minute)"}

    if len(user_requests[user_id]) >= rate_config.get("requests_per_hour", 200):
        return {"allowed": False, "reason": "Rate limit exceeded (per hour)"}

    user_requests[user_id].append(now)
    return {"allowed": True}

# ============== SCANNING ==============

def scan_content(text: str) -> dict:
    """Scan text for sensitive data patterns."""
    config = load_config()
    results = {
        "is_sensitive": False,
        "detections": [],
        "severity": "NONE"
    }

    if not text:
        return results

    # Check blocked keywords
    for keyword in config.get("blocked_keywords", []):
        if keyword.lower() in text.lower():
            results["is_sensitive"] = True
            results["severity"] = "HIGH"
            results["detections"].append({
                "type": "blocked_keyword",
                "description": f"Contains blocked keyword: '{keyword}'",
                "severity": "HIGH"
            })

    # Check PII patterns
    for pattern_name, pattern_info in DETECTION_PATTERNS.items():
        matches = re.findall(pattern_info["pattern"], text, re.IGNORECASE)
        if matches:
            results["is_sensitive"] = True
            if pattern_info["severity"] == "CRITICAL":
                results["severity"] = "CRITICAL"
            results["detections"].append({
                "type": pattern_name,
                "description": pattern_info["description"],
                "severity": pattern_info["severity"],
                "count": len(matches)
            })

    return results

# ============== AGENT VALIDATION ==============

def validate_agent_access(provider: str, model: str, user_id: str) -> Dict[str, Any]:
    """
    Validate if the requested agent (provider + model) is allowed.
    Integrates with Agent Registry.
    """
    if not REGISTRY_AVAILABLE:
        return {"allowed": True, "reason": "Registry not available, allowing by default"}

    config = load_config()
    if not config.get("enterprise", {}).get("agent_registry_enabled", True):
        return {"allowed": True, "reason": "Agent registry disabled"}

    # Check if agent is approved
    agent = agent_registry.get_agent_by_model(provider, model)

    if not agent:
        # Agent not in registry
        if config.get("enterprise", {}).get("require_agent_approval", True):
            return {
                "allowed": False,
                "reason": f"Agent '{provider}/{model}' not found in registry. Contact admin for approval."
            }
        return {"allowed": True, "reason": "Agent not in registry, but approval not required"}

    if agent["status"] != AgentStatus.APPROVED.value:
        return {
            "allowed": False,
            "reason": f"Agent '{agent['name']}' is {agent['status']}. Contact admin."
        }

    # Check risk level and user permissions
    if agent["risk_level"] == RiskLevel.CRITICAL.value:
        # Could add additional checks here for critical-risk agents
        pass

    return {
        "allowed": True,
        "agent_id": agent["id"],
        "agent_name": agent["name"],
        "risk_level": agent["risk_level"]
    }

# ============== API CALLS ==============

async def call_external_api(messages: list, config: dict, override_provider: str = None,
                            override_model: str = None) -> dict:
    """Call external AI API with KMS integration."""
    provider = override_provider or config.get("active_provider", "openai")
    provider_config = config.get("providers", {}).get(provider, {})

    if not provider_config:
        return {"success": False, "error": f"Provider '{provider}' not found"}

    # Try KMS first, then fall back to config
    api_key = get_api_key(provider) if KMS_AVAILABLE else None
    if not api_key:
        api_key = provider_config.get("api_key", "")

    if not api_key or api_key.startswith("YOUR_"):
        return {
            "success": False,
            "error": f"API key not configured for {provider_config.get('name', provider)}"
        }

    model = override_model or provider_config.get("default_model")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            # OpenAI-compatible providers
            openai_compatible = [
                "openai", "deepseek", "mistral", "groq", "openrouter",
                "together", "fireworks", "perplexity"
            ]

            if provider in openai_compatible:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }

                # OpenRouter requires extra headers
                if provider == "openrouter":
                    headers["HTTP-Referer"] = "https://ai-gateway.motilal.com"
                    headers["X-Title"] = "AI Gateway Enterprise"

                response = await client.post(
                    provider_config.get("base_url"),
                    headers=headers,
                    json={
                        "model": model,
                        "messages": messages,
                        "max_tokens": 2000
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["choices"][0]["message"]["content"],
                        "provider": provider,
                        "model": model
                    }
                else:
                    return {"success": False, "error": f"API error: {response.status_code}"}

            elif provider == "claude":
                claude_messages = [m for m in messages if m["role"] != "system"]
                system = next((m["content"] for m in messages if m["role"] == "system"), "")

                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": model,
                        "max_tokens": 2000,
                        "system": system or "You are a helpful assistant.",
                        "messages": claude_messages
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["content"][0]["text"],
                        "provider": "claude",
                        "model": model
                    }
                else:
                    return {"success": False, "error": f"Claude API error: {response.status_code}"}

            elif provider == "gemini":
                url = f"{provider_config.get('base_url')}/{model}:generateContent?key={api_key}"
                gemini_contents = [
                    {"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]}
                    for m in messages
                ]

                response = await client.post(url, json={"contents": gemini_contents})

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["candidates"][0]["content"]["parts"][0]["text"],
                        "provider": "gemini",
                        "model": model
                    }
                else:
                    return {"success": False, "error": f"Gemini API error: {response.status_code}"}

            elif provider == "ollama":
                response = await client.post(
                    provider_config.get("base_url"),
                    json={"model": model, "messages": messages, "stream": False}
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["message"]["content"],
                        "provider": "ollama",
                        "model": model
                    }
                else:
                    return {"success": False, "error": f"Ollama error: {response.status_code}"}

            else:
                return {"success": False, "error": f"Provider '{provider}' not implemented"}

        except Exception as e:
            return {"success": False, "error": str(e)}

# ============== REQUEST LOGGING ==============

def log_request(request_id: str, user_id: str, action: str, route: str,
                provider: str, content: str, detections: list,
                response_preview: str = "", processing_time_ms: int = 0,
                user_role: str = "user", model: str = "", agent_id: str = ""):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO request_logs
        (request_id, timestamp, user_id, user_role, action, route, provider, model, agent_id,
         content_preview, content_hash, content_size_bytes, detections_json, response_preview, processing_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_id, now_ist().isoformat(), user_id, user_role, action, route,
        provider, model, agent_id, content[:500] if content else "",
        hashlib.sha256(content.encode()).hexdigest() if content else "",
        len(content.encode()) if content else 0, json.dumps(detections),
        response_preview[:500] if response_preview else "", processing_time_ms
    ))
    conn.commit()
    conn.close()

# ============== API MODELS ==============

class ChatRequest(BaseModel):
    messages: Optional[List[Dict[str, str]]] = None
    message: Optional[str] = None
    conversation_history: Optional[List[Dict[str, str]]] = None
    user_id: Optional[str] = "anonymous"
    provider: Optional[str] = None
    model: Optional[str] = None

class MCPAccessRequest(BaseModel):
    """Request for MCP tool access."""
    agent_id: str
    tool_id: str
    operation: str
    resource_path: str = ""
    parameters: Dict[str, Any] = {}
    user_id: str = "anonymous"
    user_permissions: List[str] = []

# ============== PAGE ENDPOINTS ==============

@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return """
        <h1>AI Gateway Enterprise v3.0</h1>
        <ul>
            <li><a href="/chat">Chat Interface</a></li>
            <li><a href="/docs">API Documentation</a></li>
            <li><a href="/api/health">Health Check</a></li>
        </ul>
        """

@app.get("/chat", response_class=HTMLResponse)
async def chat_page():
    try:
        with open("chat.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>Chat Interface</h1><p>chat.html not found</p>"

# ============== MAIN CHAT ENDPOINT ==============

@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Main chat endpoint with full enterprise security."""
    start_time = now_ist()
    request_id = str(uuid.uuid4())[:8]
    config = load_config()

    # Rate limiting
    rate_check = check_rate_limit(request.user_id)
    if not rate_check["allowed"]:
        return JSONResponse(status_code=429, content={"error": rate_check["reason"]})

    # Parse messages
    if request.message:
        messages = request.conversation_history or []
        messages.append({"role": "user", "content": request.message})
        full_content = request.message
    elif request.messages:
        messages = request.messages
        full_content = "\n".join([m.get("content", "") for m in messages])
    else:
        return JSONResponse(status_code=400, content={"error": "Message required"})

    # Determine provider and model
    provider = request.provider or config.get("active_provider", "openai")
    model = request.model or config.get("providers", {}).get(provider, {}).get("default_model", "")

    # Validate agent access
    agent_check = validate_agent_access(provider, model, request.user_id)
    if not agent_check.get("allowed", True):
        log_request(
            request_id=request_id,
            user_id=request.user_id,
            action="AGENT_BLOCKED",
            route="agent_validation",
            provider=provider,
            content=full_content,
            detections=[{"type": "agent_blocked", "reason": agent_check["reason"]}],
            model=model
        )
        return JSONResponse(
            status_code=403,
            content={
                "request_id": request_id,
                "blocked": True,
                "response": agent_check["reason"]
            }
        )

    # Scan for sensitive data
    scan_result = scan_content(full_content)
    processing_time = int((now_ist() - start_time).total_seconds() * 1000)

    if scan_result["is_sensitive"]:
        local_llm_mode = config.get("local_llm_mode", "mock")

        if local_llm_mode == "block":
            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="BLOCKED",
                route="none",
                provider="none",
                content=full_content,
                detections=scan_result["detections"],
                processing_time_ms=processing_time,
                model=model,
                agent_id=agent_check.get("agent_id", "")
            )

            return JSONResponse(
                status_code=200,
                content={
                    "request_id": request_id,
                    "blocked": True,
                    "response": "Request blocked due to sensitive data. Please rephrase without personal or confidential information.",
                    "_admin_info": {
                        "status": "BLOCKED",
                        "detections": scan_result["detections"],
                        "severity": scan_result["severity"]
                    }
                }
            )
        else:
            # Route to local LLM (mock)
            mock_response = f"""[LOCAL LLM RESPONSE]

Your request contained sensitive information and was processed by the on-premise AI model.
Data Security: Your data did NOT leave the company network.

Detected: {', '.join([d['description'] for d in scan_result['detections'][:3]])}

[This is a simulated local LLM response for the POC]"""

            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="ROUTED_LOCAL_LLM",
                route="local_llm_mock",
                provider="local_llm",
                content=full_content,
                detections=scan_result["detections"],
                response_preview=mock_response,
                processing_time_ms=processing_time,
                model="local",
                agent_id=agent_check.get("agent_id", "")
            )

            return {
                "request_id": request_id,
                "status": "ROUTED_TO_LOCAL_LLM",
                "response": mock_response,
                "data_stayed_local": True
            }
    else:
        # Clean content - route to external API
        api_result = await call_external_api(messages, config, provider, model)
        processing_time = int((now_ist() - start_time).total_seconds() * 1000)

        if api_result["success"]:
            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="ALLOWED",
                route="external_api",
                provider=api_result["provider"],
                content=full_content,
                detections=[],
                response_preview=api_result["content"],
                processing_time_ms=processing_time,
                model=api_result.get("model", ""),
                agent_id=agent_check.get("agent_id", "")
            )

            # Log telemetry
            token_stats = None
            if TELEMETRY_AVAILABLE:
                token_stats = log_token_usage(
                    request_id=request_id,
                    user_id=request.user_id,
                    provider=api_result["provider"],
                    input_text=full_content,
                    output_text=api_result["content"],
                    model=api_result.get("model", ""),
                    request_type="chat",
                    response_time_ms=processing_time
                )

            return {
                "request_id": request_id,
                "status": "ALLOWED",
                "provider": api_result["provider"],
                "model": api_result.get("model"),
                "response": api_result["content"],
                "usage": token_stats
            }
        else:
            return JSONResponse(
                status_code=502,
                content={
                    "request_id": request_id,
                    "status": "API_ERROR",
                    "error": api_result["error"]
                }
            )

# ============== AGENT REGISTRY ENDPOINTS ==============

@app.get("/api/registry/agents")
async def list_agents(
    status: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = Query(default=100, le=500)
):
    """List all registered agents."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    status_enum = AgentStatus(status) if status else None
    agents = agent_registry.list_agents(status=status_enum, provider=provider, limit=limit)
    return agents  # Return array directly for frontend compatibility

@app.post("/api/registry/agents")
async def create_agent(request: Request):
    """Register a new agent."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    try:
        body = await request.json()
        from registry.agent_registry import AIAgent, RiskLevel

        agent = AIAgent(
            name=body.get("name"),
            provider=body.get("provider"),
            model_id=body.get("model_id"),
            description=body.get("description", ""),
            risk_level=RiskLevel(body.get("risk_level", "medium")),
            permissions=body.get("permissions", ["chat.basic"]),
            owner=body.get("owner", "admin"),
            metadata=body.get("metadata", {})
        )

        result = agent_registry.register_agent(agent)
        if result.get("success"):
            return result
        else:
            return JSONResponse(status_code=400, content=result)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.get("/api/registry/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get agent details."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    agent = agent_registry.get_agent(agent_id)
    if not agent:
        return JSONResponse(status_code=404, content={"error": "Agent not found"})
    return agent

@app.post("/api/registry/agents/{agent_id}/approve")
async def approve_agent(agent_id: str, approved_by: str = "admin", reason: str = ""):
    """Approve an agent for use."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    result = agent_registry.approve_agent(agent_id, approved_by, reason)
    return result

@app.post("/api/registry/agents/{agent_id}/block")
async def block_agent(agent_id: str, blocked_by: str = "admin", reason: str = ""):
    """Block an agent from use."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    result = agent_registry.block_agent(agent_id, blocked_by, reason)
    return result

@app.get("/api/registry/summary")
async def registry_summary():
    """Get registry summary statistics."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    return agent_registry.get_registry_summary()

@app.get("/api/registry/audit")
async def registry_audit(agent_id: Optional[str] = None, limit: int = 100):
    """Get agent audit log."""
    if not REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "Agent Registry not available"})

    logs = agent_registry.get_audit_log(agent_id=agent_id, limit=limit)
    return {"audit_logs": logs, "count": len(logs)}

# ============== MCP GATEWAY ENDPOINTS ==============

@app.post("/api/mcp/access")
async def mcp_access_request(request: MCPAccessRequest):
    """
    Request access to an enterprise tool via MCP Gateway.
    This is called when an AI agent wants to access enterprise resources.
    """
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    # Get agent info
    agent_name = "Unknown"
    if REGISTRY_AVAILABLE:
        agent = agent_registry.get_agent(request.agent_id)
        agent_name = agent["name"] if agent else "Unknown"

    # Get tool info
    tool = tool_registry.get_tool(request.tool_id)
    tool_name = tool["name"] if tool else "Unknown"

    # Create MCP request
    mcp_request = MCPRequest(
        request_id=str(uuid.uuid4())[:12],
        agent_id=request.agent_id,
        agent_name=agent_name,
        tool_id=request.tool_id,
        tool_name=tool_name,
        operation=request.operation,
        resource_path=request.resource_path,
        parameters=request.parameters,
        user_id=request.user_id,
        user_permissions=request.user_permissions
    )

    # Evaluate access
    response = mcp_gateway.evaluate_request(mcp_request)
    return response.to_dict()

@app.get("/api/mcp/tools")
async def list_mcp_tools(category: Optional[str] = None):
    """List available enterprise tools."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    category_enum = MCPToolCategory(category) if category else None
    tools = tool_registry.list_tools(category=category_enum)
    return tools  # Return array directly for frontend compatibility

@app.get("/api/mcp/tools/{tool_id}")
async def get_mcp_tool(tool_id: str):
    """Get tool details."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    tool = tool_registry.get_tool(tool_id)
    if not tool:
        return JSONResponse(status_code=404, content={"error": "Tool not found"})
    return tool

@app.get("/api/mcp/access-log")
async def mcp_access_log(
    agent_id: Optional[str] = None,
    tool_id: Optional[str] = None,
    decision: Optional[str] = None,
    limit: int = 100
):
    """Get MCP access audit log."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    decision_enum = AccessDecision(decision) if decision else None
    logs = mcp_gateway.get_access_log(agent_id=agent_id, tool_id=tool_id, decision=decision_enum, limit=limit)
    return logs  # Return array directly for frontend compatibility

@app.get("/api/mcp/stats")
async def mcp_stats(days: int = 30):
    """Get MCP Gateway statistics."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    return mcp_gateway.get_access_stats(days)

@app.get("/api/mcp/pending-approvals")
async def mcp_pending_approvals():
    """Get pending MCP access approvals."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    approvals = mcp_gateway.get_pending_approvals()
    return approvals  # Return array directly for frontend compatibility

@app.post("/api/mcp/approve/{approval_id}")
async def mcp_approve(approval_id: str, reviewer: str = "admin"):
    """Approve a pending MCP access request."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    return mcp_gateway.approve_pending_request(approval_id, reviewer)

@app.post("/api/mcp/deny/{approval_id}")
async def mcp_deny(approval_id: str, reviewer: str = "admin", reason: str = ""):
    """Deny a pending MCP access request."""
    if not MCP_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "MCP Gateway not available"})

    return mcp_gateway.deny_pending_request(approval_id, reviewer, reason)

# ============== KMS ENDPOINTS ==============

@app.get("/api/kms/health")
async def kms_health():
    """Get KMS health status."""
    if not KMS_AVAILABLE:
        return {"status": "not_available", "provider": None, "secrets_count": 0, "providers": []}

    health = get_secrets_health()
    # Add configured providers list
    providers = list_configured_providers() if KMS_AVAILABLE else []
    health["providers"] = providers
    health["secrets_count"] = len(providers)
    return health

@app.get("/api/kms/providers")
async def kms_providers():
    """List providers configured in KMS."""
    if not KMS_AVAILABLE:
        return {"providers": [], "count": 0}
    providers = list_configured_providers()
    return {"providers": providers, "count": len(providers)}

@app.post("/api/kms/migrate")
async def kms_migrate():
    """Migrate API keys from config.json to KMS vault."""
    if not KMS_AVAILABLE:
        return JSONResponse(status_code=503, content={"error": "KMS not available"})
    result = migrate_config_to_vault("config.json")
    return result

@app.post("/api/kms/init")
async def kms_init(request: Request):
    """Initialize KMS with a specific provider."""
    try:
        body = await request.json()
        provider = body.get("provider", "local")
        vault_url = body.get("vault_url")
        region = body.get("region", "ap-south-1")

        success = init_secrets_manager(
            provider=provider,
            vault_url=vault_url,
            region=region
        )

        if success:
            return {"success": True, "provider": provider}
        else:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Failed to initialize {provider}"}
            )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )

# ============== STANDARD ENDPOINTS ==============

@app.get("/api/providers")
async def get_providers():
    """Get all available AI providers."""
    config = load_config()
    providers = config.get("providers", {})

    safe_providers = {}
    for key, provider in providers.items():
        api_key = provider.get("api_key", "")
        kms_configured = get_api_key(key) is not None if KMS_AVAILABLE else False
        is_configured = (api_key and not api_key.startswith("YOUR_")) or kms_configured

        safe_providers[key] = {
            "name": provider.get("name"),
            "enabled": provider.get("enabled", True),
            "configured": is_configured,
            "kms_configured": kms_configured,
            "default_model": provider.get("default_model"),
            "models": provider.get("models", []),
            "is_local": provider.get("is_local", False)
        }

    return {
        "providers": safe_providers,
        "active_provider": config.get("active_provider"),
        "count": len(providers)
    }

@app.get("/api/config")
async def get_config():
    """Get current configuration (hides API keys)."""
    config = load_config()
    safe_config = config.copy()

    if "providers" in safe_config:
        for provider in safe_config["providers"]:
            if "api_key" in safe_config["providers"][provider]:
                key = safe_config["providers"][provider]["api_key"]
                kms_configured = get_api_key(provider) is not None if KMS_AVAILABLE else False
                if kms_configured:
                    safe_config["providers"][provider]["api_key"] = "***KMS_CONFIGURED***"
                elif key and not key.startswith("YOUR_"):
                    safe_config["providers"][provider]["api_key"] = "***CONFIGURED***"
                else:
                    safe_config["providers"][provider]["api_key"] = "NOT_CONFIGURED"

    return safe_config

@app.post("/api/scan")
async def test_scan(content: str):
    """Test endpoint to scan content."""
    scan_result = scan_content(content)
    return {
        "scan_result": scan_result,
        "would_route_to": "local_llm" if scan_result["is_sensitive"] else "external_api"
    }

@app.get("/api/logs")
async def get_logs(limit: int = 100, action: str = None):
    """Get request logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM request_logs WHERE 1=1"
    params = []

    if action:
        query += " AND action = ?"
        params.append(action)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for log in logs:
        if log.get("detections_json"):
            log["detections"] = json.loads(log["detections_json"])
            del log["detections_json"]

    return {"logs": logs, "count": len(logs)}

@app.get("/api/health")
async def health_check():
    """Comprehensive health check."""
    config = load_config()
    providers = config.get("providers", {})
    configured_count = sum(1 for p in providers.values() if p.get("api_key") and not p["api_key"].startswith("YOUR_"))

    return {
        "status": "healthy",
        "timestamp": now_ist().isoformat(),
        "version": "3.0.0",
        "active_provider": config.get("active_provider"),
        "configured_providers": configured_count,
        "modules": {
            "kms": KMS_AVAILABLE,
            "agent_registry": REGISTRY_AVAILABLE,
            "mcp_gateway": MCP_AVAILABLE,
            "telemetry": TELEMETRY_AVAILABLE,
            "auth": AUTH_MODULES_AVAILABLE
        }
    }

# ============== RUN SERVER ==============

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("   AI Gateway Enterprise v3.0 - Starting Server")
    print("="*60)
    print(f"\n   Dashboard: http://localhost:8000")
    print(f"   Chat:      http://localhost:8000/chat")
    print(f"   API Docs:  http://localhost:8000/docs")
    print("\n" + "="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
