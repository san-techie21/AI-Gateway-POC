"""
AI Gateway POC - Enterprise AI Security Layer
Motilal Oswal Financial Services

This gateway intercepts all AI requests, scans for sensitive data,
and routes appropriately (block/mock local LLM/external API).
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import httpx
import re
import json
import sqlite3
import hashlib
import uuid
import os

# ============== APP SETUP ==============

app = FastAPI(
    title="AI Gateway POC",
    description="Enterprise AI Security Layer - Motilal Oswal",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============== CONFIGURATION ==============

CONFIG_FILE = "config.json"

def load_config() -> dict:
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}

def save_config(config: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# ============== PII DETECTION PATTERNS ==============

DETECTION_PATTERNS = {
    "aadhaar": {
        "pattern": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
        "description": "Aadhaar Number (Indian ID)",
        "severity": "CRITICAL",
        "example": "2345 6789 0123"
    },
    "pan": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "description": "PAN Card Number",
        "severity": "CRITICAL",
        "example": "ABCDE1234F"
    },
    "phone_india": {
        "pattern": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        "description": "Indian Phone Number",
        "severity": "HIGH",
        "example": "+91 98765 43210"
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "description": "Email Address",
        "severity": "MEDIUM",
        "example": "user@example.com"
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "description": "Credit Card Number",
        "severity": "CRITICAL",
        "example": "4111111111111111"
    },
    "ifsc": {
        "pattern": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "description": "IFSC Code",
        "severity": "MEDIUM",
        "example": "SBIN0001234"
    },
    "demat": {
        "pattern": r"\b(IN|in)[0-9]{14}\b",
        "description": "Demat Account Number",
        "severity": "HIGH",
        "example": "IN12345678901234"
    },
    "passport": {
        "pattern": r"\b[A-Z][0-9]{7}\b",
        "description": "Passport Number",
        "severity": "HIGH",
        "example": "A1234567"
    },
    "api_key_generic": {
        "pattern": r"(?:api[_-]?key|apikey|api_secret|secret_key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
        "description": "API Key/Secret",
        "severity": "CRITICAL",
        "example": "api_key='abc123xyz456...'"
    },
    "aws_access_key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "description": "AWS Access Key",
        "severity": "CRITICAL",
        "example": "AKIAIOSFODNN7EXAMPLE"
    },
    "aws_secret_key": {
        "pattern": r"(?:aws_secret|secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        "description": "AWS Secret Key",
        "severity": "CRITICAL",
        "example": "aws_secret='wJalrXUtnFEMI/K7MDENG/...'"
    },
    "private_key": {
        "pattern": r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        "description": "Private Key",
        "severity": "CRITICAL",
        "example": "-----BEGIN PRIVATE KEY-----"
    },
    "db_connection": {
        "pattern": r"(?:mysql|postgres|postgresql|mongodb|redis|sqlserver)://[^\s\"']+",
        "description": "Database Connection String",
        "severity": "CRITICAL",
        "example": "mysql://user:pass@host/db"
    },
    "jwt_token": {
        "pattern": r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
        "description": "JWT Token",
        "severity": "HIGH",
        "example": "eyJhbGciOiJIUzI1NiIs..."
    },
    "gstin": {
        "pattern": r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b",
        "description": "GSTIN Number",
        "severity": "MEDIUM",
        "example": "22AAAAA0000A1Z5"
    }
}

# ============== DATABASE SETUP ==============

DB_FILE = "gateway_logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            action TEXT NOT NULL,
            route TEXT,
            provider TEXT,
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON request_logs(user_id)")
    conn.commit()
    conn.close()

init_db()

def log_request(
    request_id: str,
    user_id: str,
    action: str,
    route: str,
    provider: str,
    content: str,
    detections: list,
    response_preview: str = "",
    processing_time_ms: int = 0
):
    conn = sqlite3.connect(DB_FILE)
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    conn.execute("""
        INSERT INTO request_logs
        (request_id, timestamp, user_id, action, route, provider, content_preview,
         content_hash, content_size_bytes, detections_json, response_preview, processing_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_id,
        datetime.now().isoformat(),
        user_id,
        action,
        route,
        provider,
        content[:500] if content else "",
        content_hash,
        len(content.encode()) if content else 0,
        json.dumps(detections),
        response_preview[:500] if response_preview else "",
        processing_time_ms
    ))
    conn.commit()
    conn.close()

    # Console logging
    config = load_config()
    if config.get("alerts", {}).get("log_to_console", True):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {action} | User: {user_id} | Route: {route} | Detections: {len(detections)}")

# ============== RATE LIMITING ==============

user_requests = defaultdict(list)

def check_rate_limit(user_id: str) -> dict:
    config = load_config()
    rate_config = config.get("rate_limiting", {})

    if not rate_config.get("enabled", False):
        return {"allowed": True}

    now = datetime.now()

    # Clean old requests
    user_requests[user_id] = [
        req_time for req_time in user_requests[user_id]
        if req_time > now - timedelta(hours=1)
    ]

    requests = user_requests[user_id]
    minute_ago = now - timedelta(minutes=1)

    reqs_last_minute = sum(1 for t in requests if t > minute_ago)
    reqs_last_hour = len(requests)

    if reqs_last_minute >= rate_config.get("requests_per_minute", 20):
        return {"allowed": False, "reason": "Rate limit exceeded (per minute)"}

    if reqs_last_hour >= rate_config.get("requests_per_hour", 200):
        return {"allowed": False, "reason": "Rate limit exceeded (per hour)"}

    user_requests[user_id].append(now)
    return {"allowed": True}

# ============== SCANNING LOGIC ==============

def scan_content(text: str) -> dict:
    """Scan text for sensitive data patterns."""
    config = load_config()

    results = {
        "is_sensitive": False,
        "detections": [],
        "severity": "NONE",
        "size_check": {"passed": True},
        "keyword_check": {"passed": True},
        "code_check": {"passed": True}
    }

    if not text:
        return results

    # 1. Check content size
    size_config = config.get("file_size_limits", {})
    max_size_mb = size_config.get("max_content_size_mb", 1)
    size_mb = len(text.encode('utf-8')) / (1024 * 1024)

    if size_mb > max_size_mb:
        results["is_sensitive"] = True
        results["severity"] = "CRITICAL"
        results["size_check"] = {
            "passed": False,
            "size_mb": round(size_mb, 2),
            "limit_mb": max_size_mb
        }
        results["detections"].append({
            "type": "file_size_exceeded",
            "description": f"Content size ({size_mb:.2f}MB) exceeds limit ({max_size_mb}MB)",
            "severity": "CRITICAL"
        })

    # 2. Check blocked keywords
    blocked_keywords = config.get("blocked_keywords", [])
    text_lower = text.lower()

    for keyword in blocked_keywords:
        if keyword.lower() in text_lower:
            results["is_sensitive"] = True
            if results["severity"] != "CRITICAL":
                results["severity"] = "HIGH"
            results["keyword_check"]["passed"] = False
            results["detections"].append({
                "type": "blocked_keyword",
                "description": f"Contains blocked keyword: '{keyword}'",
                "severity": "HIGH",
                "matched": keyword
            })

    # 3. Check PII patterns
    for pattern_name, pattern_info in DETECTION_PATTERNS.items():
        matches = re.findall(pattern_info["pattern"], text, re.IGNORECASE)
        if matches:
            results["is_sensitive"] = True

            # Update overall severity
            pattern_severity = pattern_info["severity"]
            if pattern_severity == "CRITICAL":
                results["severity"] = "CRITICAL"
            elif pattern_severity == "HIGH" and results["severity"] not in ["CRITICAL"]:
                results["severity"] = "HIGH"
            elif pattern_severity == "MEDIUM" and results["severity"] not in ["CRITICAL", "HIGH"]:
                results["severity"] = "MEDIUM"

            results["detections"].append({
                "type": pattern_name,
                "description": pattern_info["description"],
                "severity": pattern_severity,
                "count": len(matches),
                "example": pattern_info.get("example", "")
            })

    # 4. Check for code blocks
    code_config = config.get("code_detection", {})
    if code_config.get("enabled", True):
        code_indicators = [
            r"^(import |from .+ import |#include |using |package )",
            r"^(def |function |class |public |private |const |let |var )",
            r"^\s*(if|else|for|while|switch|try|catch|finally)\s*[\(\{:]",
            r"(=>|->|\|\||&&|===|!==)",
            r"[\{\}].*;$"
        ]

        lines = text.split('\n')
        code_line_count = 0

        for line in lines:
            for pattern in code_indicators:
                if re.search(pattern, line):
                    code_line_count += 1
                    break

        block_threshold = code_config.get("block_lines", 50)
        warn_threshold = code_config.get("warn_lines", 10)

        if code_line_count >= block_threshold:
            results["is_sensitive"] = True
            results["severity"] = "HIGH"
            results["code_check"] = {
                "passed": False,
                "code_lines": code_line_count,
                "threshold": block_threshold
            }
            results["detections"].append({
                "type": "large_code_block",
                "description": f"Large code block detected ({code_line_count} lines)",
                "severity": "HIGH",
                "code_lines": code_line_count
            })
        elif code_line_count >= warn_threshold:
            results["code_check"] = {
                "passed": True,
                "warning": True,
                "code_lines": code_line_count
            }
            results["detections"].append({
                "type": "code_block_warning",
                "description": f"Code block detected ({code_line_count} lines) - Warning only",
                "severity": "LOW",
                "code_lines": code_line_count
            })

    # 5. Check company-specific patterns
    company_patterns = config.get("company_patterns", {})

    if company_patterns.get("employee_id"):
        emp_matches = re.findall(company_patterns["employee_id"], text, re.IGNORECASE)
        if emp_matches:
            results["is_sensitive"] = True
            results["severity"] = "HIGH"
            results["detections"].append({
                "type": "employee_id",
                "description": "Employee ID detected",
                "severity": "HIGH",
                "count": len(emp_matches)
            })

    if company_patterns.get("client_code"):
        client_matches = re.findall(company_patterns["client_code"], text)
        if client_matches:
            results["is_sensitive"] = True
            results["severity"] = "HIGH"
            results["detections"].append({
                "type": "client_code",
                "description": "Client code detected",
                "severity": "HIGH",
                "count": len(client_matches)
            })

    internal_systems = company_patterns.get("internal_systems", [])
    for system in internal_systems:
        if system.lower() in text_lower:
            results["detections"].append({
                "type": "internal_system_reference",
                "description": f"Internal system reference: {system}",
                "severity": "LOW",
                "matched": system
            })

    return results

# ============== LOCAL LLM MOCK ==============

def get_mock_local_llm_response(content: str, detections: list) -> str:
    """Generate a mock response simulating local LLM."""
    detection_summary = ", ".join([d["description"] for d in detections[:3]])

    return f"""[LOCAL LLM RESPONSE - SIMULATED]

Your request contained sensitive information and was processed by the on-premise AI model.
Data Security: Your data did NOT leave the company network.

Detected sensitive elements: {detection_summary}

---
SIMULATED RESPONSE:

I understand you're asking about information that contains sensitive data. In a production environment, this would be processed by our secure on-premise Llama/Mistral model.

For this POC demo, I'm simulating the local LLM response. The key points are:
1. Your sensitive data was detected and intercepted
2. The request was NOT sent to external APIs (OpenAI/Claude)
3. In production, a real local LLM would process this securely

If you have questions that don't contain sensitive data, they will be routed to the external AI for faster, more capable responses.

---
[End of Local LLM Simulation]"""

# ============== EXTERNAL API CALLS ==============

async def call_external_api(messages: list, config: dict) -> dict:
    """Call external AI API (OpenAI or Claude)."""
    provider = config.get("active_provider", "openai")
    provider_config = config.get("providers", {}).get(provider, {})

    api_key = provider_config.get("api_key", "")

    if not api_key or api_key.startswith("YOUR_"):
        return {
            "success": False,
            "error": f"API key not configured for {provider}. Please update config.json"
        }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            if provider == "openai":
                response = await client.post(
                    provider_config.get("base_url", "https://api.openai.com/v1/chat/completions"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model", "gpt-4o-mini"),
                        "messages": messages,
                        "max_tokens": 2000
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["choices"][0]["message"]["content"],
                        "provider": "openai",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"OpenAI API error: {response.status_code} - {response.text}"
                    }

            elif provider == "claude":
                # Convert messages format for Claude
                claude_messages = []
                for msg in messages:
                    if msg["role"] != "system":
                        claude_messages.append({
                            "role": msg["role"],
                            "content": msg["content"]
                        })

                system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")

                response = await client.post(
                    provider_config.get("base_url", "https://api.anthropic.com/v1/messages"),
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model", "claude-3-5-sonnet-20241022"),
                        "max_tokens": 2000,
                        "system": system_msg if system_msg else "You are a helpful assistant.",
                        "messages": claude_messages
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["content"][0]["text"],
                        "provider": "claude",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Claude API error: {response.status_code} - {response.text}"
                    }

            else:
                return {"success": False, "error": f"Unknown provider: {provider}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

# ============== API MODELS ==============

class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    user_id: Optional[str] = "anonymous"
    provider: Optional[str] = None  # Override default provider

class ConfigUpdate(BaseModel):
    active_provider: Optional[str] = None
    local_llm_mode: Optional[str] = None  # "mock" or "block"
    blocked_keywords: Optional[List[str]] = None
    max_content_size_mb: Optional[float] = None
    openai_api_key: Optional[str] = None
    claude_api_key: Optional[str] = None

class TestScanRequest(BaseModel):
    content: str

# ============== API ENDPOINTS ==============

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve admin dashboard."""
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>AI Gateway POC</h1><p>Admin dashboard not found. Please ensure admin.html is in the same directory.</p>"

@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Main chat endpoint - scans and routes requests."""
    start_time = datetime.now()
    request_id = str(uuid.uuid4())[:8]
    config = load_config()

    # Rate limiting
    rate_check = check_rate_limit(request.user_id)
    if not rate_check["allowed"]:
        return JSONResponse(
            status_code=429,
            content={
                "error": rate_check["reason"],
                "request_id": request_id
            }
        )

    # Extract full content
    full_content = "\n".join([msg.get("content", "") for msg in request.messages])

    # Scan for sensitive data
    scan_result = scan_content(full_content)

    processing_time = int((datetime.now() - start_time).total_seconds() * 1000)

    # Determine routing
    if scan_result["is_sensitive"]:
        local_llm_mode = config.get("local_llm_mode", "mock")

        if local_llm_mode == "block":
            # BLOCK mode - reject the request
            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="BLOCKED",
                route="none",
                provider="none",
                content=full_content,
                detections=scan_result["detections"],
                processing_time_ms=processing_time
            )

            return JSONResponse(
                status_code=403,
                content={
                    "request_id": request_id,
                    "status": "BLOCKED",
                    "message": "Request blocked due to sensitive content",
                    "detections": scan_result["detections"],
                    "severity": scan_result["severity"],
                    "suggestion": "Please remove sensitive information and try again.",
                    "note": "In production with Local LLM, this would be processed securely on-premise."
                }
            )

        else:
            # MOCK mode - simulate local LLM response
            mock_response = get_mock_local_llm_response(full_content, scan_result["detections"])

            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="ROUTED_LOCAL_LLM",
                route="local_llm_mock",
                provider="local_llm_simulated",
                content=full_content,
                detections=scan_result["detections"],
                response_preview=mock_response,
                processing_time_ms=processing_time
            )

            return {
                "request_id": request_id,
                "status": "ROUTED_TO_LOCAL_LLM",
                "message": "Sensitive data detected - routed to local LLM (simulated for POC)",
                "detections": scan_result["detections"],
                "severity": scan_result["severity"],
                "response": mock_response,
                "data_stayed_local": True
            }

    else:
        # Clean content - route to external API
        provider = request.provider or config.get("active_provider", "openai")
        api_result = await call_external_api(request.messages, config)

        processing_time = int((datetime.now() - start_time).total_seconds() * 1000)

        if api_result["success"]:
            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="ALLOWED",
                route="external_api",
                provider=api_result["provider"],
                content=full_content,
                detections=scan_result["detections"],
                response_preview=api_result["content"],
                processing_time_ms=processing_time
            )

            return {
                "request_id": request_id,
                "status": "ALLOWED",
                "message": "No sensitive data detected - processed by external API",
                "provider": api_result["provider"],
                "model": api_result.get("model"),
                "response": api_result["content"],
                "scan_result": {
                    "is_sensitive": False,
                    "detections": scan_result["detections"]  # May have warnings
                }
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

@app.post("/api/scan")
async def test_scan(request: TestScanRequest):
    """Test endpoint to scan content without sending to any API."""
    scan_result = scan_content(request.content)
    config = load_config()

    return {
        "scan_result": scan_result,
        "would_route_to": "local_llm" if scan_result["is_sensitive"] else "external_api",
        "local_llm_mode": config.get("local_llm_mode", "mock"),
        "content_size_bytes": len(request.content.encode()),
        "content_size_kb": round(len(request.content.encode()) / 1024, 2)
    }

@app.get("/api/config")
async def get_config():
    """Get current configuration (hides API keys)."""
    config = load_config()

    # Hide sensitive keys
    safe_config = config.copy()
    if "providers" in safe_config:
        for provider in safe_config["providers"]:
            if "api_key" in safe_config["providers"][provider]:
                key = safe_config["providers"][provider]["api_key"]
                if key and not key.startswith("YOUR_"):
                    safe_config["providers"][provider]["api_key"] = key[:8] + "..." + key[-4:]
                else:
                    safe_config["providers"][provider]["api_key"] = "NOT_CONFIGURED"

    return safe_config

@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    """Update configuration."""
    config = load_config()

    if update.active_provider:
        config["active_provider"] = update.active_provider

    if update.local_llm_mode:
        config["local_llm_mode"] = update.local_llm_mode

    if update.blocked_keywords is not None:
        config["blocked_keywords"] = update.blocked_keywords

    if update.max_content_size_mb is not None:
        config["file_size_limits"]["max_content_size_mb"] = update.max_content_size_mb

    if update.openai_api_key:
        config["providers"]["openai"]["api_key"] = update.openai_api_key

    if update.claude_api_key:
        config["providers"]["claude"]["api_key"] = update.claude_api_key

    save_config(config)
    return {"status": "updated", "message": "Configuration updated successfully"}

@app.get("/api/logs")
async def get_logs(limit: int = 100, action: str = None):
    """Get request logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM request_logs"
    params = []

    if action:
        query += " WHERE action = ?"
        params.append(action)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    # Parse detections JSON
    for log in logs:
        if log.get("detections_json"):
            log["detections"] = json.loads(log["detections_json"])
            del log["detections_json"]

    return {"logs": logs, "count": len(logs)}

@app.get("/api/logs/stats")
async def get_log_stats():
    """Get log statistics."""
    conn = sqlite3.connect(DB_FILE)

    stats = {}

    # Total requests
    cursor = conn.execute("SELECT COUNT(*) FROM request_logs")
    stats["total_requests"] = cursor.fetchone()[0]

    # By action
    cursor = conn.execute("""
        SELECT action, COUNT(*) as count
        FROM request_logs
        GROUP BY action
    """)
    stats["by_action"] = {row[0]: row[1] for row in cursor.fetchall()}

    # By provider
    cursor = conn.execute("""
        SELECT provider, COUNT(*) as count
        FROM request_logs
        WHERE provider IS NOT NULL AND provider != 'none'
        GROUP BY provider
    """)
    stats["by_provider"] = {row[0]: row[1] for row in cursor.fetchall()}

    # Recent 24h
    cursor = conn.execute("""
        SELECT COUNT(*) FROM request_logs
        WHERE timestamp > datetime('now', '-24 hours')
    """)
    stats["last_24h"] = cursor.fetchone()[0]

    # Detection types
    cursor = conn.execute("SELECT detections_json FROM request_logs WHERE detections_json != '[]'")
    detection_counts = defaultdict(int)
    for row in cursor.fetchall():
        detections = json.loads(row[0])
        for d in detections:
            detection_counts[d.get("type", "unknown")] += 1
    stats["detection_types"] = dict(detection_counts)

    conn.close()
    return stats

@app.delete("/api/logs")
async def clear_logs():
    """Clear all logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM request_logs")
    conn.commit()
    conn.close()
    return {"status": "cleared", "message": "All logs cleared"}

@app.get("/api/patterns")
async def get_patterns():
    """Get all detection patterns."""
    return {
        "patterns": DETECTION_PATTERNS,
        "count": len(DETECTION_PATTERNS)
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    config = load_config()

    openai_configured = config.get("providers", {}).get("openai", {}).get("api_key", "").startswith("sk-")
    claude_configured = config.get("providers", {}).get("claude", {}).get("api_key", "").startswith("sk-ant")

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "config": {
            "active_provider": config.get("active_provider"),
            "local_llm_mode": config.get("local_llm_mode"),
            "openai_configured": openai_configured,
            "claude_configured": claude_configured
        }
    }

# ============== FILE UPLOAD ENDPOINT ==============

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), user_id: str = "anonymous"):
    """Handle file uploads with scanning."""
    request_id = str(uuid.uuid4())[:8]
    config = load_config()

    # Read file content
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)

    # Check size limit
    max_size = config.get("file_size_limits", {}).get("max_file_upload_mb", 1)
    if size_mb > max_size:
        log_request(
            request_id=request_id,
            user_id=user_id,
            action="BLOCKED",
            route="file_upload",
            provider="none",
            content=f"[FILE: {file.filename}, SIZE: {size_mb:.2f}MB]",
            detections=[{"type": "file_size", "description": f"File exceeds {max_size}MB limit"}]
        )

        return JSONResponse(
            status_code=413,
            content={
                "request_id": request_id,
                "status": "BLOCKED",
                "reason": f"File size ({size_mb:.2f}MB) exceeds limit ({max_size}MB)",
                "filename": file.filename
            }
        )

    # Try to decode as text for scanning
    try:
        text_content = content.decode('utf-8')
        scan_result = scan_content(text_content)
    except:
        # Binary file - just check size
        scan_result = {"is_sensitive": False, "detections": []}

    if scan_result["is_sensitive"]:
        log_request(
            request_id=request_id,
            user_id=user_id,
            action="BLOCKED",
            route="file_upload",
            provider="none",
            content=f"[FILE: {file.filename}]",
            detections=scan_result["detections"]
        )

        return JSONResponse(
            status_code=403,
            content={
                "request_id": request_id,
                "status": "BLOCKED",
                "reason": "File contains sensitive data",
                "filename": file.filename,
                "detections": scan_result["detections"]
            }
        )

    return {
        "request_id": request_id,
        "status": "ALLOWED",
        "filename": file.filename,
        "size_mb": round(size_mb, 2),
        "message": "File passed security scan"
    }

# ============== RUN SERVER ==============

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("   AI Gateway POC - Starting Server")
    print("="*60)
    print(f"\n   Dashboard: http://localhost:8000")
    print(f"   API Docs:  http://localhost:8000/docs")
    print("\n" + "="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
