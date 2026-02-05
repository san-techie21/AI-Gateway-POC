"""
AI Gateway POC - Enterprise AI Security Layer
Motilal Oswal Financial Services

This gateway intercepts all AI requests, scans for sensitive data,
and routes appropriately (block/mock local LLM/external API).

Features:
- 29 AI Provider Support including:
  * Major LLMs: OpenAI, Claude, Gemini, DeepSeek, Mistral, Grok, Cohere, AI21
  * Chinese LLMs: GLM (ChatGLM), Qwen, Baichuan, Moonshot, Yi
  * Fast Inference: Groq, Cerebras, Lepton, SambaNova, Fireworks, Together
  * Multi-Provider: OpenRouter, DeepInfra, Novita, OctoAI
  * Enterprise: Azure OpenAI, AWS Bedrock, HuggingFace, Replicate
  * Local: Ollama
- Mock AD/SSO Authentication
- Enterprise Integration Points (Webhooks, SIEM, Email, Teams/Slack)
- Role-Based Access Control
- Comprehensive PII Detection
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
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
    version="2.0.0"
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

DEFAULT_CONFIG = {
    "active_provider": "openai",
    "local_llm_mode": "mock",
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
            "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "codestral-latest", "open-mixtral-8x22b", "open-mixtral-8x7b"],
            "enabled": True
        },
        "grok": {
            "name": "xAI Grok",
            "api_key": "YOUR_GROK_API_KEY",
            "base_url": "https://api.x.ai/v1/chat/completions",
            "default_model": "grok-beta",
            "models": ["grok-beta", "grok-2", "grok-2-mini"],
            "enabled": True
        },
        "cohere": {
            "name": "Cohere",
            "api_key": "YOUR_COHERE_API_KEY",
            "base_url": "https://api.cohere.ai/v1/chat",
            "default_model": "command-r-plus",
            "models": ["command-r-plus", "command-r", "command", "command-light"],
            "enabled": True
        },
        "ai21": {
            "name": "AI21 Labs",
            "api_key": "YOUR_AI21_API_KEY",
            "base_url": "https://api.ai21.com/studio/v1/chat/completions",
            "default_model": "jamba-1.5-large",
            "models": ["jamba-1.5-large", "jamba-1.5-mini", "j2-ultra", "j2-mid"],
            "enabled": True
        },
        "perplexity": {
            "name": "Perplexity AI",
            "api_key": "YOUR_PERPLEXITY_API_KEY",
            "base_url": "https://api.perplexity.ai/chat/completions",
            "default_model": "llama-3.1-sonar-large-128k-online",
            "models": ["llama-3.1-sonar-large-128k-online", "llama-3.1-sonar-small-128k-online", "llama-3.1-sonar-huge-128k-online"],
            "enabled": True
        },
        "together": {
            "name": "Together AI",
            "api_key": "YOUR_TOGETHER_API_KEY",
            "base_url": "https://api.together.xyz/v1/chat/completions",
            "default_model": "meta-llama/Llama-3.2-90B-Vision-Instruct-Turbo",
            "models": ["meta-llama/Llama-3.2-90B-Vision-Instruct-Turbo", "meta-llama/Llama-3.1-405B-Instruct-Turbo", "mistralai/Mixtral-8x22B-Instruct-v0.1"],
            "enabled": True
        },
        "groq": {
            "name": "Groq (Fast Inference)",
            "api_key": "YOUR_GROQ_API_KEY",
            "base_url": "https://api.groq.com/openai/v1/chat/completions",
            "default_model": "llama-3.3-70b-versatile",
            "models": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
            "enabled": True
        },
        "fireworks": {
            "name": "Fireworks AI",
            "api_key": "YOUR_FIREWORKS_API_KEY",
            "base_url": "https://api.fireworks.ai/inference/v1/chat/completions",
            "default_model": "accounts/fireworks/models/llama-v3p1-405b-instruct",
            "models": ["accounts/fireworks/models/llama-v3p1-405b-instruct", "accounts/fireworks/models/llama-v3p1-70b-instruct"],
            "enabled": True
        },
        "glm": {
            "name": "Zhipu GLM (ChatGLM)",
            "api_key": "YOUR_GLM_API_KEY",
            "base_url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "default_model": "glm-4-plus",
            "models": ["glm-4-plus", "glm-4", "glm-4-air", "glm-4-flash", "glm-4v-plus"],
            "enabled": True
        },
        "azure_openai": {
            "name": "Azure OpenAI",
            "api_key": "YOUR_AZURE_OPENAI_API_KEY",
            "base_url": "https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2024-02-15-preview",
            "default_model": "gpt-4o",
            "models": ["gpt-4o", "gpt-4", "gpt-35-turbo"],
            "enabled": True,
            "requires_resource_name": True
        },
        "aws_bedrock": {
            "name": "AWS Bedrock",
            "api_key": "YOUR_AWS_ACCESS_KEY",
            "secret_key": "YOUR_AWS_SECRET_KEY",
            "region": "us-east-1",
            "default_model": "anthropic.claude-3-sonnet-20240229-v1:0",
            "models": ["anthropic.claude-3-sonnet-20240229-v1:0", "anthropic.claude-3-haiku-20240307-v1:0", "amazon.titan-text-express-v1"],
            "enabled": True,
            "requires_aws_auth": True
        },
        "huggingface": {
            "name": "Hugging Face Inference",
            "api_key": "YOUR_HF_API_KEY",
            "base_url": "https://api-inference.huggingface.co/models",
            "default_model": "meta-llama/Llama-3.2-3B-Instruct",
            "models": ["meta-llama/Llama-3.2-3B-Instruct", "mistralai/Mistral-7B-Instruct-v0.2", "microsoft/Phi-3-mini-4k-instruct"],
            "enabled": True
        },
        "replicate": {
            "name": "Replicate",
            "api_key": "YOUR_REPLICATE_API_KEY",
            "base_url": "https://api.replicate.com/v1/predictions",
            "default_model": "meta/llama-2-70b-chat",
            "models": ["meta/llama-2-70b-chat", "mistralai/mixtral-8x7b-instruct-v0.1"],
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
        },
        "openrouter": {
            "name": "OpenRouter (Multi-Provider)",
            "api_key": "YOUR_OPENROUTER_API_KEY",
            "base_url": "https://openrouter.ai/api/v1/chat/completions",
            "default_model": "anthropic/claude-3.5-sonnet",
            "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "google/gemini-pro-1.5", "meta-llama/llama-3.1-405b-instruct"],
            "enabled": True
        },
        "moonshot": {
            "name": "Moonshot AI (Kimi)",
            "api_key": "YOUR_MOONSHOT_API_KEY",
            "base_url": "https://api.moonshot.cn/v1/chat/completions",
            "default_model": "moonshot-v1-128k",
            "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
            "enabled": True
        },
        "baichuan": {
            "name": "Baichuan AI",
            "api_key": "YOUR_BAICHUAN_API_KEY",
            "base_url": "https://api.baichuan-ai.com/v1/chat/completions",
            "default_model": "Baichuan4",
            "models": ["Baichuan4", "Baichuan3-Turbo", "Baichuan2-Turbo"],
            "enabled": True
        },
        "qwen": {
            "name": "Alibaba Qwen",
            "api_key": "YOUR_QWEN_API_KEY",
            "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            "default_model": "qwen-max",
            "models": ["qwen-max", "qwen-plus", "qwen-turbo", "qwen-long"],
            "enabled": True
        },
        "yi": {
            "name": "01.AI Yi",
            "api_key": "YOUR_YI_API_KEY",
            "base_url": "https://api.01.ai/v1/chat/completions",
            "default_model": "yi-large",
            "models": ["yi-large", "yi-medium", "yi-spark"],
            "enabled": True
        },
        "cerebras": {
            "name": "Cerebras (Ultra-Fast Inference)",
            "api_key": "YOUR_CEREBRAS_API_KEY",
            "base_url": "https://api.cerebras.ai/v1/chat/completions",
            "default_model": "llama3.1-70b",
            "models": ["llama3.1-70b", "llama3.1-8b", "llama-3.3-70b"],
            "enabled": True
        },
        "lepton": {
            "name": "Lepton AI (Fast Inference)",
            "api_key": "YOUR_LEPTON_API_KEY",
            "base_url": "https://llama3-1-405b.lepton.run/api/v1/chat/completions",
            "default_model": "llama3.1-405b",
            "models": ["llama3.1-405b", "llama3.1-70b", "mixtral-8x7b"],
            "enabled": True
        },
        "sambanova": {
            "name": "SambaNova (Enterprise Inference)",
            "api_key": "YOUR_SAMBANOVA_API_KEY",
            "base_url": "https://api.sambanova.ai/v1/chat/completions",
            "default_model": "Meta-Llama-3.1-405B-Instruct",
            "models": ["Meta-Llama-3.1-405B-Instruct", "Meta-Llama-3.1-70B-Instruct", "Meta-Llama-3.1-8B-Instruct"],
            "enabled": True
        },
        "novita": {
            "name": "Novita AI (Inference Marketplace)",
            "api_key": "YOUR_NOVITA_API_KEY",
            "base_url": "https://api.novita.ai/v3/openai/chat/completions",
            "default_model": "meta-llama/llama-3.1-70b-instruct",
            "models": ["meta-llama/llama-3.1-70b-instruct", "meta-llama/llama-3.1-405b-instruct", "mistralai/mistral-nemo-instruct"],
            "enabled": True
        },
        "deepinfra": {
            "name": "DeepInfra (Inference Platform)",
            "api_key": "YOUR_DEEPINFRA_API_KEY",
            "base_url": "https://api.deepinfra.com/v1/openai/chat/completions",
            "default_model": "meta-llama/Meta-Llama-3.1-70B-Instruct",
            "models": ["meta-llama/Meta-Llama-3.1-70B-Instruct", "meta-llama/Meta-Llama-3.1-405B-Instruct", "mistralai/Mixtral-8x22B-Instruct-v0.1"],
            "enabled": True
        },
        "octoai": {
            "name": "OctoAI (Optimized Inference)",
            "api_key": "YOUR_OCTOAI_API_KEY",
            "base_url": "https://text.octoai.run/v1/chat/completions",
            "default_model": "meta-llama-3.1-70b-instruct",
            "models": ["meta-llama-3.1-70b-instruct", "meta-llama-3.1-405b-instruct", "mixtral-8x22b-instruct"],
            "enabled": True
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
    },
    "integrations": {
        "webhooks": {
            "enabled": False,
            "endpoints": [],
            "events": ["violation", "critical_detection", "rate_limit_exceeded"]
        },
        "siem": {
            "enabled": False,
            "type": "splunk",
            "endpoint": "",
            "token": ""
        },
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "recipients": []
        },
        "teams": {
            "enabled": False,
            "webhook_url": ""
        },
        "slack": {
            "enabled": False,
            "webhook_url": ""
        }
    },
    "alerts": {
        "log_to_console": True,
        "notify_on_critical": True,
        "notify_on_violation": True
    }
}

def load_config() -> dict:
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            # Merge with defaults to ensure all keys exist
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
                elif isinstance(value, dict) and isinstance(config.get(key), dict):
                    for k, v in value.items():
                        if k not in config[key]:
                            config[key][k] = v
            return config
    except Exception as e:
        print(f"Error loading config, using defaults: {e}")
        return DEFAULT_CONFIG.copy()

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
    },
    "ssn_us": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "description": "US Social Security Number",
        "severity": "CRITICAL",
        "example": "123-45-6789"
    },
    "bank_account": {
        "pattern": r"\b\d{9,18}\b(?=.*(?:account|acct|a/c))",
        "description": "Bank Account Number",
        "severity": "HIGH",
        "example": "123456789012"
    }
}

# ============== DATABASE SETUP ==============

DB_FILE = "gateway_logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)

    # Request logs table
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
            content_preview TEXT,
            content_hash TEXT,
            content_size_bytes INTEGER,
            detections_json TEXT,
            response_preview TEXT,
            processing_time_ms INTEGER
        )
    """)

    # Integration events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS integration_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            integration TEXT NOT NULL,
            payload_json TEXT,
            status TEXT,
            response TEXT
        )
    """)

    # Sessions table (for mock AD)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            user_id TEXT NOT NULL,
            user_role TEXT NOT NULL,
            auth_method TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON request_logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON request_logs(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON request_logs(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON sessions(session_id)")
    conn.commit()
    conn.close()

init_db()

# ============== INTEGRATION HANDLERS ==============

async def send_webhook(event_type: str, payload: dict):
    """Send webhook notification to configured endpoints."""
    config = load_config()
    webhook_config = config.get("integrations", {}).get("webhooks", {})

    if not webhook_config.get("enabled"):
        return

    if event_type not in webhook_config.get("events", []):
        return

    async with httpx.AsyncClient(timeout=10.0) as client:
        for endpoint in webhook_config.get("endpoints", []):
            try:
                response = await client.post(
                    endpoint,
                    json={
                        "event": event_type,
                        "timestamp": datetime.now().isoformat(),
                        "data": payload
                    }
                )
                log_integration_event(event_type, "webhook", payload, "success", str(response.status_code))
            except Exception as e:
                log_integration_event(event_type, "webhook", payload, "error", str(e))

async def send_teams_notification(message: str, severity: str = "INFO"):
    """Send notification to Microsoft Teams."""
    config = load_config()
    teams_config = config.get("integrations", {}).get("teams", {})

    if not teams_config.get("enabled") or not teams_config.get("webhook_url"):
        return

    color = {"CRITICAL": "FF0000", "HIGH": "FFA500", "MEDIUM": "FFFF00", "LOW": "00FF00", "INFO": "0000FF"}.get(severity, "808080")

    payload = {
        "@type": "MessageCard",
        "themeColor": color,
        "title": f"AI Gateway Alert - {severity}",
        "text": message,
        "sections": [{
            "facts": [
                {"name": "Severity", "value": severity},
                {"name": "Timestamp", "value": datetime.now().isoformat()}
            ]
        }]
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            await client.post(teams_config["webhook_url"], json=payload)
            log_integration_event("notification", "teams", {"message": message}, "success", "sent")
        except Exception as e:
            log_integration_event("notification", "teams", {"message": message}, "error", str(e))

async def send_slack_notification(message: str, severity: str = "INFO"):
    """Send notification to Slack."""
    config = load_config()
    slack_config = config.get("integrations", {}).get("slack", {})

    if not slack_config.get("enabled") or not slack_config.get("webhook_url"):
        return

    emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:", "MEDIUM": ":large_yellow_circle:", "LOW": ":white_check_mark:"}.get(severity, ":information_source:")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} AI Gateway Alert"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            }
        ]
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            await client.post(slack_config["webhook_url"], json=payload)
            log_integration_event("notification", "slack", {"message": message}, "success", "sent")
        except Exception as e:
            log_integration_event("notification", "slack", {"message": message}, "error", str(e))

async def send_to_siem(event_data: dict):
    """Send event to SIEM (Splunk/Elastic/etc)."""
    config = load_config()
    siem_config = config.get("integrations", {}).get("siem", {})

    if not siem_config.get("enabled"):
        return

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            headers = {}
            if siem_config.get("token"):
                headers["Authorization"] = f"Splunk {siem_config['token']}"

            await client.post(
                siem_config["endpoint"],
                json={"event": event_data},
                headers=headers
            )
            log_integration_event("siem_export", siem_config.get("type", "siem"), event_data, "success", "sent")
        except Exception as e:
            log_integration_event("siem_export", siem_config.get("type", "siem"), event_data, "error", str(e))

def log_integration_event(event_type: str, integration: str, payload: dict, status: str, response: str):
    """Log integration event to database."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO integration_events (timestamp, event_type, integration, payload_json, status, response)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), event_type, integration, json.dumps(payload), status, response))
    conn.commit()
    conn.close()

# ============== LOGGING ==============

def log_request(
    request_id: str,
    user_id: str,
    action: str,
    route: str,
    provider: str,
    content: str,
    detections: list,
    response_preview: str = "",
    processing_time_ms: int = 0,
    user_role: str = "unknown",
    model: str = ""
):
    conn = sqlite3.connect(DB_FILE)
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    conn.execute("""
        INSERT INTO request_logs
        (request_id, timestamp, user_id, user_role, action, route, provider, model, content_preview,
         content_hash, content_size_bytes, detections_json, response_preview, processing_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_id,
        datetime.now().isoformat(),
        user_id,
        user_role,
        action,
        route,
        provider,
        model,
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
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {action} | User: {user_id} ({user_role}) | Provider: {provider} | Detections: {len(detections)}")

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
2. The request was NOT sent to external APIs
3. In production, a real local LLM would process this securely

---
[End of Local LLM Simulation]"""

# ============== MULTI-PROVIDER API CALLS ==============

async def call_external_api(messages: list, config: dict, override_provider: str = None) -> dict:
    """Call external AI API - supports 20+ providers."""
    provider = override_provider or config.get("active_provider", "openai")
    provider_config = config.get("providers", {}).get(provider, {})

    if not provider_config:
        return {"success": False, "error": f"Provider '{provider}' not found in configuration"}

    api_key = provider_config.get("api_key", "")

    if not api_key or api_key.startswith("YOUR_"):
        return {
            "success": False,
            "error": f"API key not configured for {provider_config.get('name', provider)}. Please update config.json"
        }

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            # OpenAI-compatible providers (most common format)
            openai_compatible = [
                "openai", "deepseek", "mistral", "grok", "groq", "fireworks",
                "together", "perplexity", "openrouter", "moonshot", "baichuan", "qwen", "yi", "ai21",
                "cerebras", "lepton", "sambanova", "novita", "deepinfra", "octoai"
            ]

            if provider in openai_compatible:
                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model"),
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
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"{provider_config.get('name')} API error: {response.status_code} - {response.text[:200]}"
                    }

            elif provider == "claude":
                # Anthropic Claude format
                claude_messages = [msg for msg in messages if msg["role"] != "system"]
                system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")

                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model"),
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
                    return {"success": False, "error": f"Claude API error: {response.status_code}"}

            elif provider == "gemini":
                # Google Gemini format
                model = provider_config.get("default_model")
                url = f"{provider_config.get('base_url')}/{model}:generateContent?key={api_key}"

                # Convert messages to Gemini format
                gemini_contents = []
                for msg in messages:
                    role = "user" if msg["role"] == "user" else "model"
                    gemini_contents.append({
                        "role": role,
                        "parts": [{"text": msg["content"]}]
                    })

                response = await client.post(
                    url,
                    json={"contents": gemini_contents}
                )

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

            elif provider == "cohere":
                # Cohere format
                chat_history = []
                message = ""
                for msg in messages:
                    if msg["role"] == "user":
                        message = msg["content"]
                    else:
                        chat_history.append({
                            "role": "CHATBOT" if msg["role"] == "assistant" else "USER",
                            "message": msg["content"]
                        })

                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model"),
                        "message": message,
                        "chat_history": chat_history
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["text"],
                        "provider": "cohere",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {"success": False, "error": f"Cohere API error: {response.status_code}"}

            elif provider == "glm":
                # Zhipu GLM format
                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": provider_config.get("default_model"),
                        "messages": messages
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["choices"][0]["message"]["content"],
                        "provider": "glm",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {"success": False, "error": f"GLM API error: {response.status_code}"}

            elif provider == "azure_openai":
                # Azure OpenAI format
                response = await client.post(
                    provider_config.get("base_url"),
                    headers={
                        "api-key": api_key,
                        "Content-Type": "application/json"
                    },
                    json={
                        "messages": messages,
                        "max_tokens": 2000
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["choices"][0]["message"]["content"],
                        "provider": "azure_openai",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {"success": False, "error": f"Azure OpenAI API error: {response.status_code}"}

            elif provider == "huggingface":
                # Hugging Face Inference format
                model = provider_config.get("default_model")
                url = f"{provider_config.get('base_url')}/{model}"

                # Format for chat models
                prompt = "\n".join([f"{msg['role']}: {msg['content']}" for msg in messages])

                response = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={"inputs": prompt, "parameters": {"max_new_tokens": 500}}
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data[0]["generated_text"] if isinstance(data, list) else data.get("generated_text", str(data))
                    return {
                        "success": True,
                        "content": content,
                        "provider": "huggingface",
                        "model": model
                    }
                else:
                    return {"success": False, "error": f"HuggingFace API error: {response.status_code}"}

            elif provider == "ollama":
                # Ollama (local) format
                response = await client.post(
                    provider_config.get("base_url"),
                    json={
                        "model": provider_config.get("default_model"),
                        "messages": messages,
                        "stream": False
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "content": data["message"]["content"],
                        "provider": "ollama",
                        "model": provider_config.get("default_model")
                    }
                else:
                    return {"success": False, "error": f"Ollama error: {response.status_code}"}

            else:
                return {"success": False, "error": f"Provider '{provider}' not implemented yet"}

        except Exception as e:
            return {"success": False, "error": str(e)}

# ============== API MODELS ==============

class ChatRequest(BaseModel):
    messages: Optional[List[Dict[str, str]]] = None
    message: Optional[str] = None
    conversation_history: Optional[List[Dict[str, str]]] = None
    user_id: Optional[str] = "anonymous"
    provider: Optional[str] = None
    model: Optional[str] = None

class ConfigUpdate(BaseModel):
    active_provider: Optional[str] = None
    local_llm_mode: Optional[str] = None
    blocked_keywords: Optional[List[str]] = None
    max_content_size_mb: Optional[float] = None

class ProviderUpdate(BaseModel):
    provider: str
    api_key: Optional[str] = None
    enabled: Optional[bool] = None
    default_model: Optional[str] = None

class WebhookConfig(BaseModel):
    enabled: bool
    endpoints: List[str] = []
    events: List[str] = []

class IntegrationTest(BaseModel):
    integration: str  # "teams", "slack", "webhook", "siem"
    test_message: Optional[str] = "Test notification from AI Gateway"

class TestScanRequest(BaseModel):
    content: str

# ============== PAGE ENDPOINTS ==============

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve admin dashboard."""
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>AI Gateway POC</h1><p>Admin dashboard not found.</p>"

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve login page."""
    try:
        with open("login.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>Login</h1><p>Login page not found.</p>"

@app.get("/chat", response_class=HTMLResponse)
async def user_chat():
    """Serve user-facing chat interface."""
    try:
        with open("chat.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>AI Chat</h1><p>Chat interface not found.</p>"

@app.get("/admin", response_class=HTMLResponse)
async def admin_redirect():
    """Serve admin dashboard."""
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "<h1>AI Gateway POC</h1><p>Admin dashboard not found.</p>"

# ============== CHAT ENDPOINT ==============

@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Main chat endpoint - scans and routes requests."""
    start_time = datetime.now()
    request_id = str(uuid.uuid4())[:8]
    config = load_config()

    # Rate limiting
    rate_check = check_rate_limit(request.user_id)
    if not rate_check["allowed"]:
        await send_webhook("rate_limit_exceeded", {"user_id": request.user_id})
        return JSONResponse(
            status_code=429,
            content={"error": rate_check["reason"], "request_id": request_id}
        )

    # Handle both message formats
    if request.message:
        messages = request.conversation_history or []
        messages.append({"role": "user", "content": request.message})
        full_content = request.message
    elif request.messages:
        messages = request.messages
        full_content = "\n".join([msg.get("content", "") for msg in messages])
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "Either 'message' or 'messages' field is required"}
        )

    # Scan for sensitive data
    scan_result = scan_content(full_content)
    processing_time = int((datetime.now() - start_time).total_seconds() * 1000)

    # Determine routing
    if scan_result["is_sensitive"]:
        local_llm_mode = config.get("local_llm_mode", "mock")

        # Send notifications for violations
        severity = scan_result.get("severity", "UNKNOWN")
        detection_types = [d["type"] for d in scan_result["detections"]]

        await send_webhook("violation", {
            "user_id": request.user_id,
            "severity": severity,
            "detections": detection_types
        })

        if severity == "CRITICAL":
            await send_teams_notification(
                f"CRITICAL: User {request.user_id} attempted to send sensitive data. Detections: {', '.join(detection_types)}",
                "CRITICAL"
            )
            await send_slack_notification(
                f"*CRITICAL VIOLATION*\nUser: `{request.user_id}`\nDetections: {', '.join(detection_types)}",
                "CRITICAL"
            )
            await send_to_siem({
                "event_type": "critical_violation",
                "user_id": request.user_id,
                "detections": scan_result["detections"],
                "timestamp": datetime.now().isoformat()
            })

        if local_llm_mode == "block":
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
                status_code=200,
                content={
                    "request_id": request_id,
                    "blocked": True,
                    "response": "I'm sorry, but I cannot process this request as it contains sensitive information. Please rephrase your message without including personal data, credentials, or confidential information.",
                    "_admin_info": {
                        "status": "BLOCKED",
                        "detections": scan_result["detections"],
                        "severity": scan_result["severity"]
                    }
                }
            )
        else:
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
                "response": mock_response,
                "data_stayed_local": True
            }
    else:
        # Clean content - route to external API
        provider = request.provider or config.get("active_provider", "openai")
        api_result = await call_external_api(messages, config, provider)
        processing_time = int((datetime.now() - start_time).total_seconds() * 1000)

        if api_result["success"]:
            log_request(
                request_id=request_id,
                user_id=request.user_id,
                action="ALLOWED",
                route="external_api",
                provider=api_result["provider"],
                model=api_result.get("model", ""),
                content=full_content,
                detections=scan_result["detections"],
                response_preview=api_result["content"],
                processing_time_ms=processing_time
            )

            return {
                "request_id": request_id,
                "status": "ALLOWED",
                "provider": api_result["provider"],
                "model": api_result.get("model"),
                "response": api_result["content"]
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

# ============== PROVIDER ENDPOINTS ==============

@app.get("/api/providers")
async def get_providers():
    """Get all available AI providers."""
    config = load_config()
    providers = config.get("providers", {})

    # Hide API keys, show configuration status
    safe_providers = {}
    for key, provider in providers.items():
        api_key = provider.get("api_key", "")
        is_configured = api_key and not api_key.startswith("YOUR_")

        safe_providers[key] = {
            "name": provider.get("name"),
            "enabled": provider.get("enabled", True),
            "configured": is_configured,
            "default_model": provider.get("default_model"),
            "models": provider.get("models", []),
            "is_local": provider.get("is_local", False)
        }

    return {
        "providers": safe_providers,
        "active_provider": config.get("active_provider"),
        "count": len(providers)
    }

@app.post("/api/providers/update")
async def update_provider(update: ProviderUpdate):
    """Update a provider's configuration."""
    config = load_config()

    if update.provider not in config.get("providers", {}):
        return JSONResponse(status_code=404, content={"error": f"Provider '{update.provider}' not found"})

    if update.api_key:
        config["providers"][update.provider]["api_key"] = update.api_key

    if update.enabled is not None:
        config["providers"][update.provider]["enabled"] = update.enabled

    if update.default_model:
        config["providers"][update.provider]["default_model"] = update.default_model

    save_config(config)
    return {"status": "updated", "provider": update.provider}

@app.post("/api/providers/set-active")
async def set_active_provider(provider: str):
    """Set the active AI provider."""
    config = load_config()

    if provider not in config.get("providers", {}):
        return JSONResponse(status_code=404, content={"error": f"Provider '{provider}' not found"})

    config["active_provider"] = provider
    save_config(config)
    return {"status": "updated", "active_provider": provider}

# ============== INTEGRATION ENDPOINTS ==============

@app.get("/api/integrations")
async def get_integrations():
    """Get all integration configurations."""
    config = load_config()
    integrations = config.get("integrations", {})

    # Hide sensitive data
    safe_integrations = {}
    for key, integration in integrations.items():
        safe_integration = integration.copy()
        for sensitive_key in ["token", "password", "webhook_url"]:
            if sensitive_key in safe_integration and safe_integration[sensitive_key]:
                safe_integration[sensitive_key] = "***CONFIGURED***"
        safe_integrations[key] = safe_integration

    return {"integrations": safe_integrations}

@app.post("/api/integrations/webhook")
async def update_webhook_config(config_update: WebhookConfig):
    """Update webhook configuration."""
    config = load_config()
    config["integrations"]["webhooks"] = {
        "enabled": config_update.enabled,
        "endpoints": config_update.endpoints,
        "events": config_update.events
    }
    save_config(config)
    return {"status": "updated"}

@app.post("/api/integrations/test")
async def test_integration(test: IntegrationTest):
    """Test an integration by sending a test notification."""
    if test.integration == "teams":
        await send_teams_notification(test.test_message, "INFO")
    elif test.integration == "slack":
        await send_slack_notification(test.test_message, "INFO")
    elif test.integration == "webhook":
        await send_webhook("test", {"message": test.test_message})
    elif test.integration == "siem":
        await send_to_siem({"event_type": "test", "message": test.test_message})
    else:
        return JSONResponse(status_code=400, content={"error": f"Unknown integration: {test.integration}"})

    return {"status": "sent", "integration": test.integration}

@app.get("/api/integrations/events")
async def get_integration_events(limit: int = 50):
    """Get recent integration events."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    cursor = conn.execute(
        "SELECT * FROM integration_events ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {"events": events, "count": len(events)}

# ============== SCAN & CONFIG ENDPOINTS ==============

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
    safe_config = config.copy()

    if "providers" in safe_config:
        for provider in safe_config["providers"]:
            if "api_key" in safe_config["providers"][provider]:
                key = safe_config["providers"][provider]["api_key"]
                if key and not key.startswith("YOUR_"):
                    safe_config["providers"][provider]["api_key"] = "***CONFIGURED***"
                else:
                    safe_config["providers"][provider]["api_key"] = "NOT_CONFIGURED"
            if "secret_key" in safe_config["providers"][provider]:
                safe_config["providers"][provider]["secret_key"] = "***HIDDEN***"

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

    save_config(config)
    return {"status": "updated"}

# ============== LOGS & STATS ENDPOINTS ==============

@app.get("/api/logs")
async def get_logs(limit: int = 100, action: str = None, user_id: str = None):
    """Get request logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM request_logs WHERE 1=1"
    params = []

    if action:
        query += " AND action = ?"
        params.append(action)

    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)

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

@app.get("/api/logs/stats")
async def get_log_stats():
    """Get log statistics."""
    conn = sqlite3.connect(DB_FILE)
    stats = {}

    cursor = conn.execute("SELECT COUNT(*) FROM request_logs")
    stats["total_requests"] = cursor.fetchone()[0]

    cursor = conn.execute("SELECT action, COUNT(*) as count FROM request_logs GROUP BY action")
    stats["by_action"] = {row[0]: row[1] for row in cursor.fetchall()}

    cursor = conn.execute("SELECT provider, COUNT(*) as count FROM request_logs WHERE provider IS NOT NULL AND provider != 'none' GROUP BY provider")
    stats["by_provider"] = {row[0]: row[1] for row in cursor.fetchall()}

    cursor = conn.execute("SELECT COUNT(*) FROM request_logs WHERE timestamp > datetime('now', '-24 hours')")
    stats["last_24h"] = cursor.fetchone()[0]

    conn.close()
    return stats

@app.delete("/api/logs")
async def clear_logs():
    """Clear all logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM request_logs")
    conn.commit()
    conn.close()
    return {"status": "cleared"}

@app.get("/api/violations")
async def get_violations(limit: int = 100, since_id: int = None):
    """Get only violation logs."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM request_logs WHERE (action = 'BLOCKED' OR action = 'ROUTED_LOCAL_LLM') AND detections_json != '[]'"
    params = []

    if since_id:
        query += " AND id > ?"
        params.append(since_id)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    violations = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for v in violations:
        if v.get("detections_json"):
            v["detections"] = json.loads(v["detections_json"])
            del v["detections_json"]

    return {"violations": violations, "count": len(violations)}

@app.get("/api/violations/count")
async def get_violation_count(since_minutes: int = 60):
    """Get count of recent violations."""
    conn = sqlite3.connect(DB_FILE)

    cursor = conn.execute("""
        SELECT COUNT(*) FROM request_logs
        WHERE (action = 'BLOCKED' OR action = 'ROUTED_LOCAL_LLM')
        AND detections_json != '[]'
        AND timestamp > datetime('now', ?)
    """, (f'-{since_minutes} minutes',))

    count = cursor.fetchone()[0]
    conn.close()

    return {"total_violations": count, "since_minutes": since_minutes}

@app.get("/api/patterns")
async def get_patterns():
    """Get all detection patterns."""
    return {"patterns": DETECTION_PATTERNS, "count": len(DETECTION_PATTERNS)}

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    config = load_config()

    # Count configured providers
    providers = config.get("providers", {})
    configured_count = sum(1 for p in providers.values() if p.get("api_key") and not p["api_key"].startswith("YOUR_"))

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "active_provider": config.get("active_provider"),
        "local_llm_mode": config.get("local_llm_mode"),
        "configured_providers": configured_count,
        "total_providers": len(providers)
    }

# ============== FILE UPLOAD ==============

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), user_id: str = "anonymous"):
    """Handle file uploads with scanning."""
    request_id = str(uuid.uuid4())[:8]
    config = load_config()

    content = await file.read()
    size_mb = len(content) / (1024 * 1024)

    max_size = config.get("file_size_limits", {}).get("max_file_upload_mb", 5)
    if size_mb > max_size:
        return JSONResponse(
            status_code=413,
            content={
                "request_id": request_id,
                "status": "BLOCKED",
                "reason": f"File size ({size_mb:.2f}MB) exceeds limit ({max_size}MB)"
            }
        )

    try:
        text_content = content.decode('utf-8')
        scan_result = scan_content(text_content)
    except:
        scan_result = {"is_sensitive": False, "detections": []}

    if scan_result["is_sensitive"]:
        return JSONResponse(
            status_code=403,
            content={
                "request_id": request_id,
                "status": "BLOCKED",
                "reason": "File contains sensitive data",
                "detections": scan_result["detections"]
            }
        )

    return {
        "request_id": request_id,
        "status": "ALLOWED",
        "filename": file.filename,
        "size_mb": round(size_mb, 2)
    }

# ============== RUN SERVER ==============

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("   AI Gateway POC v2.0 - Starting Server")
    print("="*60)
    print(f"\n   Login:     http://localhost:8000/login")
    print(f"   Dashboard: http://localhost:8000")
    print(f"   User Chat: http://localhost:8000/chat")
    print(f"   API Docs:  http://localhost:8000/docs")
    print("\n" + "="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
