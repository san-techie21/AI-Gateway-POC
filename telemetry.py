"""
Telemetry Module - Token Usage Tracking
AI Gateway POC - Motilal Oswal Financial Services

Tracks:
- Token usage per user
- Token usage per API provider
- Cost estimates per provider
- Usage statistics and trends
"""

import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    """Get current time in Indian Standard Time (IST)."""
    return datetime.now(IST)

# ============== TOKEN COST ESTIMATES (USD per 1M tokens) ==============

PROVIDER_COSTS = {
    # OpenAI
    "openai": {"input": 2.50, "output": 10.00, "currency": "USD"},

    # Anthropic Claude
    "claude": {"input": 3.00, "output": 15.00, "currency": "USD"},

    # Google Gemini
    "gemini": {"input": 0.075, "output": 0.30, "currency": "USD"},

    # DeepSeek
    "deepseek": {"input": 0.14, "output": 0.28, "currency": "USD"},

    # Mistral
    "mistral": {"input": 2.00, "output": 6.00, "currency": "USD"},

    # Grok
    "grok": {"input": 5.00, "output": 15.00, "currency": "USD"},

    # Cohere
    "cohere": {"input": 0.50, "output": 1.50, "currency": "USD"},

    # AI21
    "ai21": {"input": 0.50, "output": 0.50, "currency": "USD"},

    # Perplexity
    "perplexity": {"input": 0.20, "output": 0.20, "currency": "USD"},

    # Together AI
    "together": {"input": 0.90, "output": 0.90, "currency": "USD"},

    # Groq (Fast Inference)
    "groq": {"input": 0.05, "output": 0.08, "currency": "USD"},

    # Fireworks AI
    "fireworks": {"input": 0.90, "output": 0.90, "currency": "USD"},

    # GLM (ChatGLM)
    "glm": {"input": 0.10, "output": 0.10, "currency": "USD"},

    # Azure OpenAI
    "azure_openai": {"input": 2.50, "output": 10.00, "currency": "USD"},

    # AWS Bedrock (Claude)
    "aws_bedrock": {"input": 3.00, "output": 15.00, "currency": "USD"},

    # Hugging Face
    "huggingface": {"input": 0.00, "output": 0.00, "currency": "USD"},  # Free tier

    # Replicate
    "replicate": {"input": 0.50, "output": 0.50, "currency": "USD"},

    # Ollama (Local - Free)
    "ollama": {"input": 0.00, "output": 0.00, "currency": "USD"},

    # OpenRouter
    "openrouter": {"input": 1.00, "output": 3.00, "currency": "USD"},

    # Moonshot
    "moonshot": {"input": 0.12, "output": 0.12, "currency": "USD"},

    # Baichuan
    "baichuan": {"input": 0.10, "output": 0.10, "currency": "USD"},

    # Qwen
    "qwen": {"input": 0.08, "output": 0.08, "currency": "USD"},

    # Yi
    "yi": {"input": 0.20, "output": 0.20, "currency": "USD"},

    # Cerebras
    "cerebras": {"input": 0.10, "output": 0.10, "currency": "USD"},

    # Lepton
    "lepton": {"input": 0.50, "output": 0.50, "currency": "USD"},

    # SambaNova
    "sambanova": {"input": 0.50, "output": 0.50, "currency": "USD"},

    # Novita
    "novita": {"input": 0.30, "output": 0.30, "currency": "USD"},

    # DeepInfra
    "deepinfra": {"input": 0.30, "output": 0.30, "currency": "USD"},

    # OctoAI
    "octoai": {"input": 0.30, "output": 0.30, "currency": "USD"},

    # Local LLM (simulated/mock)
    "local_llm_simulated": {"input": 0.00, "output": 0.00, "currency": "USD"},
    "none": {"input": 0.00, "output": 0.00, "currency": "USD"},
}

# Default USD to INR conversion rate
USD_TO_INR = 83.50

DB_FILE = "gateway_logs.db"


def init_telemetry_db():
    """Initialize telemetry tables in database."""
    conn = sqlite3.connect(DB_FILE)

    # Token usage tracking table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS token_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            user_role TEXT,
            provider TEXT NOT NULL,
            model TEXT,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            cost_inr REAL DEFAULT 0.0,
            request_type TEXT,
            response_time_ms INTEGER
        )
    """)

    # Daily aggregates for faster reporting
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            total_requests INTEGER DEFAULT 0,
            total_input_tokens INTEGER DEFAULT 0,
            total_output_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            total_cost_usd REAL DEFAULT 0.0,
            total_cost_inr REAL DEFAULT 0.0,
            UNIQUE(date, user_id, provider)
        )
    """)

    # Create indexes for faster queries
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token_timestamp ON token_usage(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token_user ON token_usage(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_token_provider ON token_usage(provider)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_usage_summary(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_daily_user ON daily_usage_summary(user_id)")

    conn.commit()
    conn.close()


def estimate_tokens(text: str) -> int:
    """
    Estimate token count from text.
    Rough estimate: ~4 characters per token for English text.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def calculate_cost(provider: str, input_tokens: int, output_tokens: int) -> Dict[str, float]:
    """Calculate cost based on provider and token counts."""
    costs = PROVIDER_COSTS.get(provider, {"input": 0, "output": 0})

    # Cost per 1M tokens -> per token
    input_cost = (input_tokens / 1_000_000) * costs["input"]
    output_cost = (output_tokens / 1_000_000) * costs["output"]
    total_usd = input_cost + output_cost
    total_inr = total_usd * USD_TO_INR

    return {
        "cost_usd": round(total_usd, 6),
        "cost_inr": round(total_inr, 4)
    }


def log_token_usage(
    request_id: str,
    user_id: str,
    provider: str,
    input_text: str,
    output_text: str,
    model: str = "",
    user_role: str = "unknown",
    request_type: str = "chat",
    response_time_ms: int = 0
) -> Dict[str, Any]:
    """
    Log token usage for a request.
    Returns the calculated metrics.
    """
    input_tokens = estimate_tokens(input_text)
    output_tokens = estimate_tokens(output_text)
    total_tokens = input_tokens + output_tokens

    cost = calculate_cost(provider, input_tokens, output_tokens)

    timestamp = now_ist()
    date_str = timestamp.strftime("%Y-%m-%d")

    conn = sqlite3.connect(DB_FILE)

    # Insert detailed record
    conn.execute("""
        INSERT INTO token_usage
        (request_id, timestamp, user_id, user_role, provider, model,
         input_tokens, output_tokens, total_tokens, cost_usd, cost_inr,
         request_type, response_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_id, timestamp.isoformat(), user_id, user_role, provider, model,
        input_tokens, output_tokens, total_tokens, cost["cost_usd"], cost["cost_inr"],
        request_type, response_time_ms
    ))

    # Update daily summary (upsert)
    conn.execute("""
        INSERT INTO daily_usage_summary
        (date, user_id, provider, total_requests, total_input_tokens,
         total_output_tokens, total_tokens, total_cost_usd, total_cost_inr)
        VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(date, user_id, provider) DO UPDATE SET
            total_requests = total_requests + 1,
            total_input_tokens = total_input_tokens + excluded.total_input_tokens,
            total_output_tokens = total_output_tokens + excluded.total_output_tokens,
            total_tokens = total_tokens + excluded.total_tokens,
            total_cost_usd = total_cost_usd + excluded.total_cost_usd,
            total_cost_inr = total_cost_inr + excluded.total_cost_inr
    """, (
        date_str, user_id, provider, input_tokens, output_tokens,
        total_tokens, cost["cost_usd"], cost["cost_inr"]
    ))

    conn.commit()
    conn.close()

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cost_usd": cost["cost_usd"],
        "cost_inr": cost["cost_inr"]
    }


def get_user_usage(user_id: str, days: int = 30) -> Dict[str, Any]:
    """Get usage statistics for a specific user."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    cutoff = (now_ist() - timedelta(days=days)).strftime("%Y-%m-%d")

    # Total usage
    cursor = conn.execute("""
        SELECT
            SUM(total_requests) as total_requests,
            SUM(total_input_tokens) as total_input_tokens,
            SUM(total_output_tokens) as total_output_tokens,
            SUM(total_tokens) as total_tokens,
            SUM(total_cost_usd) as total_cost_usd,
            SUM(total_cost_inr) as total_cost_inr
        FROM daily_usage_summary
        WHERE user_id = ? AND date >= ?
    """, (user_id, cutoff))

    total = dict(cursor.fetchone())

    # Usage by provider
    cursor = conn.execute("""
        SELECT
            provider,
            SUM(total_requests) as requests,
            SUM(total_tokens) as tokens,
            SUM(total_cost_usd) as cost_usd,
            SUM(total_cost_inr) as cost_inr
        FROM daily_usage_summary
        WHERE user_id = ? AND date >= ?
        GROUP BY provider
        ORDER BY tokens DESC
    """, (user_id, cutoff))

    by_provider = [dict(row) for row in cursor.fetchall()]

    # Daily trend
    cursor = conn.execute("""
        SELECT
            date,
            SUM(total_requests) as requests,
            SUM(total_tokens) as tokens,
            SUM(total_cost_inr) as cost_inr
        FROM daily_usage_summary
        WHERE user_id = ? AND date >= ?
        GROUP BY date
        ORDER BY date
    """, (user_id, cutoff))

    daily_trend = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "user_id": user_id,
        "period_days": days,
        "total": total,
        "by_provider": by_provider,
        "daily_trend": daily_trend
    }


def get_provider_usage(days: int = 30) -> Dict[str, Any]:
    """Get usage statistics by provider."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    cutoff = (now_ist() - timedelta(days=days)).strftime("%Y-%m-%d")

    # Usage by provider
    cursor = conn.execute("""
        SELECT
            provider,
            SUM(total_requests) as total_requests,
            SUM(total_input_tokens) as input_tokens,
            SUM(total_output_tokens) as output_tokens,
            SUM(total_tokens) as total_tokens,
            SUM(total_cost_usd) as cost_usd,
            SUM(total_cost_inr) as cost_inr,
            COUNT(DISTINCT user_id) as unique_users
        FROM daily_usage_summary
        WHERE date >= ?
        GROUP BY provider
        ORDER BY total_tokens DESC
    """, (cutoff,))

    by_provider = [dict(row) for row in cursor.fetchall()]

    # Total across all providers
    cursor = conn.execute("""
        SELECT
            SUM(total_requests) as total_requests,
            SUM(total_tokens) as total_tokens,
            SUM(total_cost_usd) as total_cost_usd,
            SUM(total_cost_inr) as total_cost_inr
        FROM daily_usage_summary
        WHERE date >= ?
    """, (cutoff,))

    totals = dict(cursor.fetchone())

    conn.close()

    return {
        "period_days": days,
        "totals": totals,
        "by_provider": by_provider
    }


def get_overall_stats(days: int = 30) -> Dict[str, Any]:
    """Get overall telemetry statistics."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    cutoff = (now_ist() - timedelta(days=days)).strftime("%Y-%m-%d")

    # Overall totals
    cursor = conn.execute("""
        SELECT
            SUM(total_requests) as total_requests,
            SUM(total_input_tokens) as total_input_tokens,
            SUM(total_output_tokens) as total_output_tokens,
            SUM(total_tokens) as total_tokens,
            SUM(total_cost_usd) as total_cost_usd,
            SUM(total_cost_inr) as total_cost_inr,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT provider) as providers_used
        FROM daily_usage_summary
        WHERE date >= ?
    """, (cutoff,))

    totals = dict(cursor.fetchone())

    # Top users by tokens
    cursor = conn.execute("""
        SELECT
            user_id,
            SUM(total_requests) as requests,
            SUM(total_tokens) as tokens,
            SUM(total_cost_inr) as cost_inr
        FROM daily_usage_summary
        WHERE date >= ?
        GROUP BY user_id
        ORDER BY tokens DESC
        LIMIT 10
    """, (cutoff,))

    top_users = [dict(row) for row in cursor.fetchall()]

    # Top providers by tokens
    cursor = conn.execute("""
        SELECT
            provider,
            SUM(total_requests) as requests,
            SUM(total_tokens) as tokens,
            SUM(total_cost_inr) as cost_inr
        FROM daily_usage_summary
        WHERE date >= ?
        GROUP BY provider
        ORDER BY tokens DESC
        LIMIT 10
    """, (cutoff,))

    top_providers = [dict(row) for row in cursor.fetchall()]

    # Daily trend
    cursor = conn.execute("""
        SELECT
            date,
            SUM(total_requests) as requests,
            SUM(total_tokens) as tokens,
            SUM(total_cost_inr) as cost_inr
        FROM daily_usage_summary
        WHERE date >= ?
        GROUP BY date
        ORDER BY date
    """, (cutoff,))

    daily_trend = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "period_days": days,
        "generated_at": now_ist().isoformat(),
        "totals": totals,
        "top_users": top_users,
        "top_providers": top_providers,
        "daily_trend": daily_trend,
        "cost_rates": PROVIDER_COSTS
    }


def get_recent_usage(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent token usage records."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    cursor = conn.execute("""
        SELECT * FROM token_usage
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    records = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return records


# Initialize telemetry tables on module load
init_telemetry_db()
