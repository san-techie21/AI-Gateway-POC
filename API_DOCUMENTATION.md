# AI Gateway - API Documentation

**Version:** 1.0
**Base URL:** `https://aigateway.motilal.local/api`

---

## Authentication

All API requests require authentication via session cookie (after AD login) or API key header.

```http
Authorization: Bearer <api-key>
```

---

## Endpoints

### Chat API

#### POST /api/chat

Send a message through the AI Gateway.

**Request:**
```json
{
  "content": "What is the revenue growth strategy?",
  "provider": "auto",
  "user_id": "emp12345"
}
```

**Response (Success):**
```json
{
  "response": "Based on the analysis...",
  "provider": "azure_openai",
  "action": "allowed",
  "scan_result": {
    "has_sensitive": false,
    "patterns_found": []
  },
  "request_id": "req_abc123"
}
```

**Response (Blocked):**
```json
{
  "error": "Content blocked - sensitive data detected",
  "action": "blocked",
  "scan_result": {
    "has_sensitive": true,
    "patterns_found": ["Aadhaar Number", "PAN Card"]
  },
  "request_id": "req_abc124"
}
```

---

### Content Scanning

#### POST /api/scan

Test content for sensitive data without making API calls.

**Request:**
```json
{
  "content": "My Aadhaar is 2345 6789 0123"
}
```

**Response:**
```json
{
  "has_sensitive": true,
  "action": "blocked",
  "patterns_found": [
    {
      "name": "Aadhaar Number",
      "severity": "critical",
      "match": "2345 6789 0123"
    }
  ]
}
```

---

### Logs & Monitoring

#### GET /api/logs

Get request logs with optional filters.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| limit | int | Max records (default: 100) |
| action | string | Filter by action: allowed, blocked, local |
| user_id | string | Filter by user ID |
| from_date | string | Start date (ISO format) |
| to_date | string | End date (ISO format) |

**Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2026-02-06T14:29:40+05:30",
      "user_id": "dashboard_user",
      "action": "blocked",
      "provider": "none",
      "content_preview": "My Aadhaar number is...",
      "detections": ["Aadhaar Number"]
    }
  ],
  "total": 1,
  "page": 1
}
```

#### GET /api/logs/stats

Get aggregated statistics.

**Response:**
```json
{
  "total_requests": 150,
  "allowed": 120,
  "blocked": 25,
  "local_routed": 5,
  "detections_by_type": {
    "Aadhaar Number": 15,
    "PAN Card": 8,
    "API Key": 2
  }
}
```

---

### Configuration

#### GET /api/config

Get current configuration.

**Response:**
```json
{
  "patterns": [...],
  "keywords": [...],
  "active_provider": "azure_openai",
  "rate_limits": {
    "per_user_per_day": 100,
    "per_user_per_hour": 20
  }
}
```

#### POST /api/config

Update configuration (Admin only).

**Request:**
```json
{
  "keywords": ["merger", "acquisition"],
  "rate_limit": 100
}
```

---

### Providers

#### GET /api/providers

List available AI providers.

**Response:**
```json
{
  "providers": [
    {
      "id": "azure_openai",
      "name": "Azure OpenAI (Mumbai)",
      "status": "active",
      "models": ["gpt-4o", "gpt-4-turbo"]
    },
    {
      "id": "aws_bedrock",
      "name": "AWS Bedrock (Mumbai)",
      "status": "configured",
      "models": ["claude-3-sonnet"]
    }
  ],
  "active": "azure_openai"
}
```

#### POST /api/providers/set-active

Set the active provider.

**Request:**
```json
{
  "provider": "azure_openai"
}
```

---

### Health & Status

#### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "5d 12h 30m",
  "components": {
    "database": "ok",
    "active_directory": "ok",
    "siem": "ok",
    "ai_provider": "ok"
  }
}
```

---

### Telemetry & Usage

#### GET /api/telemetry/overview

Get overall usage statistics across all users and providers.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| days | int | Period in days (default: 30) |

**Response:**
```json
{
  "period_days": 30,
  "generated_at": "2026-02-07T15:30:00+05:30",
  "totals": {
    "total_requests": 1250,
    "total_input_tokens": 450000,
    "total_output_tokens": 180000,
    "total_tokens": 630000,
    "total_cost_usd": 12.50,
    "total_cost_inr": 1043.75,
    "unique_users": 45,
    "providers_used": 4
  },
  "top_users": [
    {"user_id": "analyst01", "requests": 150, "tokens": 75000, "cost_inr": 125.50}
  ],
  "top_providers": [
    {"provider": "azure_openai", "requests": 800, "tokens": 400000, "cost_inr": 650.00}
  ],
  "daily_trend": [
    {"date": "2026-02-06", "requests": 45, "tokens": 22500, "cost_inr": 35.25}
  ]
}
```

#### GET /api/telemetry/user/{user_id}

Get usage statistics for a specific user.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| user_id | string | User ID (path parameter) |
| days | int | Period in days (default: 30) |

**Response:**
```json
{
  "user_id": "analyst01",
  "period_days": 30,
  "total": {
    "total_requests": 150,
    "total_input_tokens": 50000,
    "total_output_tokens": 25000,
    "total_tokens": 75000,
    "total_cost_usd": 1.50,
    "total_cost_inr": 125.25
  },
  "by_provider": [
    {"provider": "azure_openai", "requests": 120, "tokens": 60000, "cost_inr": 100.00}
  ],
  "daily_trend": [
    {"date": "2026-02-06", "requests": 8, "tokens": 4000, "cost_inr": 6.65}
  ]
}
```

#### GET /api/telemetry/providers

Get usage statistics grouped by AI provider.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| days | int | Period in days (default: 30) |

**Response:**
```json
{
  "period_days": 30,
  "totals": {
    "total_requests": 1250,
    "total_tokens": 630000,
    "total_cost_usd": 12.50,
    "total_cost_inr": 1043.75
  },
  "by_provider": [
    {
      "provider": "azure_openai",
      "total_requests": 800,
      "input_tokens": 300000,
      "output_tokens": 100000,
      "total_tokens": 400000,
      "cost_usd": 8.00,
      "cost_inr": 668.00,
      "unique_users": 35
    }
  ]
}
```

#### GET /api/telemetry/recent

Get recent token usage records.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| limit | int | Max records (default: 50) |

**Response:**
```json
{
  "records": [
    {
      "id": 125,
      "request_id": "req_abc123",
      "timestamp": "2026-02-07T15:25:30+05:30",
      "user_id": "analyst01",
      "user_role": "research",
      "provider": "azure_openai",
      "model": "gpt-4o",
      "input_tokens": 250,
      "output_tokens": 180,
      "total_tokens": 430,
      "cost_usd": 0.0032,
      "cost_inr": 0.27,
      "request_type": "chat",
      "response_time_ms": 1250
    }
  ],
  "total": 50
}
```

#### GET /api/telemetry/costs

Get provider cost rates.

**Response:**
```json
{
  "cost_rates": {
    "azure_openai": {"input": 2.50, "output": 10.00, "currency": "USD"},
    "aws_bedrock": {"input": 3.00, "output": 15.00, "currency": "USD"},
    "deepseek": {"input": 0.14, "output": 0.28, "currency": "USD"},
    "gemini": {"input": 0.075, "output": 0.30, "currency": "USD"}
  },
  "usd_to_inr": 83.50,
  "note": "Costs are per 1 million tokens"
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 429 | Rate Limited - Too many requests |
| 500 | Server Error - Internal error |
| 503 | Service Unavailable - AI provider down |

---

## Rate Limits

| User Type | Per Hour | Per Day |
|-----------|----------|---------|
| General | 20 | 100 |
| Research | 50 | 500 |
| Strategy | 50 | 500 |

---

## Webhooks

Configure webhooks in Admin Console > Configuration > Integrations.

**Webhook Payload:**
```json
{
  "event": "query_blocked",
  "timestamp": "2026-02-06T14:29:40+05:30",
  "data": {
    "user_id": "emp12345",
    "patterns_found": ["Aadhaar Number"],
    "severity": "critical"
  }
}
```

**Supported Events:**
- `query_blocked` - Sensitive data detected
- `rate_limit_exceeded` - User rate limited
- `auth_failure` - Authentication failed
- `config_changed` - Configuration updated

---

**Document Version:** 1.1
**Last Updated:** February 7, 2026
