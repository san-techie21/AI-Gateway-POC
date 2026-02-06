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

**Document Version:** 1.0
**Last Updated:** February 6, 2026
