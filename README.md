# AI Gateway POC

**Enterprise AI Security Layer - Motilal Oswal Financial Services**

A proof-of-concept demonstrating an AI security gateway that scans outgoing requests for sensitive data before routing to external AI APIs.

---

## Quick Start

### 1. Install Python Dependencies

```bash
cd G:\AI-Gateway-POC
pip install -r requirements.txt
```

### 2. Configure API Key

Edit `config.json` and add your OpenAI or Claude API key:

```json
{
  "providers": {
    "openai": {
      "api_key": "sk-YOUR-OPENAI-KEY-HERE",
      ...
    }
  }
}
```

### 3. Run the Server

```bash
python main.py
```

Or using uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open Dashboard

Open your browser and go to:
```
http://localhost:8000
```

---

## Features Demonstrated

### 1. PII Detection
- Aadhaar Number (Indian ID)
- PAN Card
- Phone Numbers
- Email Addresses
- Credit Card Numbers
- IFSC Codes
- Demat Account Numbers
- Passport Numbers

### 2. Credential Detection
- API Keys
- AWS Access Keys
- AWS Secret Keys
- Private Keys (PEM)
- Database Connection Strings
- JWT Tokens

### 3. Content Controls
- File Size Limits (default: 1MB)
- Blocked Keywords (confidential, internal only, etc.)
- Large Code Block Detection

### 4. Routing Logic
- **Clean Content** → External API (OpenAI/Claude)
- **Sensitive Content** → Block OR Mock Local LLM (toggle in dashboard)

---

## Dashboard Features

| Section | Description |
|---------|-------------|
| **Dashboard** | Stats, mode toggle, recent activity |
| **Test Chat** | Interactive chat to test detection |
| **Scan Tester** | Test content without API calls |
| **Request Logs** | View all requests and their status |
| **Settings** | Configure API keys, limits, keywords |
| **Detection Patterns** | View all detection patterns |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Admin Dashboard |
| `/api/chat` | POST | Main chat endpoint |
| `/api/scan` | POST | Test scanner only |
| `/api/config` | GET/POST | Configuration |
| `/api/logs` | GET/DELETE | Request logs |
| `/api/logs/stats` | GET | Statistics |
| `/api/patterns` | GET | Detection patterns |
| `/api/health` | GET | Health check |
| `/api/upload` | POST | File upload scanning |

---

## Local LLM Mode Toggle

The dashboard has a toggle switch for handling sensitive data:

### BLOCK Mode
- Sensitive requests are rejected with an error
- User sees what was detected
- Suggested to remove sensitive data

### MOCK Mode
- Simulates local LLM response
- Shows what would happen with on-premise AI
- Data marked as "stayed local"

---

## Test Examples

Try these in the chat interface:

**1. Aadhaar Detection:**
```
My Aadhaar is 2345 6789 0123, please help
```

**2. PAN Detection:**
```
Process PAN ABCDE1234F for tax
```

**3. API Key Detection:**
```
api_key = "sk-abc123xyz456789012345678901234567890"
```

**4. Database String:**
```
mysql://admin:pass@db.internal.com/prod
```

**5. Blocked Keywords:**
```
This confidential document about trading algorithm
```

**6. Clean Query (Should Pass):**
```
What is machine learning?
```

---

## File Structure

```
G:\AI-Gateway-POC\
├── main.py           # FastAPI application
├── config.json       # Configuration
├── admin.html        # Dashboard UI
├── requirements.txt  # Python dependencies
├── README.md         # This file
└── gateway_logs.db   # SQLite logs (auto-created)
```

---

## Configuration Options

### config.json

```json
{
  "active_provider": "openai",        // or "claude"
  "local_llm_mode": "mock",           // or "block"

  "file_size_limits": {
    "max_content_size_mb": 1
  },

  "blocked_keywords": [
    "confidential",
    "internal only",
    ...
  ],

  "rate_limiting": {
    "enabled": true,
    "requests_per_minute": 20
  }
}
```

---

## Production Considerations

This POC demonstrates the concept. For production:

1. **Local LLM**: Replace mock with actual Ollama/vLLM
2. **Authentication**: Add AD/LDAP integration
3. **Database**: Use PostgreSQL instead of SQLite
4. **Alerts**: Configure email/Slack notifications
5. **HTTPS**: Add SSL certificate
6. **Load Balancing**: Deploy behind nginx

---

## Troubleshooting

### "API key not configured"
Edit `config.json` and add your OpenAI/Claude API key.

### Port 8000 already in use
```bash
uvicorn main:app --port 8001
```

### Module not found
```bash
pip install -r requirements.txt
```

---

## Demo Script

For presenting to stakeholders:

1. Open Dashboard → Show stats (all zeros initially)
2. Go to "Test Chat" → Send clean query → Shows external API response
3. Send Aadhaar number → Shows BLOCKED (if in block mode)
4. Toggle to MOCK mode → Send Aadhaar → Shows local LLM simulation
5. Go to "Logs" → Show all captured requests
6. Go to "Scan Tester" → Paste code with API keys → Show detection
7. Go to "Patterns" → Show all 15+ patterns being detected

---

## Support

For issues or questions, contact the development team.

**Version:** 1.0.0 (POC)
**Date:** February 2026
