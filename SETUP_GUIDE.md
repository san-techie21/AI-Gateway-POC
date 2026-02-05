# AI Gateway POC - Complete Setup Guide

**Enterprise AI Security Layer - Motilal Oswal Financial Services**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Running the Server](#running-the-server)
6. [Using the Dashboard](#using-the-dashboard)
7. [API Reference](#api-reference)
8. [Do's and Don'ts](#dos-and-donts)
9. [Testing Guide](#testing-guide)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)
12. [Production Roadmap](#production-roadmap)

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/san-techie21/AI-Gateway-POC.git
cd AI-Gateway-POC

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Add your API key to config.json

# 4. Start the server
python main.py

# 5. Open browser
# Navigate to: http://localhost:8000
```

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.8+ | 3.10+ |
| RAM | 2 GB | 4 GB |
| Disk Space | 100 MB | 500 MB |
| OS | Windows/Linux/Mac | Any |
| Browser | Chrome/Firefox/Edge | Chrome |

**Note:** This POC does NOT require:
- GPU
- Docker
- Cloud services
- Database server (uses SQLite)

---

## Installation Steps

### Step 1: Install Python

Download Python from https://www.python.org/downloads/

Verify installation:
```bash
python --version
# Should show Python 3.8 or higher
```

### Step 2: Clone or Download Repository

**Option A - Git Clone:**
```bash
git clone https://github.com/san-techie21/AI-Gateway-POC.git
cd AI-Gateway-POC
```

**Option B - Download ZIP:**
1. Go to https://github.com/san-techie21/AI-Gateway-POC
2. Click "Code" → "Download ZIP"
3. Extract to any folder

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- FastAPI (web framework)
- Uvicorn (server)
- httpx (HTTP client)
- pydantic (data validation)
- python-multipart (file uploads)

### Step 4: Configure API Keys (Optional)

Edit `config.json` and add your API key:

```json
{
  "providers": {
    "openai": {
      "api_key": "sk-YOUR-OPENAI-KEY-HERE"
    }
  }
}
```

**Without API key:** The gateway will still work for scanning/detection. External API calls will show "API key not configured" message.

---

## Configuration

### config.json Options

| Setting | Description | Default |
|---------|-------------|---------|
| `active_provider` | Which AI to use (openai/claude) | openai |
| `local_llm_mode` | What to do with sensitive data (block/mock) | mock |
| `max_content_size_mb` | Maximum content size in MB | 1 |
| `blocked_keywords` | List of words that trigger blocking | [confidential, UPSI, ...] |
| `requests_per_minute` | Rate limit per user | 10 |

### Mode Explanation

| Mode | Behavior |
|------|----------|
| **BLOCK** | Sensitive requests are rejected with error |
| **MOCK** | Simulates local LLM response (for demo) |

---

## Running the Server

### Option 1: Python Direct
```bash
python main.py
```

### Option 2: Uvicorn (with auto-reload)
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Option 3: Windows Batch File
Double-click `start_server.bat`

**Server will be available at:** http://localhost:8000

---

## Using the Dashboard

### Dashboard Sections

| Section | Purpose |
|---------|---------|
| **Dashboard** | Overview stats, mode toggle, recent activity |
| **Test Chat** | Interactive chat to test the gateway |
| **Scan Tester** | Test content for sensitive data (no API call) |
| **Request Logs** | View all processed requests |
| **Settings** | Configure API keys, limits, keywords |
| **Detection Patterns** | View all 15+ detection patterns |

### Mode Toggle

The dashboard has a toggle switch in the top-right:
- **BLOCK Mode**: Red - Blocks sensitive requests
- **MOCK Mode**: Purple - Simulates local LLM

---

## API Reference

### POST /api/chat
Main chat endpoint with scanning.

**Request:**
```json
{
  "messages": [{"role": "user", "content": "Your message here"}],
  "user_id": "optional_user_id"
}
```

**Response (Clean):**
```json
{
  "status": "ALLOWED",
  "response": "AI response here",
  "provider": "openai"
}
```

**Response (Sensitive - Mock Mode):**
```json
{
  "status": "ROUTED_TO_LOCAL_LLM",
  "response": "[LOCAL LLM RESPONSE - SIMULATED]...",
  "data_stayed_local": true,
  "detections": [...]
}
```

### POST /api/scan
Test scanner without API calls.

**Request:**
```json
{
  "content": "Text to scan for sensitive data"
}
```

### GET /api/health
Health check endpoint.

### GET /api/logs
Get request logs with optional filters.

### GET /api/logs/stats
Get statistics summary.

---

## Do's and Don'ts

### DO's

| Do | Why |
|----|-----|
| Test with sample data first | Verify detection is working |
| Use MOCK mode for demos | Shows the concept without blocking |
| Review logs regularly | Monitor what's being detected |
| Add company-specific keywords | Customize for your organization |
| Keep API keys in config.json only | Don't hardcode in source |
| Use the Scan Tester | Test content before chat |
| Share dashboard URL with stakeholders | Easy demo access |

### DON'Ts

| Don't | Why |
|-------|-----|
| Don't use real Aadhaar/PAN for testing | Use sample numbers instead |
| Don't expose port 8000 to internet | This is a POC, not production |
| Don't disable detection for "testing" | Defeats the purpose |
| Don't commit API keys to Git | Security risk |
| Don't ignore HIGH/CRITICAL detections | These are serious data leaks |
| Don't run multiple instances on same port | Port conflict |
| Don't modify main.py patterns without testing | May break detection |

### Sample Test Data (Safe to Use)

```
Aadhaar: 2345 6789 0123 (sample)
PAN: ABCDE1234F (sample)
Phone: +91 98765 43210 (sample)
Card: 4111111111111111 (test card)
```

---

## Testing Guide

### Quick Tests

**1. Clean Query (Should PASS):**
```
What is machine learning?
```

**2. Aadhaar Detection (Should BLOCK/MOCK):**
```
My Aadhaar is 2345 6789 0123
```

**3. PAN Detection (Should BLOCK/MOCK):**
```
Process PAN ABCDE1234F for tax
```

**4. API Key Detection (Should BLOCK/MOCK):**
```
api_key = "sk-abc123xyz456789012345678901234567890"
```

**5. Blocked Keyword (Should BLOCK/MOCK):**
```
This is confidential information
```

### Running Automated Tests

```bash
python demo_test.py
```

Select option:
1. Scanner Only (no API calls)
2. Full Chat Tests
3. View Statistics
4. Run All

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Port 8000 already in use" | Kill existing process or use `--port 8001` |
| "Module not found" | Run `pip install -r requirements.txt` |
| "API key not configured" | Add key to config.json |
| Dashboard not loading | Check if server is running |
| Detection not working | Check regex patterns in main.py |

### Check Server Status

```bash
curl http://localhost:8000/api/health
```

### View Server Logs

The server prints logs to console. Look for:
- `INFO: Uvicorn running on http://0.0.0.0:8000`
- `INFO: Application startup complete`

### Reset Database

Delete `gateway_logs.db` and restart server.

---

## Security Considerations

### This POC Demonstrates:

1. **Data scanning before external API calls**
2. **PII detection** (Indian formats: Aadhaar, PAN, IFSC, etc.)
3. **Credential detection** (API keys, AWS keys, private keys)
4. **Content filtering** (blocked keywords, file size limits)
5. **Audit logging** (all requests logged)
6. **Routing decisions** (block vs. local LLM)

### For Production, Add:

| Feature | Purpose |
|---------|---------|
| HTTPS/SSL | Encrypt traffic |
| Authentication | User login (AD/LDAP) |
| Real Local LLM | Replace mock with Ollama/vLLM |
| PostgreSQL | Replace SQLite |
| Load Balancer | Handle multiple users |
| Monitoring | Prometheus/Grafana |
| Alerts | Email/Slack notifications |

---

## Production Roadmap

### Phase 1: POC (Current)
- Basic detection
- Mock local LLM
- SQLite logging
- Single user

### Phase 2: Pilot
- Add authentication
- Real local LLM (Ollama)
- Department-level deployment
- Email alerts

### Phase 3: Production
- Enterprise authentication (AD)
- GPU servers for local LLM
- PostgreSQL database
- Full monitoring
- Company-wide rollout

---

## File Structure

```
AI-Gateway-POC/
├── main.py              # Core FastAPI application
├── admin.html           # Dashboard UI
├── config.json          # Configuration
├── requirements.txt     # Python dependencies
├── README.md            # Quick reference
├── SETUP_GUIDE.md       # This file
├── demo_test.py         # Test script
├── start_server.bat     # Windows launcher
├── .gitignore           # Git ignore rules
└── gateway_logs.db      # SQLite database (auto-created)
```

---

## Support

For issues or questions:
- Review this guide
- Check troubleshooting section
- Review server console logs

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Feb 2026 | Initial POC release |

---

**Built for Motilal Oswal Financial Services**
**AI Gateway POC - Securing AI Interactions**
