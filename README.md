# AI Gateway POC

**Enterprise AI Security Layer for BFSI**
**Motilal Oswal Financial Services Ltd.**

---

## Live Demo

**URL:** https://ai-gateway-poc.onrender.com

**Test Credentials:**
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Full Admin Access |
| analyst | analyst123 | Research (External + Local AI) |
| employee | employee123 | General (External AI only) |

---

## What This Does

An intelligent security gateway that:
1. **Scans** all AI requests for sensitive data (PAN, Aadhaar, UPSI, API keys)
2. **Blocks** or **Routes** sensitive content to local LLM (data never leaves network)
3. **Allows** clean queries to external AI (Azure OpenAI, AWS Bedrock)
4. **Logs** everything for SEBI compliance (5-year audit trail)

---

## Quick Start

```bash
# Clone
git clone https://github.com/san-techie21/AI-Gateway-POC.git
cd AI-Gateway-POC

# Install
pip install -r requirements.txt

# Run
python main.py

# Open http://localhost:8000
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [HANDOVER_SUMMARY.md](HANDOVER_SUMMARY.md) | Complete delivery checklist and go-live summary |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Production deployment instructions |
| [ADMIN_MANUAL.md](ADMIN_MANUAL.md) | Admin console user guide |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | API endpoints reference |
| [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) | Security controls and design |
| [COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) | SEBI, RBI, DPDPA regulatory mapping |

---

## Deployment Options

### Docker (Recommended)
```bash
docker-compose up -d
```

### Linux VM
```bash
sudo ./scripts/install.sh
```

### Windows Server
```powershell
.\scripts\install.ps1
```

---

## Features

- **Sensitive Data Detection:** Aadhaar, PAN, Credit Cards, API Keys, UPSI keywords
- **Multi-Provider Routing:** Azure OpenAI (India), AWS Bedrock (Mumbai), Local LLM
- **Authentication:** SAML 2.0, OAuth 2.0, LDAP/Active Directory
- **SIEM Integration:** IBM QRadar, Splunk (CEF/LEEF/JSON formats)
- **Role-Based Access:** 6 configurable roles with AD group mapping
- **Admin Dashboard:** Real-time monitoring, configuration, logs

---

## Compliance

| Regulation | Status |
|------------|--------|
| SEBI AI/ML Guidelines 2025 | Compliant |
| SEBI PIT Regulations 2015 | Compliant |
| RBI Data Localization | Compliant |
| DPDPA 2023 | Compliant |

---

## Test Examples

**Blocked (Aadhaar):**
```
My Aadhaar is 2345 6789 0123
```

**Blocked (PAN):**
```
PAN number ABCDE1234F
```

**Allowed (Clean):**
```
What are the latest fintech trends?
```

---

## Repository Structure

```
AI-Gateway-POC/
├── main.py                 # FastAPI application
├── admin.html              # Admin dashboard
├── auth.py                 # Authentication module
├── qradar.py               # SIEM integration
├── config.json             # Configuration
├── Dockerfile              # Container image
├── docker-compose.yml      # Full stack deployment
├── scripts/                # VM installation scripts
├── nginx/                  # Production NGINX config
└── *.md                    # Documentation
```

---

**Go-Live Target:** February 9, 2026
**Version:** 1.0 (POC)
