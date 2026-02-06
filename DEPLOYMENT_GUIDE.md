# AI Gateway - Deployment Guide

**Version:** 1.0
**Date:** February 6, 2026
**For:** Motilal Oswal Financial Services Ltd.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (5 Minutes)](#quick-start)
3. [Production Deployment](#production-deployment)
4. [Configuration](#configuration)
5. [Active Directory Integration](#active-directory-integration)
6. [SIEM Integration (QRadar)](#siem-integration)
7. [Database Setup (SQL Server)](#database-setup)
8. [Security Hardening](#security-hardening)
9. [Monitoring & Alerts](#monitoring--alerts)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Storage | 50 GB SSD | 100 GB SSD |
| OS | Windows Server 2019 / Ubuntu 20.04 | Windows Server 2022 / Ubuntu 22.04 |

### Software Requirements

- Python 3.11+
- SQL Server 2019+ (for production audit logs)
- NGINX or IIS (reverse proxy)
- SSL Certificate (for HTTPS)

### Network Requirements

- Outbound HTTPS (443) to AI providers:
  - `api.openai.com`
  - `api.anthropic.com`
  - `api.groq.com`
  - `*.openai.azure.com` (Azure OpenAI)
  - `bedrock-runtime.*.amazonaws.com` (AWS Bedrock)
- Inbound HTTPS (443) from corporate network
- Connection to Active Directory (LDAP/389 or LDAPS/636)
- Connection to QRadar (Syslog/514 or API)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Pull the image
docker pull aigateway/mosl:latest

# Run with environment variables
docker run -d \
  --name ai-gateway \
  -p 443:8000 \
  -e AD_SERVER=ldap://dc.motilal.local:389 \
  -e AD_BASE_DN=DC=motilal,DC=local \
  -e OPENAI_API_KEY=your-key \
  -v /data/logs:/app/logs \
  aigateway/mosl:latest
```

### Option 2: Direct Installation

```bash
# Clone repository
git clone https://github.com/san-techie21/AI-Gateway-POC.git
cd AI-Gateway-POC

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Option 3: Windows Service

```powershell
# Install as Windows Service using NSSM
nssm install AIGateway "C:\AIGateway\venv\Scripts\python.exe" "C:\AIGateway\main.py"
nssm set AIGateway AppDirectory "C:\AIGateway"
nssm set AIGateway DisplayName "AI Gateway Service"
nssm start AIGateway
```

---

## Production Deployment

### Step 1: Prepare Server

```bash
# Create application directory
mkdir -p /opt/ai-gateway
cd /opt/ai-gateway

# Create service account
useradd -r -s /bin/false aigateway
```

### Step 2: Deploy Application

```bash
# Extract deployment package
tar -xzf ai-gateway-v1.0.tar.gz

# Set permissions
chown -R aigateway:aigateway /opt/ai-gateway
chmod 750 /opt/ai-gateway
```

### Step 3: Configure Environment

Create `/opt/ai-gateway/.env`:

```ini
# Server Configuration
HOST=0.0.0.0
PORT=8000
WORKERS=4
DEBUG=false

# Database (SQL Server)
DB_TYPE=mssql
DB_HOST=sqlserver.motilal.local
DB_PORT=1433
DB_NAME=AIGatewayLogs
DB_USER=aigateway_svc
DB_PASSWORD=<secure-password>

# Active Directory
AD_SERVER=ldap://dc.motilal.local:389
AD_BASE_DN=DC=motilal,DC=local
AD_BIND_USER=CN=svc_aigateway,OU=ServiceAccounts,DC=motilal,DC=local
AD_BIND_PASSWORD=<secure-password>

# SIEM (QRadar)
QRADAR_HOST=qradar.motilal.local
QRADAR_PORT=514
QRADAR_API_TOKEN=<api-token>

# AI Providers (configure at least one)
AZURE_OPENAI_ENDPOINT=https://mosl-openai.openai.azure.com/
AZURE_OPENAI_KEY=<api-key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o

# AWS Bedrock (alternative)
AWS_ACCESS_KEY_ID=<access-key>
AWS_SECRET_ACCESS_KEY=<secret-key>
AWS_REGION=ap-south-1
```

### Step 4: Create Systemd Service

Create `/etc/systemd/system/ai-gateway.service`:

```ini
[Unit]
Description=AI Gateway Service
After=network.target

[Service]
Type=simple
User=aigateway
Group=aigateway
WorkingDirectory=/opt/ai-gateway
Environment="PATH=/opt/ai-gateway/venv/bin"
ExecStart=/opt/ai-gateway/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
systemctl daemon-reload
systemctl enable ai-gateway
systemctl start ai-gateway
```

### Step 5: Configure NGINX Reverse Proxy

Create `/etc/nginx/sites-available/ai-gateway`:

```nginx
server {
    listen 443 ssl http2;
    server_name aigateway.motilal.local;

    ssl_certificate /etc/ssl/certs/aigateway.crt;
    ssl_certificate_key /etc/ssl/private/aigateway.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/ai-gateway /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## Configuration

### Admin Console Access

1. Navigate to `https://aigateway.motilal.local/`
2. Log in with AD credentials
3. Access Configuration panel

### Sensitive Data Patterns

Configure in Admin Console > Configuration > Sensitive Patterns:

| Pattern Name | Regex | Severity |
|--------------|-------|----------|
| Aadhaar Number | `[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}` | Critical |
| PAN Card | `[A-Z]{5}[0-9]{4}[A-Z]` | Critical |
| Client Code | `MOT[0-9]{8}` | Critical |
| Demat Account | `IN[0-9]{14}` | Critical |
| Trading Account | `MOSL[A-Z0-9]{10}` | Critical |

### Organization-Specific Patterns

Add your organization's specific patterns:
- Client Code Format
- Demat Account Format
- UCC Format
- Employee ID Format
- Internal Project Codes

### UPSI Keywords

Pre-configured keywords for SEBI PIT compliance:
- merger, acquisition, demerger
- quarterly results, financial results
- dividend declaration
- board meeting (financial context)
- capital restructure, buyback

---

## Active Directory Integration

### SAML 2.0 Configuration

1. Configure ADFS to trust AI Gateway as a Relying Party
2. Export ADFS Federation Metadata
3. In Admin Console > Configuration > AD Integration:
   - Set Authentication Protocol: SAML 2.0
   - Enter IdP Entity ID: `https://adfs.motilal.local/adfs/services/trust`
   - Enter IdP SSO URL: `https://adfs.motilal.local/adfs/ls/`
   - Paste IdP Certificate (PEM format)

### Role Mapping

Map AD Groups to AI Gateway roles:

| Role | AD Group | External AI | Local LLM | Admin |
|------|----------|-------------|-----------|-------|
| General Employee | CN=AllEmployees,OU=... | Yes | No | No |
| Research Analyst | CN=Research,OU=... | Yes | Yes | No |
| Strategy Team | CN=Strategy,OU=... | Yes | Yes | No |
| Compliance Team | CN=Compliance,OU=... | Yes | No | No |
| IT Admin | CN=ITAdmins,OU=... | Yes | No | No |
| Security Team | CN=Security,OU=... | Yes | No | Yes |

---

## SIEM Integration

### IBM QRadar Setup

1. In QRadar: Add new Log Source
   - Log Source Type: Universal DSM
   - Protocol: Syslog
   - Port: 514

2. In Admin Console > Configuration > SIEM / QRadar:
   - QRadar Host: `qradar.motilal.local`
   - Syslog Port: 514
   - API Token: (for advanced queries)
   - Log Format: CEF (Common Event Format)
   - Forwarding Mode: Real-time

### Log Event Types

| Event | CEF Severity | Description |
|-------|--------------|-------------|
| ALLOWED | 1 | Query allowed to external AI |
| BLOCKED | 8 | Query blocked - sensitive data |
| LOCAL_ROUTED | 3 | Query routed to local LLM |
| AUTH_SUCCESS | 1 | User authentication success |
| AUTH_FAILURE | 5 | User authentication failure |
| CONFIG_CHANGE | 4 | Admin configuration change |

---

## Database Setup

### SQL Server Configuration

```sql
-- Create database
CREATE DATABASE AIGatewayLogs;
GO

-- Create service account
CREATE LOGIN aigateway_svc WITH PASSWORD = '<secure-password>';
GO

USE AIGatewayLogs;
GO

CREATE USER aigateway_svc FOR LOGIN aigateway_svc;
GO

-- Grant permissions
GRANT CREATE TABLE TO aigateway_svc;
GRANT SELECT, INSERT, UPDATE, DELETE TO aigateway_svc;
GO
```

### Tables Created Automatically

- `request_logs` - All AI requests with timestamps, user, action, content
- `integration_events` - Webhook/SIEM event history
- `config_history` - Configuration change audit trail

### Data Retention

Configure in `.env`:
```ini
LOG_RETENTION_DAYS=1825  # 5 years per SEBI requirement
```

---

## Security Hardening

### Checklist

- [ ] Enable HTTPS only (disable HTTP)
- [ ] Use strong TLS ciphers (TLS 1.2+)
- [ ] Rotate API keys quarterly
- [ ] Enable audit logging
- [ ] Configure firewall rules
- [ ] Set up intrusion detection
- [ ] Enable MFA for admin access
- [ ] Regular security scans

### Firewall Rules

```bash
# Allow HTTPS from corporate network
ufw allow from 10.0.0.0/8 to any port 443

# Allow AD connection
ufw allow out to 10.0.1.10 port 389
ufw allow out to 10.0.1.10 port 636

# Allow SIEM connection
ufw allow out to 10.0.2.20 port 514

# Deny all other inbound
ufw default deny incoming
```

---

## Monitoring & Alerts

### Health Check Endpoint

```bash
curl https://aigateway.motilal.local/api/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "5d 12h 30m",
  "database": "connected",
  "ad": "connected",
  "siem": "connected"
}
```

### Alert Configuration

Configure email alerts in Admin Console:
- Blocked query threshold (e.g., 10/hour)
- Authentication failures
- System errors
- Budget alerts (80% of monthly limit)

---

## Troubleshooting

### Common Issues

**Issue: "Connection refused" on startup**
```bash
# Check if port is in use
netstat -tlnp | grep 8000
# Check service status
systemctl status ai-gateway
# View logs
journalctl -u ai-gateway -f
```

**Issue: AD authentication fails**
```bash
# Test LDAP connection
ldapsearch -x -H ldap://dc.motilal.local:389 -b "DC=motilal,DC=local" -D "CN=svc_aigateway,..." -W
```

**Issue: AI provider returns errors**
```bash
# Check API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### Log Locations

| Log Type | Location |
|----------|----------|
| Application | `/opt/ai-gateway/logs/app.log` |
| Access | `/opt/ai-gateway/logs/access.log` |
| Audit | SQL Server `request_logs` table |
| NGINX | `/var/log/nginx/ai-gateway.access.log` |

### Support Contacts

- Technical Issues: IT Support
- Security Incidents: Security Team
- Compliance Questions: Compliance Team

---

## Appendix: API Documentation

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for full API reference.

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/chat` | Send message to AI |
| GET | `/api/logs` | Get request logs |
| GET | `/api/config` | Get configuration |
| POST | `/api/scan` | Test content scan |

---

**Document Version:** 1.0
**Last Updated:** February 6, 2026
