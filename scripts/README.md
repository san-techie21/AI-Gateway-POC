# AI Gateway - Deployment Scripts

## Overview

This folder contains installation and deployment scripts for the AI Gateway.

## Scripts

### Linux Installation

```bash
# Make executable
chmod +x install.sh

# Run as root
sudo ./install.sh
```

**Requirements:**
- Ubuntu 20.04/22.04 or RHEL 8/9
- Python 3.11+
- Root access

### Windows Installation

```powershell
# Run as Administrator
.\install.ps1
```

**Requirements:**
- Windows Server 2019/2022
- Python 3.11+
- Administrator privileges
- (Optional) NSSM for Windows Service

## Docker Deployment

### Quick Start

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f ai-gateway

# Stop
docker-compose down
```

### Production Deployment

1. Copy `.env.template` to `.env` and configure
2. Add SSL certificates to `nginx/ssl/`
3. Run with Docker Compose

```bash
docker-compose up -d
```

## Post-Installation

1. **Configure Environment**: Edit `.env` file with your settings
2. **SSL Certificates**: Replace self-signed with production certs
3. **Active Directory**: Configure LDAP connection
4. **QRadar**: Configure SIEM integration
5. **AI Providers**: Add Azure OpenAI or AWS Bedrock API keys

## Mock Users (POC Testing)

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Security Admin |
| analyst | analyst123 | Research |
| strategy | strategy123 | Strategy |
| employee | employee123 | General |
| compliance | compliance123 | Compliance |

## Support

- Technical Issues: IT Support
- Security: Security Team
- Compliance: Compliance Team
