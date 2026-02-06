#!/bin/bash
#
# AI Gateway - Installation Script
# Motilal Oswal Financial Services Ltd.
#
# Usage: sudo ./install.sh
#
# This script installs the AI Gateway on Ubuntu 20.04/22.04 or RHEL 8/9
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "============================================="
echo "   AI Gateway - Enterprise Installation"
echo "   Motilal Oswal Financial Services"
echo "============================================="
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${YELLOW}Detected OS: $OS $VER${NC}"

# Installation directory
INSTALL_DIR="/opt/ai-gateway"
SERVICE_USER="aigateway"
SERVICE_GROUP="aigateway"

# Create service account
echo -e "${YELLOW}Creating service account...${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d $INSTALL_DIR $SERVICE_USER
    echo -e "${GREEN}Created user: $SERVICE_USER${NC}"
else
    echo -e "${GREEN}User $SERVICE_USER already exists${NC}"
fi

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt-get update
    apt-get install -y python3.11 python3.11-venv python3-pip nginx
elif [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Rocky"* ]]; then
    dnf install -y python3.11 python3-pip nginx
else
    echo -e "${YELLOW}Warning: Unsupported OS, attempting generic installation${NC}"
fi

# Create installation directory
echo -e "${YELLOW}Creating installation directory...${NC}"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
mkdir -p $INSTALL_DIR/data
mkdir -p $INSTALL_DIR/static

# Copy application files
echo -e "${YELLOW}Copying application files...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"

cp -r $APP_DIR/*.py $INSTALL_DIR/
cp -r $APP_DIR/*.html $INSTALL_DIR/
cp $APP_DIR/requirements.txt $INSTALL_DIR/
if [ -d "$APP_DIR/static" ]; then
    cp -r $APP_DIR/static/* $INSTALL_DIR/static/
fi

# Create virtual environment
echo -e "${YELLOW}Creating Python virtual environment...${NC}"
python3.11 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r $INSTALL_DIR/requirements.txt

# Create environment file template
echo -e "${YELLOW}Creating environment configuration...${NC}"
cat > $INSTALL_DIR/.env.template << 'ENVFILE'
# AI Gateway Configuration
# Copy this file to .env and update with your settings

# Server Configuration
HOST=0.0.0.0
PORT=8000
WORKERS=4
DEBUG=false

# Database (SQLite for POC, SQL Server for production)
DB_TYPE=sqlite
# DB_TYPE=mssql
# DB_HOST=sqlserver.motilal.local
# DB_PORT=1433
# DB_NAME=AIGatewayLogs
# DB_USER=aigateway_svc
# DB_PASSWORD=<secure-password>

# Active Directory
AD_SERVER=ldap://dc.motilal.local:389
AD_BASE_DN=DC=motilal,DC=local
AD_BIND_USER=CN=svc_aigateway,OU=ServiceAccounts,DC=motilal,DC=local
AD_BIND_PASSWORD=<secure-password>

# SIEM (QRadar)
QRADAR_ENABLED=true
QRADAR_HOST=qradar.motilal.local
QRADAR_PORT=514
QRADAR_API_TOKEN=<api-token>

# AI Providers (configure at least one)
AZURE_OPENAI_ENDPOINT=https://mosl-openai.openai.azure.com/
AZURE_OPENAI_KEY=<api-key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o

# AWS Bedrock (alternative)
# AWS_ACCESS_KEY_ID=<access-key>
# AWS_SECRET_ACCESS_KEY=<secret-key>
# AWS_REGION=ap-south-1
ENVFILE

if [ ! -f $INSTALL_DIR/.env ]; then
    cp $INSTALL_DIR/.env.template $INSTALL_DIR/.env
    echo -e "${YELLOW}Created .env file - please configure before starting${NC}"
fi

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
chmod 750 $INSTALL_DIR
chmod 640 $INSTALL_DIR/.env
chmod 640 $INSTALL_DIR/.env.template

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/ai-gateway.service << 'SERVICEFILE'
[Unit]
Description=AI Gateway Service
After=network.target

[Service]
Type=simple
User=aigateway
Group=aigateway
WorkingDirectory=/opt/ai-gateway
Environment="PATH=/opt/ai-gateway/venv/bin"
EnvironmentFile=/opt/ai-gateway/.env
ExecStart=/opt/ai-gateway/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ai-gateway/logs /opt/ai-gateway/data

[Install]
WantedBy=multi-user.target
SERVICEFILE

# Reload systemd
systemctl daemon-reload

# Create NGINX configuration
echo -e "${YELLOW}Creating NGINX configuration...${NC}"
cat > /etc/nginx/sites-available/ai-gateway << 'NGINXCONF'
server {
    listen 443 ssl http2;
    server_name aigateway.motilal.local;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/aigateway.crt;
    ssl_certificate_key /etc/ssl/private/aigateway.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Proxy to application
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
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # Static files
    location /static {
        alias /opt/ai-gateway/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name aigateway.motilal.local;
    return 301 https://$server_name$request_uri;
}
NGINXCONF

# Enable NGINX site
if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf /etc/nginx/sites-available/ai-gateway /etc/nginx/sites-enabled/
fi

# Create self-signed certificate for testing (replace with real cert in production)
echo -e "${YELLOW}Creating self-signed SSL certificate (for testing only)...${NC}"
if [ ! -f /etc/ssl/certs/aigateway.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/aigateway.key \
        -out /etc/ssl/certs/aigateway.crt \
        -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=Motilal Oswal/CN=aigateway.motilal.local"
    chmod 600 /etc/ssl/private/aigateway.key
fi

# Create firewall rules
echo -e "${YELLOW}Configuring firewall...${NC}"
if command -v ufw &> /dev/null; then
    ufw allow 443/tcp comment 'AI Gateway HTTPS'
    ufw allow 80/tcp comment 'AI Gateway HTTP (redirect)'
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-service=https
    firewall-cmd --permanent --add-service=http
    firewall-cmd --reload
fi

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo "Next steps:"
echo "1. Edit /opt/ai-gateway/.env with your configuration"
echo "2. Replace SSL certificates with production certs"
echo "3. Update NGINX server_name if needed"
echo "4. Start the service:"
echo "   systemctl enable ai-gateway"
echo "   systemctl start ai-gateway"
echo "   systemctl reload nginx"
echo ""
echo "5. Access the dashboard at: https://aigateway.motilal.local"
echo ""
echo -e "${YELLOW}For POC testing, you can use mock credentials:${NC}"
echo "   Username: admin / Password: admin123"
echo "   Username: analyst / Password: analyst123"
echo ""
