#
# AI Gateway - Windows Installation Script
# Motilal Oswal Financial Services Ltd.
#
# Usage: Run as Administrator
#   .\install.ps1
#

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host @"
=============================================
   AI Gateway - Enterprise Installation
   Motilal Oswal Financial Services
   Windows Server Edition
=============================================
"@ -ForegroundColor Green

# Configuration
$InstallDir = "C:\AIGateway"
$ServiceName = "AIGateway"
$ServiceDisplayName = "AI Gateway Service"
$PythonVersion = "3.11"
$Port = 8000

# Check if Python is installed
Write-Host "Checking Python installation..." -ForegroundColor Yellow
$pythonPath = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonPath) {
    Write-Host "Python not found. Please install Python $PythonVersion from python.org" -ForegroundColor Red
    Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

$pythonVer = python --version 2>&1
Write-Host "Found: $pythonVer" -ForegroundColor Green

# Create installation directory
Write-Host "Creating installation directory..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
New-Item -ItemType Directory -Path "$InstallDir\logs" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\data" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\static" -Force | Out-Null

# Copy application files
Write-Host "Copying application files..." -ForegroundColor Yellow
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Split-Path -Parent $ScriptDir

Copy-Item "$AppDir\*.py" -Destination $InstallDir -Force
Copy-Item "$AppDir\*.html" -Destination $InstallDir -Force
Copy-Item "$AppDir\requirements.txt" -Destination $InstallDir -Force
if (Test-Path "$AppDir\static") {
    Copy-Item "$AppDir\static\*" -Destination "$InstallDir\static" -Recurse -Force
}

# Create virtual environment
Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
Set-Location $InstallDir
python -m venv venv

# Activate and install dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
& "$InstallDir\venv\Scripts\pip.exe" install --upgrade pip
& "$InstallDir\venv\Scripts\pip.exe" install -r requirements.txt

# Create environment file template
Write-Host "Creating environment configuration..." -ForegroundColor Yellow
$envTemplate = @"
# AI Gateway Configuration
# Rename this file to .env and update with your settings

# Server Configuration
HOST=0.0.0.0
PORT=$Port
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
"@

$envTemplate | Out-File -FilePath "$InstallDir\.env.template" -Encoding UTF8
if (-not (Test-Path "$InstallDir\.env")) {
    Copy-Item "$InstallDir\.env.template" -Destination "$InstallDir\.env"
    Write-Host "Created .env file - please configure before starting" -ForegroundColor Yellow
}

# Check if NSSM is installed (for Windows Service)
Write-Host "Checking for NSSM (Non-Sucking Service Manager)..." -ForegroundColor Yellow
$nssmPath = Get-Command nssm -ErrorAction SilentlyContinue

if ($nssmPath) {
    Write-Host "Installing as Windows Service using NSSM..." -ForegroundColor Yellow

    # Remove existing service if present
    & nssm stop $ServiceName 2>$null
    & nssm remove $ServiceName confirm 2>$null

    # Install service
    & nssm install $ServiceName "$InstallDir\venv\Scripts\uvicorn.exe"
    & nssm set $ServiceName AppParameters "main:app --host 0.0.0.0 --port $Port --workers 4"
    & nssm set $ServiceName AppDirectory $InstallDir
    & nssm set $ServiceName DisplayName $ServiceDisplayName
    & nssm set $ServiceName Description "AI Gateway - Enterprise AI Security Layer"
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm set $ServiceName AppStdout "$InstallDir\logs\service.log"
    & nssm set $ServiceName AppStderr "$InstallDir\logs\error.log"
    & nssm set $ServiceName AppRotateFiles 1
    & nssm set $ServiceName AppRotateBytes 10485760

    Write-Host "Windows Service installed successfully" -ForegroundColor Green
} else {
    Write-Host @"
NSSM not found. To install as a Windows Service:
1. Download NSSM from https://nssm.cc/download
2. Extract and add to PATH
3. Run: nssm install AIGateway
4. Or run manually: $InstallDir\venv\Scripts\uvicorn.exe main:app --host 0.0.0.0 --port $Port
"@ -ForegroundColor Yellow
}

# Create batch file for manual start
$startBat = @"
@echo off
cd /d "$InstallDir"
call venv\Scripts\activate.bat
uvicorn main:app --host 0.0.0.0 --port $Port --workers 4
"@
$startBat | Out-File -FilePath "$InstallDir\start.bat" -Encoding ASCII

# Configure Windows Firewall
Write-Host "Configuring Windows Firewall..." -ForegroundColor Yellow
$ruleName = "AI Gateway HTTPS"
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    Write-Host "Firewall rule created for port $Port" -ForegroundColor Green
}

# Create IIS configuration (optional)
Write-Host "Creating IIS configuration file..." -ForegroundColor Yellow
$iisConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified"/>
        </handlers>
        <aspNetCore processPath="$InstallDir\venv\Scripts\uvicorn.exe"
                    arguments="main:app --host 127.0.0.1 --port $Port"
                    stdoutLogEnabled="true"
                    stdoutLogFile="$InstallDir\logs\stdout"
                    hostingModel="OutOfProcess">
            <environmentVariables>
                <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production"/>
            </environmentVariables>
        </aspNetCore>
    </system.webServer>
</configuration>
"@
$iisConfig | Out-File -FilePath "$InstallDir\web.config" -Encoding UTF8

Write-Host @"

=============================================
   Installation Complete!
=============================================

Next steps:
1. Edit $InstallDir\.env with your configuration
2. Configure SSL certificates in IIS or use reverse proxy
3. Start the service:

   Using NSSM (if installed):
   nssm start AIGateway

   Or run manually:
   $InstallDir\start.bat

4. Access the dashboard at: http://localhost:$Port

For POC testing, you can use mock credentials:
   Username: admin / Password: admin123
   Username: analyst / Password: analyst123

"@ -ForegroundColor Green
