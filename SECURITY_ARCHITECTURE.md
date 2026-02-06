# AI Gateway - Security Architecture

**Version:** 1.0
**Date:** February 6, 2026
**Classification:** Internal Use Only
**For:** Motilal Oswal Financial Services Ltd.

---

## Executive Summary

The AI Gateway provides a secure, compliant interface for enterprise AI usage. This document outlines the security architecture, threat model, and controls implemented to protect sensitive data and ensure regulatory compliance.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CORPORATE NETWORK                                │
│  ┌─────────────┐                                                        │
│  │   Users     │                                                        │
│  │  (Browser)  │                                                        │
│  └──────┬──────┘                                                        │
│         │ HTTPS (TLS 1.2+)                                              │
│         ▼                                                                │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │   NGINX     │────▶│  AI Gateway │────▶│   SQL       │               │
│  │  (Reverse   │     │  (FastAPI)  │     │   Server    │               │
│  │   Proxy)    │     └──────┬──────┘     │  (Audit DB) │               │
│  └─────────────┘            │            └─────────────┘               │
│                             │                                           │
│         ┌───────────────────┼───────────────────┐                       │
│         ▼                   ▼                   ▼                       │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │   Active    │     │   QRadar    │     │   Local     │               │
│  │  Directory  │     │   (SIEM)    │     │    LLM      │               │
│  └─────────────┘     └─────────────┘     │  (Optional) │               │
│                                          └─────────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (Encrypted)
                              ▼
              ┌───────────────────────────────────┐
              │        EXTERNAL AI PROVIDERS       │
              │  ┌─────────┐    ┌─────────┐       │
              │  │ Azure   │    │  AWS    │       │
              │  │ OpenAI  │    │ Bedrock │       │
              │  │(Mumbai) │    │(Mumbai) │       │
              │  └─────────┘    └─────────┘       │
              └───────────────────────────────────┘
```

---

## Security Layers

### Layer 1: Network Security

| Control | Implementation |
|---------|----------------|
| **Firewall** | Corporate firewall with whitelist-only outbound |
| **TLS Encryption** | TLS 1.2+ for all connections |
| **Network Segmentation** | Gateway in DMZ, isolated from internal systems |
| **DDoS Protection** | Rate limiting at NGINX and application level |

**Allowed Outbound Connections:**
- `*.openai.azure.com:443` (Azure OpenAI)
- `bedrock-runtime.ap-south-1.amazonaws.com:443` (AWS Bedrock)
- `dc.motilal.local:389/636` (Active Directory)
- `qradar.motilal.local:514` (SIEM)

### Layer 2: Authentication & Authorization

| Control | Implementation |
|---------|----------------|
| **Identity Provider** | On-premises Active Directory |
| **SSO Protocol** | SAML 2.0 / OAuth 2.0 |
| **Session Management** | Secure cookies, 30-minute timeout |
| **MFA** | Integrated with AD MFA policies |

**Role-Based Access Control (RBAC):**

```
User → AD Group → AI Gateway Role → Permissions
```

| Role | External AI | Local LLM | Admin Panel | Config |
|------|-------------|-----------|-------------|--------|
| General Employee | ✓ | ✗ | ✗ | ✗ |
| Research Analyst | ✓ | ✓ | ✗ | ✗ |
| Strategy Team | ✓ | ✓ | ✗ | ✗ |
| Compliance Team | ✓ | ✗ | ✗ | ✗ |
| IT Admin | ✓ | ✗ | ✗ | ✗ |
| Security Team | ✓ | ✗ | ✓ | ✓ |

### Layer 3: Data Protection

| Control | Implementation |
|---------|----------------|
| **Content Scanning** | Real-time regex pattern matching |
| **Data Masking** | Sensitive data hashed in logs |
| **Encryption at Rest** | SQL Server TDE |
| **Encryption in Transit** | TLS 1.2+ everywhere |

**Sensitive Data Detection Patterns:**

| Category | Pattern | Action |
|----------|---------|--------|
| Aadhaar Number | 12-digit format | Block + Alert |
| PAN Card | ABCDE1234F format | Block + Alert |
| Client Codes | Organization-specific | Block + Alert |
| Demat Accounts | IN + 14 digits | Block + Alert |
| API Keys | sk-*, AKIA* | Block + Alert |
| UPSI Keywords | merger, acquisition, etc. | Block + Alert |

### Layer 4: Application Security

| Control | Implementation |
|---------|----------------|
| **Input Validation** | All inputs sanitized before processing |
| **Output Encoding** | XSS prevention on all outputs |
| **CSRF Protection** | Token-based protection |
| **Rate Limiting** | Per-user quotas enforced |

**Request Processing Flow:**

```
1. Receive Request
       ↓
2. Validate Authentication
       ↓
3. Check Authorization (RBAC)
       ↓
4. Scan Content for Sensitive Data ←── CRITICAL CONTROL
       ↓
   ┌───┴───┐
   │Blocked│ → Log Event → Send to SIEM → Return Error
   └───────┘
       ↓ (Clean)
5. Apply Rate Limiting
       ↓
6. Route to AI Provider
       ↓
7. Log Request/Response
       ↓
8. Return to User
```

### Layer 5: Audit & Monitoring

| Control | Implementation |
|---------|----------------|
| **Request Logging** | All requests logged with user, timestamp, action |
| **SIEM Integration** | Real-time event forwarding to QRadar |
| **Alerting** | Configurable thresholds for blocked queries |
| **Log Retention** | 5 years per SEBI requirements |

**Events Logged:**

| Event Type | Logged Data | Retention |
|------------|-------------|-----------|
| ALLOWED | User, timestamp, provider, content hash | 5 years |
| BLOCKED | User, timestamp, patterns matched, full content | 5 years |
| AUTH_SUCCESS | User, timestamp, IP address | 1 year |
| AUTH_FAILURE | Username attempted, IP, reason | 1 year |
| CONFIG_CHANGE | Admin user, change details | 5 years |

---

## Threat Model

### Threat 1: Data Exfiltration via AI Queries

**Threat:** Employee attempts to send sensitive client data to external AI.

**Controls:**
- Content scanning with regex patterns
- Automatic blocking of detected PII
- Real-time alerting to Security Team
- Full audit trail for investigation

**Residual Risk:** Low

### Threat 2: Unauthorized Access

**Threat:** Unauthorized user gains access to AI Gateway.

**Controls:**
- AD authentication required
- Role-based access control
- Session timeout (30 minutes)
- Failed login monitoring

**Residual Risk:** Low

### Threat 3: UPSI Leakage

**Threat:** UPSI (Unpublished Price Sensitive Information) sent to external AI.

**Controls:**
- UPSI keyword detection
- Automatic blocking with SEBI-aligned keywords
- Compliance team alerting
- Full audit trail for regulatory reporting

**Residual Risk:** Low

### Threat 4: API Key Exposure

**Threat:** Organization's AI provider API keys leaked.

**Controls:**
- Keys stored encrypted in environment variables
- Never exposed to client-side code
- Key rotation procedures in place
- Anomaly detection on API usage

**Residual Risk:** Low

### Threat 5: Man-in-the-Middle Attack

**Threat:** Attacker intercepts communication between gateway and AI provider.

**Controls:**
- TLS 1.2+ enforced on all connections
- Certificate validation enabled
- No HTTP fallback allowed
- HSTS headers enforced

**Residual Risk:** Very Low

---

## Compliance Mapping

| Regulation | Requirement | AI Gateway Control |
|------------|-------------|-------------------|
| **SEBI PIT 2015** | Prevent UPSI leakage | Keyword detection + blocking |
| **SEBI AI/ML 2025** | AI usage governance | Full audit logging |
| **RBI Data Localization** | Data must stay in India | Azure/AWS Mumbai regions only |
| **DPDPA 2023** | Protect personal data | PII detection + blocking |
| **ISO 27001** | Access control | RBAC + AD integration |

---

## Key Management

### API Keys

| Key Type | Storage | Rotation |
|----------|---------|----------|
| Azure OpenAI | Encrypted env var | Quarterly |
| AWS Bedrock | Encrypted env var | Quarterly |
| QRadar API | Encrypted env var | Annually |

### Encryption Keys

| Key Type | Algorithm | Storage |
|----------|-----------|---------|
| TLS Certificate | RSA 2048+ | File system (restricted) |
| Database TDE | AES-256 | SQL Server managed |
| Session Cookies | AES-256 | Application memory |

---

## Incident Response

### Severity Levels

| Level | Definition | Response Time |
|-------|------------|---------------|
| **Critical** | Data breach confirmed | Immediate |
| **High** | Attempted data exfiltration | 1 hour |
| **Medium** | Multiple blocked attempts | 4 hours |
| **Low** | Single blocked attempt | 24 hours |

### Response Procedures

**Critical/High Severity:**
1. Isolate affected user account
2. Notify Security Team immediately
3. Preserve all logs
4. Begin forensic investigation
5. Report to Compliance if regulatory impact

**Medium/Low Severity:**
1. Review logs for patterns
2. Determine if user training needed
3. Update detection patterns if false positive
4. Document in incident log

---

## Security Testing

### Regular Testing Schedule

| Test Type | Frequency | Responsibility |
|-----------|-----------|----------------|
| Vulnerability Scan | Weekly | IT Security |
| Penetration Test | Annually | External Vendor |
| Pattern Testing | Monthly | Security Team |
| Access Review | Quarterly | IT Admin + Compliance |

### Pre-Deployment Checklist

- [ ] All default passwords changed
- [ ] TLS certificates valid and installed
- [ ] Firewall rules configured
- [ ] AD integration tested
- [ ] SIEM integration verified
- [ ] Sensitive patterns configured
- [ ] Rate limits set appropriately
- [ ] Backup procedures documented
- [ ] Incident response plan reviewed

---

## Appendix: Security Contacts

| Role | Responsibility |
|------|----------------|
| Security Team | Security incidents, access reviews |
| IT Admin | Technical issues, system maintenance |
| Compliance Team | Regulatory queries, audit support |
| Vendor Support | AI provider issues |

---

**Document Version:** 1.0
**Classification:** Internal Use Only
**Last Updated:** February 6, 2026
