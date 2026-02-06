# AI Gateway - Compliance Mapping

**Version:** 1.0
**Date:** February 6, 2026
**For:** Motilal Oswal Financial Services Ltd.

---

## Overview

This document maps AI Gateway features to regulatory requirements applicable to financial services organizations in India. The gateway has been designed to ensure compliance with SEBI, RBI, and data protection regulations.

---

## Regulatory Framework

### Applicable Regulations

| Regulation | Issuing Authority | Applicability |
|------------|-------------------|---------------|
| SEBI AI/ML Guidelines 2025 | Securities and Exchange Board of India | AI usage in financial services |
| SEBI PIT Regulations 2015 | Securities and Exchange Board of India | Prevention of insider trading |
| RBI Data Localization | Reserve Bank of India | Storage of financial data |
| DPDPA 2023 | Government of India | Personal data protection |
| FIU-IND Reporting | Financial Intelligence Unit | Suspicious transaction reporting |
| ISO 27001 | International Organization for Standardization | Information security management |

---

## SEBI AI/ML Guidelines 2025

### Requirement 1: AI Governance Framework

> Organizations must establish governance frameworks for AI/ML systems.

| Requirement | AI Gateway Implementation | Status |
|-------------|--------------------------|--------|
| Defined roles and responsibilities | Role-based access control with AD integration | ✅ Compliant |
| Approval process for AI usage | All queries logged with user attribution | ✅ Compliant |
| Regular monitoring and review | Real-time dashboard and SIEM integration | ✅ Compliant |
| Documentation of AI systems | Full documentation package provided | ✅ Compliant |

### Requirement 2: Data Protection in AI

> Ensure sensitive data is not exposed through AI systems.

| Requirement | AI Gateway Implementation | Status |
|-------------|--------------------------|--------|
| PII detection and prevention | Regex-based content scanning | ✅ Compliant |
| Client data protection | Client code patterns blocked | ✅ Compliant |
| Encryption requirements | TLS 1.2+ for all communications | ✅ Compliant |
| Access controls | RBAC with AD authentication | ✅ Compliant |

### Requirement 3: Audit Trail

> Maintain complete audit trail of AI system usage.

| Requirement | AI Gateway Implementation | Status |
|-------------|--------------------------|--------|
| All transactions logged | Every request logged with full metadata | ✅ Compliant |
| User identification | AD username captured for each request | ✅ Compliant |
| Timestamp recording | UTC timestamps on all events | ✅ Compliant |
| Log retention | 5-year retention configured | ✅ Compliant |
| Tamper-proof logs | SQL Server with TDE encryption | ✅ Compliant |

---

## SEBI PIT Regulations 2015

### Prevention of Insider Trading

> Prevent leakage of Unpublished Price Sensitive Information (UPSI).

| UPSI Category | Detection Method | Action |
|---------------|------------------|--------|
| Financial Results | Keywords: "quarterly results", "financial results", "revenue", "profit" | Block + Alert |
| Mergers & Acquisitions | Keywords: "merger", "acquisition", "demerger", "takeover" | Block + Alert |
| Dividend Announcements | Keywords: "dividend declaration", "interim dividend" | Block + Alert |
| Capital Restructure | Keywords: "buyback", "capital restructure", "rights issue" | Block + Alert |
| Material Events | Keywords: "board meeting", "material event" | Block + Alert |

### Implementation Details

```
User Query → Content Scanner → UPSI Keyword Detection
                                      ↓
                              ┌───────┴───────┐
                              │   UPSI Found  │
                              └───────┬───────┘
                                      ↓
                    ┌─────────────────┼─────────────────┐
                    ↓                 ↓                 ↓
              Block Query      Log to SIEM      Alert Compliance
                    ↓                 ↓                 ↓
              Return Error    CEF Event Sent    Email Notification
```

### Compliance Evidence

| Control | Evidence Location |
|---------|-------------------|
| UPSI keyword list | Admin Console > Configuration > Sensitive Patterns |
| Blocked query logs | SQL Server `request_logs` table |
| Real-time alerts | QRadar SIEM dashboard |
| Audit reports | Admin Console > Request Logs > Export |

---

## RBI Data Localization

### Requirement

> Payment system data and financial information must be stored in India.

| Requirement | AI Gateway Implementation | Status |
|-------------|--------------------------|--------|
| Data stored in India | SQL Server hosted on-premises in India | ✅ Compliant |
| AI providers in India | Azure OpenAI (Mumbai), AWS Bedrock (Mumbai) | ✅ Compliant |
| No cross-border transfer | Firewall blocks non-India endpoints | ✅ Compliant |

### Technical Controls

**Allowed AI Provider Endpoints (India Only):**
- `mosl-openai.openai.azure.com` (Azure Mumbai)
- `bedrock-runtime.ap-south-1.amazonaws.com` (AWS Mumbai)

**Blocked Endpoints:**
- `api.openai.com` (US)
- `bedrock-runtime.us-east-1.amazonaws.com` (US)
- All non-India regions

---

## DPDPA 2023 (Digital Personal Data Protection Act)

### Personal Data Categories

| Data Type | Detection Pattern | Protection Level |
|-----------|-------------------|------------------|
| Aadhaar Number | `[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}` | Critical - Always blocked |
| PAN Card | `[A-Z]{5}[0-9]{4}[A-Z]` | Critical - Always blocked |
| Mobile Number | `(\+91[\s-]?)?[6-9][0-9]{9}` | High - Always blocked |
| Email Address | Standard email pattern | Medium - Configurable |

### Data Principal Rights

| Right | AI Gateway Support |
|-------|-------------------|
| Right to Access | Logs available for export |
| Right to Correction | N/A (gateway doesn't store personal data) |
| Right to Erasure | Content blocked, not stored |
| Right to Grievance Redressal | Contact Compliance Team |

### Consent Management

- **Implicit Consent**: Users consent to monitoring by using corporate systems
- **Explicit Consent**: AD login constitutes consent to policy
- **Data Purpose**: Limited to security and compliance monitoring

---

## FIU-IND Reporting

### Suspicious Transaction Monitoring

| Indicator | Detection | Reporting |
|-----------|-----------|-----------|
| Multiple blocked attempts | Threshold alert (10/hour) | Manual review required |
| UPSI pattern attempts | Real-time SIEM alert | Immediate escalation |
| After-hours access | Anomaly detection | Daily report |

### Integration with Existing STR Process

The AI Gateway feeds into the organization's existing STR (Suspicious Transaction Report) workflow:

1. Gateway detects suspicious pattern
2. Event logged to QRadar
3. QRadar correlation rules trigger alert
4. Compliance Team investigates
5. STR filed if required

---

## ISO 27001 Controls

### Annex A Control Mapping

| Control | ISO 27001 Reference | Implementation |
|---------|---------------------|----------------|
| Access Control | A.9 | AD integration, RBAC |
| Cryptography | A.10 | TLS 1.2+, SQL TDE |
| Operations Security | A.12 | Logging, monitoring |
| Communications Security | A.13 | Encrypted channels |
| Supplier Relationships | A.15 | AI provider agreements |
| Incident Management | A.16 | SIEM integration, alerts |
| Compliance | A.18 | Audit logging, retention |

### Control Evidence

| Control Category | Evidence Type | Location |
|-----------------|---------------|----------|
| Access Control | User access logs | SQL Server + QRadar |
| Encryption | TLS certificates | Server configuration |
| Logging | Request logs | SQL Server `request_logs` |
| Monitoring | SIEM events | QRadar dashboard |
| Change Management | Config history | SQL Server `config_history` |

---

## Compliance Reporting

### Regular Reports

| Report | Frequency | Recipient | Content |
|--------|-----------|-----------|---------|
| Usage Summary | Weekly | IT Management | Total queries, blocked count |
| Security Incidents | Weekly | Security Team | Blocked queries, patterns |
| UPSI Attempts | Daily | Compliance | Any UPSI keyword detections |
| Access Review | Quarterly | Audit | User access patterns |
| Full Audit | Annually | External Auditors | Complete system review |

### Generating Reports

**From Admin Console:**
1. Navigate to Request Logs
2. Apply date filters
3. Click Export CSV
4. Process in Excel for reporting

**From API:**
```bash
GET /api/logs?from_date=2026-01-01&to_date=2026-01-31&action=blocked
```

**From SQL Server:**
```sql
SELECT
    COUNT(*) as total_requests,
    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) as allowed
FROM request_logs
WHERE timestamp >= '2026-01-01' AND timestamp < '2026-02-01';
```

---

## Audit Preparation Checklist

### Documentation Ready

- [x] System architecture diagram
- [x] Security architecture document
- [x] Data flow diagrams
- [x] Access control matrix
- [x] API documentation
- [x] Deployment guide

### Evidence Collection

- [ ] Export 12 months of request logs
- [ ] Export configuration change history
- [ ] Document current pattern configurations
- [ ] Screenshot of role mappings
- [ ] SIEM integration proof
- [ ] Penetration test results

### Interview Preparation

| Topic | Document Reference |
|-------|-------------------|
| System Overview | DEPLOYMENT_GUIDE.md |
| Security Controls | SECURITY_ARCHITECTURE.md |
| Data Protection | This document |
| Operations | ADMIN_MANUAL.md |
| Technical Details | API_DOCUMENTATION.md |

---

## Gap Analysis

### Current Compliance Status

| Regulation | Compliance Level | Notes |
|------------|------------------|-------|
| SEBI AI/ML 2025 | ✅ Fully Compliant | All controls implemented |
| SEBI PIT 2015 | ✅ Fully Compliant | UPSI detection active |
| RBI Localization | ✅ Fully Compliant | India-only providers |
| DPDPA 2023 | ✅ Fully Compliant | PII blocking active |
| ISO 27001 | ✅ Fully Compliant | All Annex A controls mapped |

### Recommended Enhancements

| Enhancement | Priority | Timeline |
|-------------|----------|----------|
| Machine learning-based pattern detection | Medium | Q3 2026 |
| Automated STR integration | Low | Q4 2026 |
| Real-time compliance dashboard | Medium | Q2 2026 |

---

## Appendix: Pattern Configuration for Compliance

### Critical Patterns (Must Enable)

```
Aadhaar: [2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}
PAN: [A-Z]{5}[0-9]{4}[A-Z]
Client Code: MOT[0-9]{8}  (customize to your format)
Demat: IN[0-9]{14}
```

### UPSI Keywords (Must Enable)

```
merger, acquisition, demerger, takeover
quarterly results, financial results, annual results
dividend, interim dividend, final dividend
buyback, rights issue, capital restructure
board meeting, AGM, EGM
material event, price sensitive
```

---

**Document Version:** 1.0
**Last Updated:** February 6, 2026
**Review Date:** August 2026
