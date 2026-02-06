# AI Gateway - Admin Manual

**Version:** 1.0
**Date:** February 6, 2026
**For:** Motilal Oswal Financial Services Ltd.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Chat Interface](#chat-interface)
4. [Request Logs](#request-logs)
5. [Configuration Panel](#configuration-panel)
6. [User Management](#user-management)
7. [Best Practices](#best-practices)

---

## Getting Started

### Accessing the Admin Console

1. Open your browser and navigate to `https://aigateway.motilal.local/`
2. You will be redirected to the AD login page
3. Enter your corporate credentials
4. Upon successful authentication, you'll see the Admin Console

### First-Time Setup Checklist

- [ ] Verify your role permissions (check with Security Team if needed)
- [ ] Review default sensitive data patterns
- [ ] Configure organization-specific patterns (Client Code, Demat, etc.)
- [ ] Test the chat interface with a sample query
- [ ] Verify SIEM integration is receiving logs

---

## Dashboard Overview

The Dashboard provides real-time visibility into AI Gateway usage.

### Statistics Cards

| Card | Description |
|------|-------------|
| **Total Requests** | All queries processed through the gateway |
| **Allowed to External** | Queries sent to external AI providers (Azure OpenAI, AWS Bedrock) |
| **Blocked** | Queries blocked due to sensitive data detection |
| **Routed to Local LLM** | Queries processed by internal LLM (for authorized users) |

### Interpreting the Numbers

- **High Blocked Count**: May indicate users need training on data handling
- **High Local LLM Usage**: Research/Strategy teams actively using internal AI
- **Zero External**: Check if AI provider connection is working

### Recent Activity Table

Shows the latest 10 requests with:
- Timestamp
- User ID (from AD)
- Action taken (Allowed/Blocked/Local)
- Provider used
- Content preview (first 50 characters)

---

## Chat Interface

### Sending a Query

1. Click on the **Chat** tab
2. Type your question in the input field
3. Click **Send** or press Enter
4. Wait for the response

### Understanding Responses

**Successful Response:**
- Shows the AI-generated answer
- Displays which provider was used
- Shows response time

**Blocked Response:**
- Red warning banner appears
- Lists detected sensitive patterns
- No query is sent to external AI
- Event logged for compliance

### Tips for Users

- Avoid including personal identifiers (Aadhaar, PAN, Client Codes)
- Use generic descriptions instead of specific account numbers
- If blocked, rephrase without sensitive data

---

## Request Logs

### Accessing Logs

1. Click on the **Request Logs** tab
2. Logs are displayed in reverse chronological order

### Filtering Options

| Filter | Options |
|--------|---------|
| **Action** | All, Allowed, Blocked, Local |
| **Date Range** | Today, Last 7 Days, Last 30 Days, Custom |
| **User** | Search by User ID |

### Log Entry Details

Each log entry shows:
- **ID**: Unique request identifier
- **Timestamp**: When the request was made
- **User ID**: AD username
- **Action**: What happened to the query
- **Provider**: Which AI service processed it
- **Content Preview**: First 50 characters (hashed for blocked)
- **Detections**: Patterns that triggered blocking (if any)

### Exporting Logs

1. Apply desired filters
2. Click **Export CSV** button
3. File downloads with filtered data
4. Use for compliance reporting or analysis

---

## Configuration Panel

### Tab 1: Sensitive Patterns

Configure regex patterns to detect sensitive data.

**Default Patterns (Pre-configured):**

| Pattern | Regex | Description |
|---------|-------|-------------|
| Aadhaar Number | `[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}` | 12-digit Indian ID |
| PAN Card | `[A-Z]{5}[0-9]{4}[A-Z]` | Permanent Account Number |
| Credit Card | `[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}` | 16-digit card |
| API Key | `(sk-[a-zA-Z0-9]{32,})\|(AKIA[0-9A-Z]{16})` | OpenAI/AWS keys |
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | Email addresses |
| Phone | `(\+91[\s-]?)?[6-9][0-9]{9}` | Indian mobile numbers |

**Adding Custom Patterns:**

1. Click **+ Add Pattern**
2. Enter Pattern Name (e.g., "Client Code")
3. Enter Regex (e.g., `MOT[0-9]{8}`)
4. Select Severity (Low/Medium/High/Critical)
5. Toggle Active status
6. Click **Save Changes**

**Testing Patterns:**

1. Use the `/api/scan` endpoint to test
2. Or use the Chat interface with test data

### Tab 2: Roles & Access

Configure which AD groups have access to which features.

**Role Matrix:**

| Role | External AI | Local LLM | Admin Dashboard |
|------|-------------|-----------|-----------------|
| General Employee | ✓ | ✗ | ✗ |
| Research Analyst | ✓ | ✓ | ✗ |
| Strategy Team | ✓ | ✓ | ✗ |
| Compliance Team | ✓ | ✗ | ✗ |
| IT Admin | ✓ | ✗ | ✗ |
| Security Team | ✓ | ✗ | ✓ |

**Modifying Access:**

1. Find the role row
2. Toggle the appropriate switches (green = enabled)
3. Click **Save Changes**

### Tab 3: AD Integration

Configure Active Directory connection.

**Settings:**

| Field | Description | Example |
|-------|-------------|---------|
| AD Server | LDAP server URL | `ldap://dc.motilal.local:389` |
| Base DN | Search base | `DC=motilal,DC=local` |
| Bind User DN | Service account | `CN=svc_aigateway,OU=ServiceAccounts,DC=motilal,DC=local` |
| Bind Password | Service account password | (encrypted) |
| Auth Protocol | SAML 2.0 or OAuth 2.0 | SAML 2.0 |

**Testing Connection:**

1. Click **Test Connection** button
2. Success: Green checkmark appears
3. Failure: Error message with details

### Tab 4: SIEM / QRadar

Configure security event forwarding.

**Settings:**

| Field | Description | Example |
|-------|-------------|---------|
| QRadar Host | SIEM server hostname | `qradar.motilal.local` |
| Syslog Port | UDP port for syslog | `514` |
| API Token | For advanced queries | (encrypted) |
| Log Format | Event format | CEF (recommended) |
| Forwarding Mode | When to send | Real-time |

**Event Types Forwarded:**

- ALLOWED (severity 1)
- BLOCKED (severity 8)
- LOCAL_ROUTED (severity 3)
- AUTH_SUCCESS (severity 1)
- AUTH_FAILURE (severity 5)
- CONFIG_CHANGE (severity 4)

### Tab 5: Scale & Quotas

Configure usage limits and cost controls.

**Settings:**

| Field | Description | Default |
|-------|-------------|---------|
| Total Users | Expected user count | 1000 |
| Daily Active Users | Concurrent users | 200 |
| Queries/User/Day | Rate limit | 50 |
| Monthly API Budget | Cost ceiling | ₹500,000 |

**Rate Limit Tiers:**

| Tier | Per Hour | Per Day |
|------|----------|---------|
| General | 20 | 100 |
| Research | 50 | 500 |
| Strategy | 50 | 500 |

---

## User Management

### Viewing Users

User management is handled through Active Directory. The gateway reads user information from AD groups.

### Role Assignment

1. Add users to appropriate AD groups in Active Directory
2. AI Gateway automatically picks up group membership
3. No manual user creation needed in the gateway

### Troubleshooting Access Issues

1. Verify user is in correct AD group
2. Check if group is mapped in Roles & Access tab
3. Have user log out and log back in
4. Check authentication logs for errors

---

## Best Practices

### For Administrators

1. **Review logs weekly** - Look for patterns in blocked queries
2. **Update patterns quarterly** - Add new sensitive data patterns as needed
3. **Monitor rate limits** - Adjust based on actual usage
4. **Test after changes** - Always test pattern changes in staging first
5. **Document custom patterns** - Keep records of why patterns were added

### For Users

1. **Don't include PII** - Avoid personal identifiers in queries
2. **Use generic terms** - Say "a client" instead of specific client codes
3. **Report false positives** - If legitimate queries are blocked, report to admin
4. **Understand the purpose** - The gateway protects sensitive data

### Security Guidelines

1. **Never share credentials** - Each user should use their own AD account
2. **Log out when done** - Especially on shared workstations
3. **Report suspicious activity** - Contact Security Team immediately
4. **Don't bypass the gateway** - All AI queries must go through the gateway

---

## Appendix: Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Send message in chat |
| `Ctrl + L` | Clear chat history |
| `Ctrl + /` | Focus search in logs |

---

## Support

- **Technical Issues**: IT Support Desk
- **Access Problems**: IT Security Team
- **Compliance Questions**: Compliance Team
- **Feature Requests**: Product Team

---

**Document Version:** 1.0
**Last Updated:** February 6, 2026
