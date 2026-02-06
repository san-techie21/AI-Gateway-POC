# AI Gateway Implementation - Information Checklist

**For:** Motilal Oswal Financial Services Ltd.
**Prepared by:** External Consultant
**Date:** February 6, 2026

---

## Purpose
This checklist captures the information needed to build a production-ready, audit-compliant AI Gateway that your internal team can deploy. The software will be delivered as a complete package - your team only needs to:
1. Deploy to your cloud/infrastructure
2. Connect to Active Directory
3. Configure API keys
4. Run the setup script

---

## SECTION A: Infrastructure & Cloud

### A1. Cloud Environment
- [ ] Which cloud provider do you primarily use?
  - [ ] Microsoft Azure
  - [ ] Amazon Web Services (AWS)
  - [ ] Google Cloud Platform (GCP)
  - [ ] On-premise data center only
  - [ ] Hybrid (specify): ________________

- [ ] Do you have Azure OpenAI or AWS Bedrock already provisioned in India region?
  - [ ] Yes - Azure OpenAI (Mumbai/Pune)
  - [ ] Yes - AWS Bedrock (Mumbai)
  - [ ] No - Need to provision
  - [ ] Not sure

- [ ] For on-premise/local LLM (Secure Mode), do you have GPU servers available?
  - [ ] Yes - NVIDIA A100/H100
  - [ ] Yes - Other GPU (specify): ________________
  - [ ] No - Will need to procure
  - [ ] Can use cloud GPU instances

### A2. Database
- [ ] Preferred database for audit logs (5-year retention required by SEBI)?
  - [ ] Microsoft SQL Server
  - [ ] PostgreSQL
  - [ ] MongoDB
  - [ ] Oracle
  - [ ] Azure Cosmos DB / AWS DynamoDB
  - [ ] Other: ________________

- [ ] Do you have a separate audit database/data warehouse?
  - [ ] Yes (name): ________________
  - [ ] No - Use application database

### A3. Network & Security
- [ ] Deployment zone preference?
  - [ ] DMZ (accessible from corporate network)
  - [ ] Internal network only
  - [ ] Internet-facing with VPN
  - [ ] Other: ________________

- [ ] Firewall/proxy requirements?
  - [ ] All external API calls must go through proxy
  - [ ] Whitelist-based outbound access
  - [ ] Direct internet access allowed for specific services
  - [ ] Provide proxy details: ________________

---

## SECTION B: Authentication & Access Control

### B1. Identity Provider
- [ ] Primary authentication system?
  - [ ] Microsoft Active Directory (On-prem)
  - [ ] Azure Active Directory (Entra ID)
  - [ ] Okta
  - [ ] Ping Identity
  - [ ] Other: ________________

- [ ] SSO protocol supported?
  - [ ] SAML 2.0
  - [ ] OAuth 2.0 / OpenID Connect
  - [ ] Kerberos
  - [ ] LDAP direct bind

### B2. User Groups & Roles
- [ ] How should users be categorized for AI access?

| Role | Description | External AI Access | Local LLM Access | Admin Dashboard |
|------|-------------|-------------------|------------------|-----------------|
| General User | Regular employees | ? | ? | ? |
| Research Analyst | Research team | ? | ? | ? |
| Strategy Team | Strategy/Planning | ? | ? | ? |
| Compliance | Compliance officers | ? | ? | ? |
| IT Admin | System administrators | ? | ? | ? |
| Security Team | Security monitoring | ? | ? | ? |

- [ ] Are there AD groups we should map to these roles?
  - Group names: ________________

### B3. Access Restrictions
- [ ] Should certain departments be blocked from external AI entirely?
  - [ ] Yes (specify departments): ________________
  - [ ] No - All can use with content filtering

- [ ] Should usage be limited by time (e.g., market hours only)?
  - [ ] Yes (specify): ________________
  - [ ] No

---

## SECTION C: Sensitive Data Patterns (Critical for Compliance)

### C1. Client Identifiers
Please provide patterns/formats (examples will help us build detection rules):

- [ ] Client Code format: ________________
  - Example: ________________

- [ ] Demat Account format: ________________
  - Example: ________________

- [ ] Trading Account format: ________________
  - Example: ________________

- [ ] UCC (Unique Client Code) format: ________________
  - Example: ________________

### C2. Internal References
- [ ] Internal project code format: ________________
- [ ] Internal memo/circular format: ________________
- [ ] Cost center codes: ________________
- [ ] Employee ID format: ________________

### C3. UPSI Keywords (Unpublished Price Sensitive Information)
Standard UPSI terms we'll detect:
- merger, acquisition, demerger
- quarterly results, financial results
- dividend declaration
- change in capital structure
- board meeting (financial context)

- [ ] Additional UPSI-related terms specific to MOSL: ________________

### C4. Proprietary Terms
- [ ] Trading strategy names to block: ________________
- [ ] Product names (internal): ________________
- [ ] System names (internal): ________________

---

## SECTION D: Compliance & Audit Requirements

### D1. Regulatory Mapping
- [ ] Which regulations must the audit trail satisfy?
  - [x] SEBI AI/ML Guidelines 2025
  - [x] SEBI PIT Regulations 2015
  - [x] SEBI Intermediaries Regulations
  - [x] RBI Data Localization
  - [x] DPDPA 2023
  - [ ] FIU-IND reporting requirements
  - [ ] ISO 27001
  - [ ] SOC 2
  - [ ] Other: ________________

### D2. Audit Log Requirements
- [ ] Log retention period: ________________ years (SEBI requires minimum 5)

- [ ] What must be logged for each AI query?
  - [x] Timestamp
  - [x] User ID / Employee ID
  - [x] Department
  - [x] Query content (full/partial/hashed)
  - [x] Response content (full/partial/hashed)
  - [x] Model used
  - [x] Routing decision (external/local/blocked)
  - [x] Sensitive data detected (yes/no + patterns)
  - [x] IP address
  - [x] Session ID
  - [ ] Other: ________________

- [ ] Should query content be stored in full or hashed?
  - [ ] Full text (maximum audit capability)
  - [ ] Hashed (privacy-preserving)
  - [ ] Full text for blocked queries, hashed for allowed

### D3. SIEM/Logging Integration
- [ ] Do you have a centralized logging system?
  - [ ] Splunk
  - [ ] ELK Stack (Elasticsearch)
  - [ ] Azure Sentinel
  - [ ] AWS CloudWatch
  - [ ] IBM QRadar
  - [ ] Other: ________________

- [ ] Should AI Gateway logs be forwarded to SIEM?
  - [ ] Yes - Real-time
  - [ ] Yes - Batch (hourly/daily)
  - [ ] No - Standalone audit database sufficient

### D4. Alert Requirements
- [ ] Who should receive alerts for blocked/suspicious queries?
  - Email(s): ________________
  - [ ] Integration with ticketing system (ServiceNow, Jira, etc.)

- [ ] Alert thresholds?
  - [ ] Every blocked query
  - [ ] Pattern-based (e.g., same user blocked 3+ times)
  - [ ] Daily summary only

---

## SECTION E: Cost & Scale Planning

### E1. User Scale
- [ ] Total employees who will have access: ________________
- [ ] Expected daily active users: ________________
- [ ] Expected peak concurrent users: ________________
- [ ] Expected queries per user per day: ________________

### E2. Budget Considerations
- [ ] Monthly budget for external AI APIs: Rs. ________________
- [ ] One-time infrastructure budget: Rs. ________________

### E3. Cost Optimization Preferences
- [ ] Which approach for cost control?
  - [ ] Rate limiting per user (queries/day)
  - [ ] Department-wise quotas
  - [ ] Prioritize cheaper models, premium on request
  - [ ] Local LLM for most queries, external for complex only
  - [ ] Other: ________________

### E4. Model Preferences
Given cost sensitivity, recommended tiered approach:

| Tier | Use Case | Model | Est. Cost |
|------|----------|-------|-----------|
| Default | General queries | Local Llama 4 / Qwen 2.5 | Free (infra only) |
| Standard | Research | Groq/Cerebras (fast, cheap) | ~$0.001/query |
| Premium | Complex analysis | Azure OpenAI GPT-5 | ~$0.01/query |
| Research | Web search | Perplexity | ~$0.005/query |

- [ ] Approve this tiered approach?
- [ ] Modifications: ________________

---

## SECTION F: Deployment & Handover

### F1. Deployment Preference
- [ ] How should the software be delivered?
  - [ ] Docker containers (recommended)
  - [ ] Kubernetes Helm charts
  - [ ] VM images (OVA/AMI)
  - [ ] Source code + deployment scripts
  - [ ] Other: ________________

### F2. Environment Requirements
- [ ] Number of environments needed?
  - [ ] Development
  - [ ] UAT/Testing
  - [ ] Production
  - [ ] DR (Disaster Recovery)

### F3. Support & Maintenance
- [ ] Who will maintain the system post-deployment?
  - [ ] Internal IT team
  - [ ] Managed service
  - [ ] Hybrid

- [ ] Do you need documentation for?
  - [ ] Deployment guide
  - [ ] Admin user manual
  - [ ] API documentation
  - [ ] Troubleshooting guide
  - [ ] Security architecture document (for auditors)

### F4. Testing Requirements
- [ ] Do you need?
  - [ ] VAPT (Vulnerability Assessment & Penetration Testing) report
  - [ ] Load testing results
  - [ ] Compliance testing checklist
  - [ ] UAT test cases

---

## SECTION G: Timeline & Priorities

### G1. Priority Features
Please rank (1 = highest priority):

| Feature | Priority (1-5) |
|---------|---------------|
| Content scanning & blocking | |
| Audit logging | |
| AD/SSO integration | |
| Multiple AI model support | |
| Admin dashboard | |
| Usage analytics/reports | |
| Cost tracking | |
| Mobile access | |

### G2. Rollout Preference
- [ ] Phased rollout approach?
  - [ ] Phase 1: IT/Tech team only (pilot)
  - [ ] Phase 2: Research & Strategy teams
  - [ ] Phase 3: All employees

- [ ] Or big-bang deployment to all?

### G3. Go-Live Target
- [ ] Expected go-live date: ________________
- [ ] Any regulatory deadlines driving this? ________________

---

## SECTION H: Additional Information

### H1. Existing Systems Integration
- [ ] Any existing AI tools being used (officially or unofficially)?
  - Tool name: ________________
  - Should it be replaced or integrated?

### H2. Special Requirements
- [ ] Any specific requirements not covered above?

________________
________________
________________

### H3. Points of Contact
- [ ] Technical contact (for deployment): ________________
- [ ] Business contact (for requirements): ________________
- [ ] Compliance contact (for audit requirements): ________________

---

## Next Steps After Receiving This Information

1. **Architecture Finalization** - Design based on your cloud/infra choices
2. **Detection Rules Configuration** - Build patterns from your data formats
3. **Software Build** - Complete production-ready package
4. **Documentation** - Admin guides, deployment docs, compliance docs
5. **Handover** - Docker images + scripts + documentation
6. **Support** - Remote assistance during deployment

---

**Please fill this checklist and share back. Partial information is fine - we can clarify as we go.**

*Estimated delivery after receiving complete information: 2-3 weeks for production-ready software*
