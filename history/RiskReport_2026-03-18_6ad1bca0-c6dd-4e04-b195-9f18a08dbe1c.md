# AI Risk Assessment – Executive Brief
- Report date: 2026-03-18
- Total risks evaluated: 55

## Top 10 risks
### 1. Ransomware disrupts operations and recovery capabilities
- Score: 20 (L=4, I=5)
- Category / Function: Cyber / Cybersecurity
- Event / Asset: SECURITY_RANSOMWARE / UNKNOWN
- Evidence: Medium | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0006
- Recommended actions: Harden privileged access | Immutable backups + frequent restore testing
- Framework mapping: NIST IR-4; NIST CP-9; NIST AC-2
- Summary: Risk signal (Medium): SECURITY_RANSOMWARE affecting UNKNOWN in Cybersecurity. Evidence window: 2025-05-13 to 2025-05-13 across 2 source(s). Representative sources: How Interlock Ransomware Affects the Defense Industrial Base Supply Chain - Resecurity | How Interlock Ransomware Affects the Defense Industrial Base Supply Chain - Resecurity

### 2. Cloud region outage disrupts hosted workloads
- Score: 20 (L=4, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Medium | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Medium): OUTAGE_CLOUD_REGION affecting cloud in Cloud Infrastructure. Evidence window: 2025-10-21 to 2025-10-21 across 2 source(s). Representative sources: AWS October 2025 Outage: What Financial Executives Must Learn About Cloud Risk Management - Financial Executives International | AWS October 2025 Outage: What Financial Executives Must Learn About Cloud Risk Management - Financial Executives International

### 3. Cloud region outage disrupts hosted workloads
- Score: 20 (L=4, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Medium | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Medium): OUTAGE_CLOUD_REGION affecting cloud in Cloud Infrastructure. Evidence window: 2025-10-21 to 2025-10-21 across 2 source(s). Representative sources: Amazon says AWS cloud service back to normal after outage disrupts businesses worldwide - Reuters | Amazon says AWS cloud service back to normal after outage disrupts businesses worldwide - Reuters

### 4. Centralized identity/SSO outage disrupts workforce access
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Identity & Access Management
- Event / Asset: OUTAGE_IDENTITY / authentication
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0001
- Recommended actions: Implement break-glass access for critical systems | Add synthetic login monitoring
- Framework mapping: NIST IA-2; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_IDENTITY affecting authentication in Identity & Access Management. Evidence window: 2025-08-12 to 2025-08-12 across 1 source(s). Representative sources: IBM Cloud hit by fourth major outage since May as authentication failures expose systemic issues - Network World

### 5. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2025-10-13 to 2025-10-13 across 1 source(s). Representative sources: Verizon Wireless Network Outage Affects a Number of U.S. Cities - Inside Towers

### 6. Cloud region outage disrupts hosted workloads
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_CLOUD_REGION affecting cloud in Cloud Infrastructure. Evidence window: 2025-10-20 to 2025-10-20 across 1 source(s). Representative sources: Outage at Amazon cloud service unit causes major disruption - dw.com

### 7. Ransomware disrupts operations and recovery capabilities
- Score: 15 (L=3, I=5)
- Category / Function: Cyber / Cybersecurity
- Event / Asset: SECURITY_RANSOMWARE / UNKNOWN
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0006
- Recommended actions: Harden privileged access | Immutable backups + frequent restore testing
- Framework mapping: NIST IR-4; NIST CP-9; NIST AC-2
- Summary: Risk signal (Weak): SECURITY_RANSOMWARE affecting UNKNOWN in Cybersecurity. Evidence window: 2025-12-11 to 2025-12-11 across 1 source(s). Representative sources: Ransomware surge intensifies across industrial sectors, with manufacturing accounting for 72% of Q3 cases - Industrial Cyber

### 8. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2026-01-06 to 2026-01-06 across 1 source(s). Representative sources: 2025 global network outage report and internet health check - Network World

### 9. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2026-01-20 to 2026-01-20 across 1 source(s). Representative sources: Verizon outage: Analysts and more weigh in - Fierce Network

### 10. Centralized identity/SSO outage disrupts workforce access
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Identity & Access Management
- Event / Asset: OUTAGE_IDENTITY / login
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0001
- Recommended actions: Implement break-glass access for critical systems | Add synthetic login monitoring
- Framework mapping: NIST IA-2; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_IDENTITY affecting login in Identity & Access Management. Evidence window: 2026-01-31 to 2026-01-31 across 1 source(s). Representative sources: ING Online Banking Outage: January 31 Login Issues Hit German Users - Meyka

## What changed since last run
- No material score changes detected (or no prior report available).
