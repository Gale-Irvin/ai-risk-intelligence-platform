# AI Risk Assessment – Executive Brief
- Report date: 2026-04-08
- Total risks evaluated: 219

## Top 10 risks
### 1. Ransomware disrupts operations and recovery capabilities
- Score: 20 (L=4, I=5)
- Category / Function: Cyber / Cybersecurity
- Event / Asset: SECURITY_RANSOMWARE / systems
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0006
- Recommended actions: Harden privileged access | Immutable backups + frequent restore testing
- Framework mapping: NIST IR-4; NIST CP-9; NIST AC-2
- Summary: Risk signal (Weak): SECURITY_RANSOMWARE affecting systems in Cybersecurity. Evidence window: 2025-10-08 to 2025-10-08 across 1 source(s). Representative sources: Asahi Group Holdings Ransomware Attack 2025: Digital Order System Disrupted, Nationwide Beer Shortage in Japan - Rescana

### 2. Cloud region outage disrupts hosted workloads
- Score: 16 (L=4, I=4)
- Category / Function: Technology / Order Processing
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0002
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_CLOUD_REGION affecting cloud in Order Processing. Evidence window: 2025-10-21 to 2025-10-21 across 1 source(s). Representative sources: AWS October 2025 Outage: What Financial Executives Must Learn About Cloud Risk Management - Financial Executives International

### 3. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2025-10-13 to 2025-10-13 across 1 source(s). Representative sources: Verizon Wireless Network Outage Affects a Number of U.S. Cities - Inside Towers

### 4. Cloud region outage disrupts hosted workloads
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_CLOUD_REGION affecting cloud in Cloud Infrastructure. Evidence window: 2025-10-21 to 2025-10-21 across 1 source(s). Representative sources: Amazon says AWS cloud service back to normal after outage disrupts businesses worldwide - Reuters

### 5. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Supplier Integration
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0003
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Supplier Integration. Evidence window: 2025-12-05 to 2025-12-05 across 1 source(s). Representative sources: Frantic Friday: Network Outage Brings Delta's Detroit Hub To A Halt - Simple Flying

### 6. Ransomware disrupts operations and recovery capabilities
- Score: 15 (L=3, I=5)
- Category / Function: Cyber / Cybersecurity
- Event / Asset: SECURITY_RANSOMWARE / UNKNOWN
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0006
- Recommended actions: Harden privileged access | Immutable backups + frequent restore testing
- Framework mapping: NIST IR-4; NIST CP-9; NIST AC-2
- Summary: Risk signal (Weak): SECURITY_RANSOMWARE affecting UNKNOWN in Cybersecurity. Evidence window: 2025-12-11 to 2025-12-11 across 1 source(s). Representative sources: Ransomware surge intensifies across industrial sectors, with manufacturing accounting for 72% of Q3 cases - Industrial Cyber

### 7. Cloud region outage disrupts hosted workloads
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_CLOUD_REGION / cloud
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement multi-region failover for critical services | Run regional outage game days
- Framework mapping: NIST CP-10; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_CLOUD_REGION affecting cloud in Cloud Infrastructure. Evidence window: 2026-01-14 to 2026-01-14 across 1 source(s). Representative sources: The Blast Radius Problem: What the 2025 AWS Outage Reveals About Healthcare’s Cloud Fragility - MedCity News

### 8. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2026-01-20 to 2026-01-20 across 1 source(s). Representative sources: Verizon outage: Analysts and more weigh in - Fierce Network

### 9. Network outage disrupts connectivity to critical services
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Network Infrastructure
- Event / Asset: OUTAGE_NETWORK / network
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0004
- Recommended actions: Increase network redundancy | Improve failover testing
- Framework mapping: NIST CP-2; NIST SC-5; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_NETWORK affecting network in Network Infrastructure. Evidence window: 2026-01-21 to 2026-01-21 across 1 source(s). Representative sources: The Verizon outage reveals the end of five-nine network reliability, and it could happen again - PhoneArena

### 10. Centralized identity/SSO outage disrupts workforce access
- Score: 15 (L=3, I=5)
- Category / Function: Technology / Cloud Infrastructure
- Event / Asset: OUTAGE_IDENTITY / identity
- Evidence: Weak | Confidence: High
- Internal enrichment used: True
- Internal refs: INC-0005
- Recommended actions: Implement break-glass access for critical systems | Add synthetic login monitoring
- Framework mapping: NIST IA-2; NIST CP-2; ISO22301 8.4
- Summary: Risk signal (Weak): OUTAGE_IDENTITY affecting identity in Cloud Infrastructure. Evidence window: 2026-02-04 to 2026-02-04 across 1 source(s). Representative sources: Azure outage disrupts VMs and identity services for over 10 hours - Network World

## What changed since last run
- No material score changes detected (or no prior report available).
