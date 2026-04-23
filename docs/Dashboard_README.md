# Executive Risk Intelligence Dashboard

This dashboard is part of the AI-driven Risk Intelligence prototype.

Its purpose is to convert external incident signals and optional internal outage data into an executive-friendly operational risk view.

## Dashboard Datasets

### 1. Dashboard_Risks.csv
Provides a structured summary of risks, including:
- event type
- impacted asset
- business function
- confidence
- likelihood
- impact
- risk score
- evidence strength

### 2. Dashboard_RiskEvidence.csv
Provides traceability to the underlying evidence, including:
- risk ID
- cluster ID
- article title
- publisher
- URL
- generated timestamp

### 3. Dashboard_RiskTrends.csv
Provides trend analysis by:
- week
- event type
- asset
- signal count

## Executive Value

This dashboard is designed to help resilience and risk leaders answer questions such as:

- What operational risks are emerging?
- Which business functions are most exposed?
- What systems or assets are being targeted?
- Are destructive cyber or disruption signals increasing?
- What evidence supports these conclusions?

## Example Risk Types

The dashboard can surface risks such as:
- destructive cyber attacks
- cyber operational disruption
- application outages
- supply chain disruption
- regulatory events

## Strategic Purpose

This dashboard demonstrates how AI-assisted signal collection and clustering can support operational resilience, disaster recovery, and executive risk reporting by translating raw external events into structured, actionable risk intelligence.