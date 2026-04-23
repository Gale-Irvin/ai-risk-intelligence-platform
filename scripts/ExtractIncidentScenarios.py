import pandas as pd
from datetime import datetime

CLUSTERS_CSV = "IncidentClusters.csv"
EVIDENCE_CSV = "EvidenceCache.csv"
OUTPUT_CSV = "IncidentScenarios.csv"


# --- Scenario Templates ---
SCENARIO_MAP = {
    "SECURITY_RANSOMWARE": {
        "title": "Ransomware disrupts operations and recovery capability",
        "impact": "Systems become unavailable, operations halt, recovery timelines increase",
        "recovery": "Restore from backup, validate integrity, rebuild systems, isolate network"
    },
    "OUTAGE_IDENTITY": {
        "title": "Identity service outage disrupts workforce access",
        "impact": "Users cannot access systems, operations slow or stop",
        "recovery": "Restore identity services, enable break-glass access, validate authentication paths"
    },
    "OUTAGE_CLOUD_REGION": {
        "title": "Cloud regional outage disrupts hosted services",
        "impact": "Applications hosted in the region become unavailable",
        "recovery": "Failover to alternate region, restore services, validate connectivity"
    },
    "OUTAGE_NETWORK": {
        "title": "Network outage disrupts connectivity",
        "impact": "Systems and users lose access to services",
        "recovery": "Restore network paths, reroute traffic, validate connectivity"
    },
    "OUTAGE_APPLICATION": {
        "title": "Critical application outage disrupts business operations",
        "impact": "Business processes are interrupted",
        "recovery": "Restart or restore application, validate integrations"
    },
}


def get_representative_title(cluster_row, evidence_df):
    if evidence_df is None:
        return "No title available"

    evidence_ids = str(cluster_row.get("evidence_ids", "")).split(",")
    evidence_ids = [x.strip() for x in evidence_ids if x.strip()]

    subset = evidence_df[evidence_df["evidence_id"].astype(str).isin(evidence_ids)]

    if not subset.empty and "title" in subset.columns:
        return subset.iloc[0]["title"]

    return "No title available"


def main():
    df_clusters = pd.read_csv(CLUSTERS_CSV)

    try:
        evidence_df = pd.read_csv(EVIDENCE_CSV)
    except:
        evidence_df = None

    rows = []

    for _, c in df_clusters.iterrows():

        if str(c.get("cluster_type", "")).upper() != "INCIDENT":
            continue

        event_type = str(c.get("event_type", "")).strip()
        business_function = str(c.get("business_function", "")).strip()
        asset = str(c.get("primary_asset_or_service", "")).strip()
        evidence_count = int(c.get("evidence_count", 0) or 0)
        strength = str(c.get("evidence_strength", "")).strip()

        incident_title = get_representative_title(c, evidence_df)

        # Scenario mapping
        template = SCENARIO_MAP.get(event_type, None)

        if template:
            scenario_title = template["title"]
            impact = template["impact"]
            recovery = template["recovery"]
        else:
            scenario_title = f"{event_type} impacts {business_function}"
            impact = f"Potential disruption to {business_function}"
            recovery = "Investigate recovery procedures"

        scenario_statement = f"If {event_type} occurs affecting {asset}, {impact.lower()}."

        # DR flags (simple logic for now)
        testing_flag = True if event_type.startswith("OUTAGE") or event_type.startswith("SECURITY") else False
        documentation_flag = True
        runbook_flag = True

        rows.append({
            "cluster_id": c.get("cluster_id"),
            "incident_title": incident_title,
            "event_type": event_type,
            "business_function": business_function,
            "primary_asset": asset,
            "scenario_title": scenario_title,
            "scenario_statement": scenario_statement,
            "operational_impact": impact,
            "recovery_focus": recovery,
            "evidence_count": evidence_count,
            "evidence_strength": strength,
            "testing_candidate_flag": testing_flag,
            "documentation_update_flag": documentation_flag,
            "runbook_review_flag": runbook_flag,
            "last_updated": datetime.now().isoformat()
        })

    df_out = pd.DataFrame(rows)
    df_out.to_csv(OUTPUT_CSV, index=False)

    print(f"Created {len(df_out)} scenarios in {OUTPUT_CSV}")


if __name__ == "__main__":
    main()