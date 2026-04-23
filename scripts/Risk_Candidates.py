import pandas as pd
from datetime import datetime
import re
import hashlib

# ----------------------------
# Config
# ----------------------------
CLUSTERS_CSV = "IncidentClusters.csv"
EVIDENCE_CSV = "EvidenceCache.csv"   # optional
OUTPUT_CSV = "RiskCandidates.csv"

# Confidence mapping
def confidence_enum(conf_score: float) -> str:
    if conf_score >= 0.85:
        return "High"
    if conf_score >= 0.70:
        return "Medium"
    return "Low"

# Risk category mapping by event type
EVENT_TO_CATEGORY = {
    "OUTAGE_IDENTITY": "Technology",
    "OUTAGE_CLOUD_REGION": "Technology",
    "OUTAGE_APPLICATION": "Technology",
    "OUTAGE_NETWORK": "Technology",
    "INTEGRATION_FAILURE": "Technology",
    "DATA_INTEGRITY": "Technology",
    "SECURITY_RANSOMWARE": "Cyber",
    "SECURITY_BREACH": "Cyber",
    "SUPPLIER_FAILURE": "Operational",
    "REGULATORY_ENFORCEMENT": "Regulatory",
    "PHYSICAL_POWER_ENVIRONMENT": "Physical",
}

# Impact baseline defaults
EVENT_TO_IMPACT = {
    "OUTAGE_IDENTITY": 4,
    "OUTAGE_CLOUD_REGION": 4,
    "OUTAGE_APPLICATION": 4,
    "OUTAGE_NETWORK": 4,
    "INTEGRATION_FAILURE": 3,
    "DATA_INTEGRITY": 4,
    "SECURITY_RANSOMWARE": 5,
    "SECURITY_BREACH": 4,
    "SUPPLIER_FAILURE": 4,
    "REGULATORY_ENFORCEMENT": 4,
    "PHYSICAL_POWER_ENVIRONMENT": 4,
}

# Impact dimensions defaults
EVENT_TO_DIMENSIONS = {
    "OUTAGE_IDENTITY": (5, 3, 2, 3, 1),
    "OUTAGE_CLOUD_REGION": (5, 4, 2, 3, 1),
    "OUTAGE_APPLICATION": (5, 3, 2, 3, 1),
    "OUTAGE_NETWORK": (5, 3, 2, 3, 1),
    "INTEGRATION_FAILURE": (3, 3, 2, 2, 1),
    "SECURITY_RANSOMWARE": (5, 4, 3, 4, 1),
    "SECURITY_BREACH": (2, 4, 5, 4, 1),
    "REGULATORY_ENFORCEMENT": (1, 4, 5, 3, 1),
    "SUPPLIER_FAILURE": (4, 4, 2, 3, 1),
    "PHYSICAL_POWER_ENVIRONMENT": (5, 3, 2, 3, 1),
}

# Title/scenario templates
EVENT_TEMPLATES = {
    "OUTAGE_IDENTITY": {
        "title": "Centralized identity/SSO outage disrupts workforce access",
        "scenario": "If centralized identity services are unavailable, users cannot authenticate to critical systems, causing access disruption and operational delays."
    },
    "OUTAGE_CLOUD_REGION": {
        "title": "Cloud region outage disrupts hosted workloads",
        "scenario": "If a cloud region becomes unavailable, dependent applications may experience outages until failover or recovery is completed."
    },
    "OUTAGE_APPLICATION": {
        "title": "Critical application outage disrupts business operations",
        "scenario": "If a critical application becomes unavailable, dependent business processes are disrupted, increasing delays and manual workarounds."
    },
    "OUTAGE_NETWORK": {
        "title": "Network outage disrupts connectivity to critical services",
        "scenario": "If core network connectivity fails, users and systems may lose access to critical services, disrupting operations and recovery actions."
    },
    "INTEGRATION_FAILURE": {
        "title": "Integration disruption interrupts partner and supplier transactions",
        "scenario": "If integration channels fail, transactions stop flowing between partners and internal systems, delaying operations and increasing manual processing."
    },
    "SECURITY_RANSOMWARE": {
        "title": "Ransomware disrupts operations and recovery capabilities",
        "scenario": "If ransomware compromises critical systems, operations may halt and recovery timelines may increase due to containment, restoration, and validation needs."
    },
    "SECURITY_BREACH": {
        "title": "Third-party breach increases data exposure and compliance risk",
        "scenario": "If a third-party breach exposes sensitive data, the organization may face regulatory reporting obligations, financial losses, and reputational harm."
    },
    "REGULATORY_ENFORCEMENT": {
        "title": "Regulatory enforcement action increases compliance exposure",
        "scenario": "If regulators take enforcement action, the organization may face corrective actions, fines, and increased audit scrutiny."
    },
}

# Recommended actions + framework mappings
EVENT_ACTIONS = {
    "OUTAGE_IDENTITY": (
        "Implement break-glass access for critical systems | Add synthetic login monitoring | Test alternate authentication paths regularly",
        "NIST IA-2; NIST CP-2; ISO22301 8.4"
    ),
    "OUTAGE_CLOUD_REGION": (
        "Implement multi-region failover for critical services | Run regional outage game days | Validate recovery runbooks",
        "NIST CP-10; NIST CP-2; ISO22301 8.4"
    ),
    "OUTAGE_APPLICATION": (
        "Add high-availability design or failover | Improve monitoring and alerting | Validate recovery procedures through tests",
        "NIST CP-2; NIST CP-10; ISO22301 8.4"
    ),
    "OUTAGE_NETWORK": (
        "Increase network redundancy | Improve failover testing | Add synthetic monitoring for critical paths",
        "NIST CP-2; NIST SC-5; ISO22301 8.4"
    ),
    "INTEGRATION_FAILURE": (
        "Add alternate transaction paths | Implement message queue buffering | Monitor transaction health end-to-end",
        "NIST SI-4; NIST CP-2; ISO22301 8.4"
    ),
    "SECURITY_RANSOMWARE": (
        "Harden privileged access | Implement immutable backups and frequent restore testing | Improve incident response playbooks",
        "NIST IR-4; NIST CP-9; NIST AC-2"
    ),
    "SECURITY_BREACH": (
        "Strengthen third-party security requirements | Improve monitoring and detection | Review data minimization and access controls",
        "NIST AC-3; NIST SI-4; NIST SA-9"
    ),
    "REGULATORY_ENFORCEMENT": (
        "Perform gap assessment against applicable requirements | Document evidence and controls | Implement corrective action tracking",
        "ISO22301; NIST 800-53 (as applicable)"
    ),
}

def slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:60] if s else "unknown"

def stable_risk_id(event_type: str, asset: str, function: str) -> str:
    base = f"{event_type}|{asset}|{function}"
    h = hashlib.sha1(base.encode("utf-8")).hexdigest()[:8].upper()
    return f"RISK-{slugify(event_type).upper()}-{slugify(asset).upper()}-{h}"

def likelihood_baseline(evidence_strength: str, evidence_count: int, conf: str) -> int:
    strength = (evidence_strength or "").strip()
    if conf == "Low":
        # conservative
        return 2
    if strength == "Strong":
        if evidence_count >= 5:
            return 4
        if evidence_count >= 3:
            return 3
        return 3
    if strength == "Medium":
        return 3 if evidence_count >= 2 else 2
    return 2

def impact_baseline(event_type: str) -> int:
    return EVENT_TO_IMPACT.get(event_type, 3)

def get_dimensions(event_type: str):
    return EVENT_TO_DIMENSIONS.get(event_type, (4, 3, 2, 3, 1))

def build_executive_summary(cluster_row: pd.Series, evidence_df: pd.DataFrame | None) -> str:
    # Keep this short and generic; include evidence strength + time window.
    et = cluster_row.get("event_type", "")
    bf = cluster_row.get("business_function", "")
    asset = cluster_row.get("primary_asset_or_service", "")
    strength = cluster_row.get("evidence_strength", "")
    start = cluster_row.get("start_date", "")
    end = cluster_row.get("end_date", "")
    count = int(cluster_row.get("evidence_count", 0) or 0)

    headline = f"Risk signal ({strength}): {et} affecting {asset} in {bf}."
    timing = f"Evidence window: {start} to {end} across {count} source(s)."

    # Optionally pull 1–2 representative titles
    titles = []
    if evidence_df is not None:
        ev_ids = str(cluster_row.get("evidence_ids", "")).split(",")
        ev_ids = [x.strip() for x in ev_ids if x.strip()]
        subset = evidence_df[evidence_df["evidence_id"].isin(ev_ids)]
        if "title" in subset.columns:
            for t in subset["title"].dropna().head(2).tolist():
                titles.append(str(t).strip())

    if titles:
        refs = "Representative sources: " + " | ".join(titles[:2])
        return f"{headline} {timing} {refs}"
    return f"{headline} {timing}"

def main():
    df_clusters = pd.read_csv(CLUSTERS_CSV)
    evidence_df = None
    try:
        evidence_df = pd.read_csv(EVIDENCE_CSV)
    except Exception:
        evidence_df = None

    now_iso = datetime.now().isoformat(timespec="seconds")

    out_rows = []
    for _, c in df_clusters.iterrows():
        if str(c.get("cluster_type", "")).strip().upper() != "INCIDENT":
            continue  # prototype: only incident clusters for now

        event_type = str(c.get("event_type", "")).strip()
        asset = str(c.get("primary_asset_or_service", "")).strip() or "UNKNOWN"
        business_function = str(c.get("business_function", "")).strip() or "Unknown Function"

        # Risk ID
        rid = stable_risk_id(event_type, asset, business_function)

        # Confidence
        conf_score = float(c.get("confidence_score", 0.0) or 0.0)
        conf = confidence_enum(conf_score)

        # Category
        category = EVENT_TO_CATEGORY.get(event_type, "Technology")

        # Templates
        tmpl = EVENT_TEMPLATES.get(event_type, None)
        title = tmpl["title"] if tmpl else f"{event_type} risk affects {business_function}"
        scenario = tmpl["scenario"] if tmpl else f"If {event_type} occurs, {business_function} may be disrupted."

        # Baseline scoring
        strength = str(c.get("evidence_strength", "")).strip()
        evidence_count = int(c.get("evidence_count", 0) or 0)

        like = likelihood_baseline(strength, evidence_count, conf)
        imp = impact_baseline(event_type)
        score = like * imp

        # Impact dimensions
        availability, financial, regulatory, reputation, safety = get_dimensions(event_type)

        # Actions + framework
        actions, mapping = EVENT_ACTIONS.get(event_type, ("Review controls and implement appropriate mitigations", "N/A"))

        impact_narr = f"{event_type} affecting {asset} can disrupt {business_function}, causing operational delays and recovery complications."

        exec_summary = build_executive_summary(c, evidence_df)

        score_rationale = (
            f"Evidence strength={strength}, evidence_count={evidence_count}, confidence={conf}. "
            f"Baseline likelihood and impact assigned using deterministic rubric for {event_type}."
        )

        out_rows.append({
            "risk_id": rid,
            "title": title,
            "risk_category": category,
            "business_function": business_function,
            "assets_or_services": asset,
            "scenario": scenario,
            "evidence_strength": strength,
            "likelihood_baseline": like,
            "impact_baseline": imp,
            "risk_score_baseline": score,
            "internal_signals_used": False,
            "internal_outage_refs": "",
            "likelihood_adjusted": "",
            "impact_adjusted": "",
            "risk_score_adjusted": "",
            "confidence": conf,
            "availability_impact": availability,
            "financial_impact": financial,
            "regulatory_impact": regulatory,
            "reputation_impact": reputation,
            "safety_impact": safety,
            "impact_narrative": impact_narr,
            "existing_controls": "",
            "control_gaps": "",
            "recommended_actions": actions,
            "framework_mapping": mapping,
            "owner_suggested": "",
            "score_rationale": score_rationale,
            "executive_summary": exec_summary,
            "last_updated": now_iso,
        })

    df_out = pd.DataFrame(out_rows)

    # Ensure columns are in the exact template order (safe even if empty)
    template_cols = [
        "risk_id","title","risk_category","business_function","assets_or_services","scenario",
        "evidence_strength","likelihood_baseline","impact_baseline","risk_score_baseline",
        "internal_signals_used","internal_outage_refs",
        "likelihood_adjusted","impact_adjusted","risk_score_adjusted",
        "confidence",
        "availability_impact","financial_impact","regulatory_impact","reputation_impact","safety_impact",
        "impact_narrative","existing_controls","control_gaps",
        "recommended_actions","framework_mapping","owner_suggested",
        "score_rationale","executive_summary","last_updated"
    ]
    for col in template_cols:
        if col not in df_out.columns:
            df_out[col] = ""
    df_out = df_out[template_cols]

    df_out.to_csv(OUTPUT_CSV, index=False)
    print(f"Wrote {len(df_out)} risk candidates to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
