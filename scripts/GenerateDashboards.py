import pandas as pd
from datetime import datetime
import os

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"


RISK_ENRICHED = OUTPUT_DIR / "RiskCandidates_Enriched.csv"
RISK_BASELINE = OUTPUT_DIR / "RiskCandidates.csv"
EVIDENCE = OUTPUT_DIR / "EvidenceCache.csv"
CLUSTERS = OUTPUT_DIR / "IncidentClusters.csv"   # optional (for extra cluster fields)

OUT_RISKS = OUTPUT_DIR / "Dashboard_Risks.csv"
OUT_EVIDENCE = OUTPUT_DIR / "Dashboard_RiskEvidence.csv"

def to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("true", "1", "yes", "y")

def load_risks() -> pd.DataFrame:
    if os.path.exists(RISK_ENRICHED):
        return pd.read_csv(RISK_ENRICHED)
    return pd.read_csv(RISK_BASELINE)

def pick_used_scores(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def num(series):
        return pd.to_numeric(series, errors="coerce")

    df["risk_score_baseline_num"] = num(df.get("risk_score_baseline"))
    df["likelihood_baseline_num"] = num(df.get("likelihood_baseline"))
    df["impact_baseline_num"] = num(df.get("impact_baseline"))

    df["risk_score_adjusted_num"] = num(df.get("risk_score_adjusted"))
    df["likelihood_adjusted_num"] = num(df.get("likelihood_adjusted"))
    df["impact_adjusted_num"] = num(df.get("impact_adjusted"))

    df["score_used"] = df["risk_score_adjusted_num"].where(df["risk_score_adjusted_num"].notna(),
                                                           df["risk_score_baseline_num"])
    df["likelihood_used"] = df["likelihood_adjusted_num"].where(df["likelihood_adjusted_num"].notna(),
                                                                df["likelihood_baseline_num"])
    df["impact_used"] = df["impact_adjusted_num"].where(df["impact_adjusted_num"].notna(),
                                                        df["impact_baseline_num"])
    df["internal_signals_used_bool"] = df.get("internal_signals_used", False).apply(to_bool)

    return df

def rank_risks(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    strength_rank = {"Strong": 3, "Medium": 2, "Weak": 1}
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}

    df["strength_rank"] = df.get("evidence_strength", "").map(strength_rank).fillna(0)
    df["conf_rank"] = df.get("confidence", "").map(conf_rank).fillna(0)

    df = df.sort_values(by=["score_used", "strength_rank", "conf_rank"],
                        ascending=[False, False, False]).reset_index(drop=True)
    df["rank"] = df.index + 1
    return df

def first_actions(actions: str, n: int = 2) -> str:
    if actions is None or (isinstance(actions, float) and pd.isna(actions)):
        return ""
    parts = [p.strip() for p in str(actions).split("|") if p.strip()]
    return " | ".join(parts[:n])

def safe_str(x) -> str:
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return ""
    return str(x)

def main():
    risks = load_risks()
    print(risks.columns.tolist())
    risks = pick_used_scores(risks)
    risks = risks[risks["score_used"].notna()].copy()
    risks = rank_risks(risks)

    # Executive Risk Summary Dataset
    risk_summary_cols = [
        "risk_id",
        "event_type",
        "primary_asset_or_service",
        "business_function",
        "confidence",
        "likelihood_adjusted",
        "impact_adjusted",
        "risk_score_adjusted",
        "evidence_strength"
    ]

    df_risk_summary = risks[risk_summary_cols].copy()

    df_risk_summary.rename(columns={
        "primary_asset_or_service": "asset",
        "likelihood_adjusted": "likelihood",
        "impact_adjusted": "impact",
        "risk_score_adjusted": "risk_score"
    }, inplace=True)

    df_risk_summary.to_csv("Dashboard_Risks.csv", index=False)

    print(f"Wrote {len(df_risk_summary)} rows to Dashboard_Risks.csv")

    # Executive Risk Evidence Dataset
    evidence_cols = [
        "risk_id",
        "cluster_id",
        "title",
        "last_updated"
    ]

    if "publishers" in risks.columns:
        evidence_cols.append("publishers")
    if "urls" in risks.columns:
        evidence_cols.append("urls")

    df_risk_evidence = risks[evidence_cols].copy()

    df_risk_evidence.rename(columns={
        "last_updated": "generated_at"
    }, inplace=True)

    df_risk_evidence.to_csv("Dashboard_RiskEvidence.csv", index=False)

    print(f"Wrote {len(df_risk_evidence)} rows to Dashboard_RiskEvidence.csv")

        # Executive Risk Trend Dataset
    trend_df = risks.copy()

    if "last_updated" in trend_df.columns:
        trend_df["trend_date"] = pd.to_datetime(trend_df["last_updated"], errors="coerce")
    else:
        trend_df["trend_date"] = pd.NaT

    trend_df = trend_df[trend_df["trend_date"].notna()].copy()
    trend_df["week"] = trend_df["trend_date"].dt.strftime("%Y-W%U")

    trend_group_cols = ["week", "event_type", "primary_asset_or_service"]

    df_risk_trends = (
        trend_df.groupby(trend_group_cols)
        .size()
        .reset_index(name="signal_count")
    )

    df_risk_trends.rename(columns={
        "primary_asset_or_service": "asset"
    }, inplace=True)

    df_risk_trends.to_csv("Dashboard_RiskTrends.csv", index=False)

    print(f"Wrote {len(df_risk_trends)} rows to Dashboard_RiskTrends.csv")

    # Optional: add cluster fields
    clusters = None
    if os.path.exists(CLUSTERS):
        try:
            clusters = pd.read_csv(CLUSTERS)
        except Exception:
            clusters = None

    if clusters is not None and not clusters.empty and "cluster_id" in risks.columns:
        keep_cols = [
            "cluster_id",
            "evidence_count",
            "start_date",
            "end_date",
            "publishers",
            "urls",
            "impact_keywords",
            "entity_summary",
            "cluster_summary"
        ]

        keep_cols = [c for c in keep_cols if c in clusters.columns]

        if keep_cols:
            risks = risks.merge(
                clusters[keep_cols],
                on="cluster_id",
                how="left",
                suffixes=("","_cl")
            )
    # Build Dashboard_Risks
    dash_risks = pd.DataFrame({
        "rank": risks["rank"],
        "risk_id": risks.get("risk_id",""),
        "cluster_id": risks.get("cluster_id",""),
        "title": risks.get("title",""),
        "risk_category": risks.get("risk_category",""),
        "business_function": risks.get("business_function",""),
        "event_type": risks.get("event_type",""),
        "primary_asset_or_service": risks.get("primary_asset_or_service",""),
        "score_used": risks["score_used"].astype(int),
        "likelihood_used": risks["likelihood_used"].astype(int),
        "impact_used": risks["impact_used"].astype(int),
        "risk_score_baseline": risks["risk_score_baseline_num"].astype(int),
        "risk_score_adjusted": risks["risk_score_adjusted_num"].fillna("").apply(lambda x: int(x) if str(x).strip() != "" else ""),
        "evidence_strength": risks.get("evidence_strength",""),
        "confidence": risks.get("confidence",""),
        "internal_signals_used": risks["internal_signals_used_bool"],
        "internal_outage_refs": risks.get("internal_outage_refs",""),
        "recommended_actions_top": risks.get("recommended_actions","").apply(lambda x: first_actions(x, 2)),
        "framework_mapping": risks.get("framework_mapping",""),
        "executive_summary": risks.get("executive_summary",""),
        "impact_narrative": risks.get("impact_narrative",""),
        # cluster extras (may be blank if not merged)
        "evidence_count": risks.get("evidence_count",""),
        "start_date": risks.get("start_date",""),
        "end_date": risks.get("end_date",""),
        "publishers": risks.get("publishers",""),
        "urls_sample": risks.get("urls",""),
        "impact_keywords": risks.get("impact_keywords",""),
        "entity_summary": risks.get("entity_summary",""),
        "cluster_summary": risks.get("cluster_summary",""),
    })

    dash_risks.to_csv(OUT_RISKS, index=False)

    # Build Dashboard_RiskEvidence (drilldown)
    ev = pd.read_csv(EVIDENCE)
    ev["evidence_id"] = ev["evidence_id"].astype(str)

    # Map evidence_id -> evidence fields
    ev_map = ev.set_index("evidence_id", drop=False)

    rows = []
    for _, r in risks.iterrows():
        risk_id = safe_str(r.get("risk_id","")).strip()
        cluster_id = safe_str(r.get("cluster_id","")).strip()
        evidence_ids = [x.strip() for x in safe_str(r.get("evidence_ids","")).split(",") if x.strip()]

        for eid in evidence_ids:
            if eid in ev_map.index:
                e = ev_map.loc[eid]
                rows.append({
                    "risk_id": risk_id,
                    "cluster_id": cluster_id,
                    "evidence_id": eid,
                    "published_date": safe_str(e.get("published_date","")),
                    "publisher": safe_str(e.get("publisher","")),
                    "title": safe_str(e.get("title","")),
                    "url": safe_str(e.get("url","")),
                    "source_type": safe_str(e.get("source_type","")),
                    "search_query": safe_str(e.get("search_query","")),
                    "relevance_score": safe_str(e.get("relevance_score","")),
                    "event_type_hint": safe_str(e.get("event_type_hint","")),
                    "entity_keywords": safe_str(e.get("entity_keywords","")),
                    "event_keywords": safe_str(e.get("event_keywords","")),
                    "asset_keywords": safe_str(e.get("asset_keywords","")),
                })
            else:
                # evidence referenced but not found (still keep the linkage)
                rows.append({
                    "risk_id": risk_id,
                    "cluster_id": cluster_id,
                    "evidence_id": eid,
                    "published_date": "",
                    "publisher": "",
                    "title": "",
                    "url": "",
                    "source_type": "",
                    "search_query": "",
                    "relevance_score": "",
                    "event_type_hint": "",
                    "entity_keywords": "",
                    "event_keywords": "",
                    "asset_keywords": "",
                })

    dash_evidence = pd.DataFrame(rows)
    dash_evidence.to_csv(OUT_EVIDENCE, index=False)

    print(f"Wrote {OUT_RISKS} ({len(dash_risks)} rows)")
    print(f"Wrote {OUT_EVIDENCE} ({len(dash_evidence)} rows)")

if __name__ == "__main__":
    main()
