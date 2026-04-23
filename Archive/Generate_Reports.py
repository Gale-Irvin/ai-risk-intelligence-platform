import pandas as pd
from datetime import datetime
import os
import uuid

ENRICHED = "RiskCandidates_Enriched.csv"
BASELINE = "RiskCandidates.csv"

OUT_REPORT_CSV = "RiskReport.csv"
OUT_TRENDS_CSV = "RiskTrends.csv"
OUT_REPORT_MD = "RiskReport.md"

TOP_N = 10
CHANGE_THRESHOLD = 3  # only show changes with abs(delta_score) >= this

def pick_score_fields(df: pd.DataFrame) -> pd.DataFrame:
    # Prefer adjusted if present/non-empty; else baseline
    def _coerce_num(s):
        return pd.to_numeric(s, errors="coerce")

    df = df.copy()
    df["risk_score_baseline_num"] = _coerce_num(df.get("risk_score_baseline", None))
    df["likelihood_baseline_num"] = _coerce_num(df.get("likelihood_baseline", None))
    df["impact_baseline_num"] = _coerce_num(df.get("impact_baseline", None))

    df["risk_score_adjusted_num"] = _coerce_num(df.get("risk_score_adjusted", None))
    df["likelihood_adjusted_num"] = _coerce_num(df.get("likelihood_adjusted", None))
    df["impact_adjusted_num"] = _coerce_num(df.get("impact_adjusted", None))

    # score_used
    df["score_used"] = df["risk_score_adjusted_num"].where(df["risk_score_adjusted_num"].notna(),
                                                          df["risk_score_baseline_num"])
    df["likelihood_used"] = df["likelihood_adjusted_num"].where(df["likelihood_adjusted_num"].notna(),
                                                                df["likelihood_baseline_num"])
    df["impact_used"] = df["impact_adjusted_num"].where(df["impact_adjusted_num"].notna(),
                                                        df["impact_baseline_num"])

    # normalize booleans
    def to_bool(v):
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("true", "1", "yes", "y")

    if "internal_signals_used" in df.columns:
        df["internal_signals_used_bool"] = df["internal_signals_used"].apply(to_bool)
    else:
        df["internal_signals_used_bool"] = False

    return df

def first_actions(actions: str, n: int = 2) -> str:
    if actions is None or (isinstance(actions, float) and pd.isna(actions)):
        return ""
    parts = [p.strip() for p in str(actions).split("|") if p.strip()]
    return " | ".join(parts[:n])

def load_current_candidates() -> pd.DataFrame:
    if os.path.exists(ENRICHED):
        return pd.read_csv(ENRICHED)
    return pd.read_csv(BASELINE)

def build_report(df: pd.DataFrame, run_id: str, report_date: str) -> pd.DataFrame:
    df = pick_score_fields(df)

    # Remove rows without score
    df = df[df["score_used"].notna()].copy()

    # Sort highest risk first; tie-breakers: evidence_strength, confidence
    strength_rank = {"Strong": 3, "Medium": 2, "Weak": 1}
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}

    df["strength_rank"] = df.get("evidence_strength", "").map(strength_rank).fillna(0)
    df["conf_rank"] = df.get("confidence", "").map(conf_rank).fillna(0)

    df = df.sort_values(by=["score_used", "strength_rank", "conf_rank"],
                        ascending=[False, False, False]).reset_index(drop=True)

    df["rank"] = df.index + 1

    # Build RiskReport.csv fields
    out = pd.DataFrame({
        "report_run_id": run_id,
        "report_date": report_date,
        "rank": df["rank"],
        "risk_id": df.get("risk_id", ""),
        "title": df.get("title", ""),
        "risk_category": df.get("risk_category", ""),
        "business_function": df.get("business_function", ""),
        "assets_or_services": df.get("assets_or_services", ""),
        "score_used": df["score_used"].astype(int),
        "likelihood_used": df["likelihood_used"].astype(int),
        "impact_used": df["impact_used"].astype(int),
        "evidence_strength": df.get("evidence_strength", ""),
        "confidence": df.get("confidence", ""),
        "internal_signals_used": df["internal_signals_used_bool"],
        "internal_outage_refs": df.get("internal_outage_refs", ""),
        "top_recommended_actions": df.get("recommended_actions", "").apply(lambda x: first_actions(x, 2)),
        "framework_mapping": df.get("framework_mapping", ""),
        "executive_summary": df.get("executive_summary", ""),
    })

    return out

def build_trends(current_report: pd.DataFrame) -> pd.DataFrame:
    # If no prior RiskReport.csv exists, return empty trends
    if not os.path.exists(OUT_REPORT_CSV):
        return pd.DataFrame(columns=[
            "report_run_id","report_date","risk_id","title","prior_score","current_score","delta_score",
            "prior_confidence","current_confidence","prior_internal_signals","current_internal_signals","change_reason"
        ])

    prior = pd.read_csv(OUT_REPORT_CSV)

    # Join on risk_id
    merged = current_report.merge(prior, on="risk_id", how="left", suffixes=("_cur", "_prior"))

    # Compute deltas where prior exists
    merged["prior_score"] = pd.to_numeric(merged["score_used_prior"], errors="coerce")
    merged["current_score"] = pd.to_numeric(merged["score_used_cur"], errors="coerce")
    merged["delta_score"] = merged["current_score"] - merged["prior_score"]

    # Changes to show
    changed = merged[
        merged["prior_score"].notna() &
        merged["delta_score"].abs().fillna(0) >= CHANGE_THRESHOLD
    ].copy()

    def reason(row):
        reasons = []
        if pd.notna(row.get("delta_score")) and abs(row["delta_score"]) >= CHANGE_THRESHOLD:
            reasons.append(f"Score changed by {int(row['delta_score'])}.")
        if str(row.get("confidence_cur", "")) != str(row.get("confidence_prior", "")):
            reasons.append("Confidence changed.")
        if bool(row.get("internal_signals_used_cur")) != bool(row.get("internal_signals_used_prior")):
            reasons.append("Internal enrichment usage changed.")
        return " ".join(reasons) if reasons else "Material change detected."

    if changed.empty:
        return pd.DataFrame(columns=[
            "report_run_id","report_date","risk_id","title","prior_score","current_score","delta_score",
            "prior_confidence","current_confidence","prior_internal_signals","current_internal_signals","change_reason"
        ])

    out = pd.DataFrame({
        "report_run_id": changed["report_run_id_cur"],
        "report_date": changed["report_date_cur"],
        "risk_id": changed["risk_id"],
        "title": changed["title_cur"],
        "prior_score": changed["prior_score"].astype(int),
        "current_score": changed["current_score"].astype(int),
        "delta_score": changed["delta_score"].astype(int),
        "prior_confidence": changed["confidence_prior"],
        "current_confidence": changed["confidence_cur"],
        "prior_internal_signals": changed["internal_signals_used_prior"],
        "current_internal_signals": changed["internal_signals_used_cur"],
        "change_reason": changed.apply(reason, axis=1),
    })

    return out.sort_values(by=["delta_score"], ascending=False)

def write_markdown(report: pd.DataFrame, trends: pd.DataFrame, report_date: str):
    top = report.head(TOP_N).copy()

    lines = []
    lines.append(f"# AI Risk Assessment – Executive Brief")
    lines.append(f"- Report date: {report_date}")
    lines.append(f"- Total risks evaluated: {len(report)}")
    lines.append("")

    lines.append(f"## Top {min(TOP_N, len(top))} risks")
    for _, r in top.iterrows():
        lines.append(f"### {int(r['rank'])}. {r['title']}")
        lines.append(f"- Score: {int(r['score_used'])} (L={int(r['likelihood_used'])}, I={int(r['impact_used'])})")
        lines.append(f"- Category / Function: {r['risk_category']} / {r['business_function']}")
        lines.append(f"- Assets/Services: {r['assets_or_services']}")
        lines.append(f"- Evidence: {r['evidence_strength']} | Confidence: {r['confidence']}")
        lines.append(f"- Internal enrichment used: {bool(r['internal_signals_used'])}")
        if str(r.get("top_recommended_actions", "")).strip():
            lines.append(f"- Recommended actions: {r['top_recommended_actions']}")
        if str(r.get("framework_mapping", "")).strip():
            lines.append(f"- Framework mapping: {r['framework_mapping']}")
        if str(r.get("executive_summary", "")).strip():
            lines.append(f"- Summary: {r['executive_summary']}")
        lines.append("")

    lines.append("## What changed since last run")
    if trends.empty:
        lines.append("- No material score changes detected (or no prior report available).")
    else:
        for _, t in trends.iterrows():
            lines.append(f"- {t['title']}: {int(t['prior_score'])} → {int(t['current_score'])} (Δ {int(t['delta_score'])}). {t['change_reason']}")
    lines.append("")

    with open(OUT_REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main():
    df = load_current_candidates()

    run_id = str(uuid.uuid4())
    report_date = datetime.now().date().isoformat()

    report = build_report(df, run_id, report_date)
    trends = build_trends(report)

    # Write outputs
    report.to_csv(OUT_REPORT_CSV, index=False)
    trends.to_csv(OUT_TRENDS_CSV, index=False)
    write_markdown(report, trends, report_date)

    print(f"Wrote {OUT_REPORT_CSV} ({len(report)} rows)")
    print(f"Wrote {OUT_TRENDS_CSV} ({len(trends)} rows)")
    print(f"Wrote {OUT_REPORT_MD}")

if __name__ == "__main__":
    main()
