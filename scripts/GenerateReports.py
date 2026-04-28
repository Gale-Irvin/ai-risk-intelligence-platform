import pandas as pd
from datetime import datetime
import os
import uuid
import shutil

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"

ENRICHED = OUTPUT_DIR / "RiskCandidates_Enriched.csv"
BASELINE = OUTPUT_DIR / "RiskCandidates.csv"

OUT_REPORT_CSV = OUTPUT_DIR / "RiskReport.csv"
OUT_TRENDS_CSV = OUTPUT_DIR / "RiskTrends.csv"
OUT_REPORT_MD = OUTPUT_DIR / "RiskReport.md"
HISTORY_DIR = OUTPUT_DIR / "history"

TOP_N = 10
CHANGE_THRESHOLD = 3  # abs(delta_score) >= this

def pick_used_values(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def num(col):
        return pd.to_numeric(df.get(col, None), errors="coerce")

    df["risk_score_baseline_num"] = num("risk_score_baseline")
    df["likelihood_baseline_num"] = num("likelihood_baseline")
    df["impact_baseline_num"] = num("impact_baseline")

    df["risk_score_adjusted_num"] = num("risk_score_adjusted")
    df["likelihood_adjusted_num"] = num("likelihood_adjusted")
    df["impact_adjusted_num"] = num("impact_adjusted")

    df["score_used"] = df["risk_score_adjusted_num"].where(df["risk_score_adjusted_num"].notna(),
                                                           df["risk_score_baseline_num"])
    df["likelihood_used"] = df["likelihood_adjusted_num"].where(df["likelihood_adjusted_num"].notna(),
                                                                df["likelihood_baseline_num"])
    df["impact_used"] = df["impact_adjusted_num"].where(df["impact_adjusted_num"].notna(),
                                                        df["impact_baseline_num"])

    def to_bool(v):
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("true", "1", "yes", "y")

    df["internal_signals_used_bool"] = df.get("internal_signals_used", False).apply(to_bool)

    return df

def first_actions(actions: str, n: int = 2) -> str:
    if actions is None or (isinstance(actions, float) and pd.isna(actions)):
        return ""
    parts = [p.strip() for p in str(actions).split("|") if p.strip()]
    return " | ".join(parts[:n])

def load_risks() -> pd.DataFrame:
    if os.path.exists(ENRICHED):
        return pd.read_csv(ENRICHED)
    return pd.read_csv(BASELINE)

def build_report(df: pd.DataFrame, run_id: str, report_date: str) -> pd.DataFrame:
    df = pick_used_values(df)

    # Require usable score
    df = df[df["score_used"].notna()].copy()

    # Tie-break ranking
    strength_rank = {"Strong": 3, "Medium": 2, "Weak": 1}
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}

    df["strength_rank"] = df.get("evidence_strength", "").map(strength_rank).fillna(0)
    df["conf_rank"] = df.get("confidence", "").map(conf_rank).fillna(0)

    df = df.sort_values(by=["score_used", "strength_rank", "conf_rank"],
                        ascending=[False, False, False]).reset_index(drop=True)
    df["rank"] = df.index + 1

    out = pd.DataFrame({
        "report_run_id": run_id,
        "report_date": report_date,
        "rank": df["rank"],
        "risk_id": df.get("risk_id", ""),
        "cluster_id": df.get("cluster_id", ""),
        "event_type": df.get("event_type", ""),
        "primary_asset_or_service": df.get("primary_asset_or_service", ""),
        "title": df.get("title", ""),
        "risk_category": df.get("risk_category", ""),
        "business_function": df.get("business_function", ""),

        "score_used": df["score_used"].astype(int),
        "likelihood_used": df["likelihood_used"].astype(int),
        "impact_used": df["impact_used"].astype(int),

        "evidence_strength": df.get("evidence_strength", ""),
        "confidence": df.get("confidence", ""),
        "internal_signals_used": df["internal_signals_used_bool"],
        "internal_outage_refs": df.get("internal_outage_refs", ""),

        "recommended_actions_top": df.get("recommended_actions", "").apply(lambda x: first_actions(x, 2)),
        "framework_mapping": df.get("framework_mapping", ""),
        "executive_summary": df.get("executive_summary", ""),
    })

    return out

def build_trends(current_report: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "report_run_id","report_date","risk_id","title",
        "prior_score","current_score","delta_score",
        "prior_confidence","current_confidence",
        "prior_internal_signals","current_internal_signals",
        "change_reason"
    ]

    if not os.path.exists(OUT_REPORT_CSV):
        return pd.DataFrame(columns=cols)

    prior = pd.read_csv(OUT_REPORT_CSV)

    merged = current_report.merge(prior, on="risk_id", how="left", suffixes=("_cur", "_prior"))

    merged["prior_score"] = pd.to_numeric(merged["score_used_prior"], errors="coerce")
    merged["current_score"] = pd.to_numeric(merged["score_used_cur"], errors="coerce")
    merged["delta_score"] = merged["current_score"] - merged["prior_score"]

    # Only when prior exists and delta is meaningful
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
        return pd.DataFrame(columns=cols)

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

    # Consolidate duplicate scenario themes before selecting the Top 10.
    # This keeps the executive report from repeating the same risk theme
    # several times when multiple incidents map to the same scenario.
    top = (
        report
        .sort_values(
            by=["score_used", "evidence_strength", "confidence"],
            ascending=[False, False, False]
        )
        .drop_duplicates(
            subset=["title", "risk_category", "business_function"],
            keep="first"
        )
        .head(TOP_N)
        .copy()
    )

    # Re-rank after deduplication
    top["rank"] = range(1, len(top) + 1)

    lines = []
    lines.append("# AI Risk Assessment – Executive Brief")
    lines.append(f"- Report date: {report_date}")
    lines.append(f"- Total risks evaluated: {len(report)}")
    lines.append("")

    lines.append(f"## Top {min(TOP_N, len(top))} risk themes")
    for _, r in top.iterrows():
        lines.append(f"### {int(r['rank'])}. {r['title']}")
        lines.append(f"- Score: {int(r['score_used'])} (L={int(r['likelihood_used'])}, I={int(r['impact_used'])})")
        lines.append(f"- Category / Function: {r['risk_category']} / {r['business_function']}")
        lines.append(f"- Event / Asset: {r['event_type']} / {r['primary_asset_or_service']}")
        lines.append(f"- Evidence: {r['evidence_strength']} | Confidence: {r['confidence']}")
        lines.append(f"- Internal enrichment used: {bool(r['internal_signals_used'])}")
        if str(r.get("internal_outage_refs", "")).strip():
            lines.append(f"- Internal refs: {r['internal_outage_refs']}")
        if str(r.get("recommended_actions_top", "")).strip():
            lines.append(f"- Recommended actions: {r['recommended_actions_top']}")
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

def ensure_history_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)

def archive_outputs(run_id: str, report_date: str):
    """
    Save a permanent copy of the current report artifacts.
    """
    ensure_history_dir()
    csv_hist = os.path.join(HISTORY_DIR, f"RiskReport_{report_date}_{run_id}.csv")
    md_hist  = os.path.join(HISTORY_DIR, f"RiskReport_{report_date}_{run_id}.md")

    # Copy if the source exists (script writes them later, but this is safe)
    if os.path.exists(OUT_REPORT_CSV):
        shutil.copyfile(OUT_REPORT_CSV, csv_hist)
    if os.path.exists(OUT_REPORT_MD):
        shutil.copyfile(OUT_REPORT_MD, md_hist)

def main():
    df = load_risks()

    run_id = str(uuid.uuid4())
    report_date = datetime.now().date().isoformat()

    # Build report objects
    report = build_report(df, run_id, report_date)
    trends = build_trends(report)

    # Write latest outputs
    report.to_csv(OUT_REPORT_CSV, index=False)
    trends.to_csv(OUT_TRENDS_CSV, index=False)
    write_markdown(report, trends, report_date)

    # Archive immutable copies
    archive_outputs(run_id, report_date)

    print(f"Wrote {OUT_REPORT_CSV} ({len(report)} rows)")
    print(f"Wrote {OUT_TRENDS_CSV} ({len(trends)} rows)")
    print(f"Wrote {OUT_REPORT_MD}")
    print(f"Archived to history/RiskReport_{report_date}_{run_id}.csv and .md")


if __name__ == "__main__":
    main()

