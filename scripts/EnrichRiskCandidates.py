import pandas as pd
from datetime import datetime, timezone
import os
import re

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"

RISK_CSV = DATA_DIR / "RiskCandidates.csv"
OUTAGE_CSV = DATA_DIR / "Outage_Input.csv" 
OUTPUT_CSV = OUTPUT_DIR / "RiskCandidates_Enriched.csv"

LOOKBACK_DAYS = 365

def parse_dt(val):
    if pd.isna(val) or str(val).strip() == "":
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", ""))
    except Exception:
        try:
            return datetime.strptime(str(val)[:10], "%Y-%m-%d")
        except Exception:
            return None

def norm(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def tokens(s: str):
    return {t for t in norm(s).split() if len(t) >= 3}

def jaccard(a, b) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni else 0.0

def risk_to_event_family(event_type: str) -> str:
    et = (event_type or "").strip().upper()
    if et.startswith("OUTAGE") or et == "INTEGRATION_FAILURE":
        return "OUTAGE"
    if et.startswith("SECURITY"):
        return "SECURITY"
    if et.startswith("REGULATORY"):
        return "REGULATORY"
    if et.startswith("SUPPLIER"):
        return "SUPPLIER"
    return "OTHER"

def outage_to_event_family(out_row: pd.Series) -> str:
    rc = norm(str(out_row.get("root_cause_category","")))
    sec = str(out_row.get("security_related","")).strip().upper() == "TRUE"
    if sec or "security" in rc or "ransom" in rc or "breach" in rc:
        return "SECURITY"
    if any(x in rc for x in ["integration", "edi", "api"]):
        return "OUTAGE"
    if any(x in rc for x in ["network", "cloud", "app", "identity", "access"]):
        return "OUTAGE"
    if any(x in rc for x in ["regulator", "compliance", "audit"]):
        return "REGULATORY"
    if "supplier" in rc or "vendor" in rc:
        return "SUPPLIER"
    return "OUTAGE"

def match_score(risk_row: pd.Series, out_row: pd.Series) -> float:
    # MatchScore = 0.55 BF + 0.25 Family + 0.20 TokenOverlap
    bf_r = norm(str(risk_row.get("business_function","")))
    bf_o = norm(str(out_row.get("business_function","")))
    BF = 1.0 if (bf_r and bf_o and bf_r == bf_o) else 0.0

    fam_r = risk_to_event_family(str(risk_row.get("event_type","")))
    fam_o = outage_to_event_family(out_row)
    FAMILY = 1.0 if fam_r == fam_o else 0.0

    r_text = " ".join([
        str(risk_row.get("primary_asset_or_service","")),
        str(risk_row.get("assets_or_services","")),
        str(risk_row.get("title","")),
        str(risk_row.get("scenario","")),
    ])
    o_text = " ".join([
        str(out_row.get("service_or_app","")),
        str(out_row.get("summary","")),
        str(out_row.get("root_cause_category","")),
        str(out_row.get("systems_downstream_impacted","")),
    ])
    K = jaccard(tokens(r_text), tokens(o_text))

    return 0.55 * BF + 0.25 * FAMILY + 0.20 * K

def adjust_likelihood(L0: int, count_lookback: int, sev1_or_high: int) -> int:
    Ladj = L0
    if count_lookback == 0:
        return Ladj
    if count_lookback == 1:
        Ladj = min(5, Ladj + 1)
    elif 2 <= count_lookback <= 3:
        Ladj = min(5, Ladj + 1)
    else:  # >=4
        Ladj = min(5, Ladj + 2)

    if sev1_or_high >= 2:
        Ladj = min(5, Ladj + 1)

    return Ladj

def adjust_impact(I0: int, matched: pd.DataFrame) -> int:
    Iadj = I0
    if matched.empty:
        return Iadj

    # customer impact
    if "customer_impact" in matched.columns:
        if any(str(x).strip().lower() == "outage" for x in matched["customer_impact"].astype(str).tolist()):
            Iadj = min(5, Iadj + 1)

    # duration
    if "duration_minutes" in matched.columns:
        dur = pd.to_numeric(matched["duration_minutes"], errors="coerce").dropna()
        if not dur.empty and dur.mean() >= 240:
            Iadj = min(5, Iadj + 1)

    # data integrity issues
    if "data_integrity_issue" in matched.columns:
        if any(str(x).strip().upper() == "TRUE" for x in matched["data_integrity_issue"].astype(str).tolist()):
            Iadj = min(5, Iadj + 1)

    return Iadj

def conf_upshift(conf: str) -> str:
    c = (conf or "").strip().lower()
    if c == "low":
        return "Medium"
    if c == "medium":
        return "High"
    if c == "high":
        return "High"
    return conf or "Medium"

def main():
    df_risk = pd.read_csv(RISK_CSV)

    if not os.path.exists(OUTAGE_CSV):
        df_risk.to_csv(OUTPUT_CSV, index=False)
        print(f"No {OUTAGE_CSV} found. Wrote unchanged output to {OUTPUT_CSV}.")
        return

    df_out = pd.read_csv(OUTAGE_CSV)

    # Parse dates and apply lookback
    now = datetime.now(timezone.utc)
    cutoff_ts = now.timestamp() - LOOKBACK_DAYS * 24 * 3600

    df_out["start_dt"] = df_out["start_time"].apply(parse_dt)
    df_out["within_lookback"] = df_out["start_dt"].apply(lambda d: (d is not None) and (d.replace(tzinfo=timezone.utc).timestamp() >= cutoff_ts))

    enriched_rows = []

    for _, r in df_risk.iterrows():
        # Compute match scores
        scored = []
        for idx, o in df_out.iterrows():
            s = match_score(r, o)
            scored.append((idx, s))

        scored.sort(key=lambda x: x[1], reverse=True)

        # Take matches above thresholds
        matched_idxs = [idx for idx, s in scored if s >= 0.70][:10]
        matched = df_out.loc[matched_idxs].copy() if matched_idxs else df_out.head(0).copy()
        matched_recent = matched[matched["within_lookback"] == True].copy() if not matched.empty else matched

        if matched_recent.empty:
            enriched_rows.append(r.to_dict())
            continue

        # Signals
        count_lb = len(matched_recent)
        sev = matched_recent.get("severity", pd.Series([], dtype=str)).astype(str).str.lower()
        sev1_or_high = int(((sev == "sev1") | (sev == "high") | (sev == "critical")).sum())

        # Baselines (fallback defaults)
        L0 = int(r.get("likelihood_baseline", 2) or 2)
        I0 = int(r.get("impact_baseline", 3) or 3)

        Ladj = adjust_likelihood(L0, count_lb, sev1_or_high)
        Iadj = adjust_impact(I0, matched_recent)
        Sadj = Ladj * Iadj

        # Refs
        refs = [str(x).strip() for x in matched_recent.get("outage_id", []).tolist() if str(x).strip()]
        refs_str = ",".join(refs[:20])

        # Confidence uplift
        conf0 = str(r.get("confidence", "")).strip()
        conf_adj = conf0
        if count_lb >= 2 or sev1_or_high >= 1:
            conf_adj = conf_upshift(conf0)

        out_row = r.to_dict()
        out_row["internal_signals_used"] = True
        out_row["internal_outage_refs"] = refs_str
        out_row["likelihood_adjusted"] = Ladj
        out_row["impact_adjusted"] = Iadj
        out_row["risk_score_adjusted"] = Sadj
        out_row["confidence"] = conf_adj

        rationale = str(out_row.get("score_rationale", "")).strip()
        note = f" Internal enrichment: matched_outages_last_{LOOKBACK_DAYS}d={count_lb}, sev1/high/critical={sev1_or_high}, refs={refs_str[:120]}."
        out_row["score_rationale"] = (rationale + note).strip()

        enriched_rows.append(out_row)

    df_enriched = pd.DataFrame(enriched_rows)
    df_enriched.to_csv(OUTPUT_CSV, index=False)
    print(f"Wrote enriched risks to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
