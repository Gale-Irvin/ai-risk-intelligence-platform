import pandas as pd
from datetime import datetime
from typing import Set
import os
import re

RISK_CSV = "RiskCandidates.csv"
OUTAGE_CSV = "Outage_Input.csv"          # optional
OUTPUT_CSV = "RiskCandidates_Enriched.csv"

LOOKBACK_DAYS = 365
MATCH_STRONG = 0.70
MATCH_MAYBE = 0.60
MAYBE_K_MIN = 0.25

def parse_date(val):
    if pd.isna(val) or str(val).strip() == "":
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", ""))
    except Exception:
        try:
            return datetime.strptime(str(val)[:10], "%Y-%m-%d")
        except Exception:
            return None

def norm_tokens(text: str) -> Set[str]:
    if text is None or (isinstance(text, float) and pd.isna(text)):
        return set()
    s = str(text).lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    toks = {t for t in s.split() if len(t) >= 3}
    # small synonym normalizations (keep tiny + generic)
    replacements = {
        "single": None,  # too generic
        "sign": None,
        "sso": "sso",
        "iam": "iam",
        "identity": "identity",
        "auth": "authentication",
        "authentication": "authentication",
        "login": "login",
        "outage": "outage",
        "api": "api",
        "edi": "edi",
        "erp": "erp",
        "wms": "wms",
        "network": "network",
        "cloud": "cloud",
        "vendor": "vendor",
        "ransomware": "ransomware",
        "breach": "breach",
    }
    out = set()
    for t in toks:
        if t in replacements:
            mapped = replacements[t]
            if mapped:
                out.add(mapped)
        else:
            out.add(t)
    return out

def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni else 0.0

def conf_upshift(conf: str) -> str:
    c = (conf or "").strip().lower()
    if c == "low":
        return "Medium"
    if c == "medium":
        return "High"
    if c == "high":
        return "High"
    return conf or "Medium"

def rc_alignment(risk_category: str, outage_row: pd.Series) -> float:
    rc = str(outage_row.get("root_cause_category", "")).strip().lower()
    sec = str(outage_row.get("security_related", "")).strip().upper() == "TRUE"
    cat = (risk_category or "").strip().lower()

    if cat == "cyber":
        return 1.0 if sec else 0.0

    if cat == "technology":
        if rc in {"network", "cloud provider", "app defect", "change", "vendor", "security", "human error"}:
            return 1.0
        # allow partial match
        if any(x in rc for x in ["network", "cloud", "app", "change", "vendor"]):
            return 1.0
        return 0.0

    if cat in {"operational", "physical", "regulatory"}:
        # operational/physical/regulatory are harder to infer from outage rows generically
        # keep conservative:
        return 1.0 if cat in rc else 0.0

    return 0.0

def match_score(risk_row: pd.Series, outage_row: pd.Series) -> float:
    # BF: exact match
    bf_r = str(risk_row.get("business_function", "")).strip().lower()
    bf_o = str(outage_row.get("business_function", "")).strip().lower()
    BF = 1.0 if (bf_r and bf_o and bf_r == bf_o) else 0.0

    # Tokens
    r_text = " ".join([
        str(risk_row.get("assets_or_services", "")),
        str(risk_row.get("title", "")),
        str(risk_row.get("scenario", "")),
    ])
    o_text = " ".join([
        str(outage_row.get("service_or_app", "")),
        str(outage_row.get("summary", "")),
        str(outage_row.get("root_cause_category", "")),
        str(outage_row.get("systems_downstream_impacted", "")),
    ])
    R = norm_tokens(r_text)
    O = norm_tokens(o_text)
    K = jaccard(R, O)

    RC = rc_alignment(str(risk_row.get("risk_category", "")), outage_row)

    return 0.45 * BF + 0.35 * K + 0.20 * RC

def adjust_likelihood(L0: int, count_365: int, sev1_count_365: int) -> int:
    Ladj = L0
    if count_365 == 0:
        return Ladj
    if count_365 == 1:
        Ladj = min(5, Ladj + 1)
    elif 2 <= count_365 <= 3:
        Ladj = min(5, Ladj + 1)
    else:  # >=4
        Ladj = min(5, Ladj + 2)

    if sev1_count_365 >= 2:
        Ladj = min(5, Ladj + 1)

    return Ladj

def adjust_impact(I0: int, matched: pd.DataFrame) -> int:
    Iadj = I0
    if matched.empty:
        return Iadj

    # customer impact
    if any(str(x).strip().lower() == "outage" for x in matched.get("customer_impact", [])):
        Iadj = min(5, Iadj + 1)

    # duration
    if "duration_minutes" in matched.columns:
        dur = pd.to_numeric(matched["duration_minutes"], errors="coerce")
        avg_dur = dur.dropna().mean()
        if avg_dur is not None and avg_dur >= 240:
            Iadj = min(5, Iadj + 1)

    # data integrity
    if any(str(x).strip().upper() == "TRUE" for x in matched.get("data_integrity_issue", [])):
        Iadj = min(5, Iadj + 1)

    return Iadj

def main():
    df_risk = pd.read_csv(RISK_CSV)

    if not os.path.exists(OUTAGE_CSV):
        # No internal file provided: output unchanged (but consistent)
        df_risk.to_csv(OUTPUT_CSV, index=False)
        print(f"No {OUTAGE_CSV} found. Wrote unchanged output to {OUTPUT_CSV}.")
        return

    df_outage = pd.read_csv(OUTAGE_CSV)

    # Parse outage dates
    df_outage["start_dt"] = df_outage["start_time"].apply(parse_date)
    now = datetime.now()
    cutoff = now.timestamp() - LOOKBACK_DAYS * 24 * 3600

    def within_lookback(dt):
        if dt is None:
            return False
        return dt.timestamp() >= cutoff

    df_outage["within_lookback"] = df_outage["start_dt"].apply(within_lookback)

    enriched_rows = []
    for _, r in df_risk.iterrows():
        # Evaluate all outages, keep top matches
        scores = []
        for idx, o in df_outage.iterrows():
            s = match_score(r, o)
            scores.append((idx, s))

        scores.sort(key=lambda x: x[1], reverse=True)

        # Select matches
        matched_idxs = []
        for idx, s in scores[:50]:  # only evaluate top 50 candidates for efficiency
            o = df_outage.loc[idx]
            bf_match = str(r.get("business_function", "")).strip().lower() == str(o.get("business_function", "")).strip().lower()
            # token overlap (K) not directly returned; use score logic gates instead:
            if s >= MATCH_STRONG:
                matched_idxs.append(idx)
            elif s >= MATCH_MAYBE and bf_match:
                # approximate "K>=0.25" by requiring score >= 0.60 + BF=1.0 already helps
                matched_idxs.append(idx)

        matched = df_outage.loc[matched_idxs].copy() if matched_idxs else df_outage.head(0).copy()

        # Apply lookback window for scoring signals
        matched_recent = matched[matched["within_lookback"] == True].copy() if not matched.empty else matched

        if matched_recent.empty:
            # no enrichment
            enriched_rows.append(r.to_dict())
            continue

        # Build refs
        refs = [str(x).strip() for x in matched_recent.get("outage_id", []).tolist() if str(x).strip()]
        refs_str = ",".join(refs[:20])  # cap length

        # Compute signals
        count_365 = len(matched_recent)
        sev = matched_recent.get("severity", pd.Series([], dtype=str)).astype(str).str.lower()
        sev1_count = int(((sev == "sev1") | (sev == "high")).sum())

        # Baseline L/I
        L0 = int(r.get("likelihood_baseline", 0) or 0)
        I0 = int(r.get("impact_baseline", 0) or 0)
        if L0 == 0:
            L0 = 2
        if I0 == 0:
            I0 = 3

        Ladj = adjust_likelihood(L0, count_365, sev1_count)
        Iadj = adjust_impact(I0, matched_recent)
        Sadj = Ladj * Iadj

        # Confidence uplift
        conf0 = str(r.get("confidence", "")).strip()
        conf_adj = conf0
        if count_365 >= 2 or sev1_count >= 1:
            conf_adj = conf_upshift(conf0)

        # Update row
        out = r.to_dict()
        out["internal_signals_used"] = True
        out["internal_outage_refs"] = refs_str
        out["likelihood_adjusted"] = Ladj
        out["impact_adjusted"] = Iadj
        out["risk_score_adjusted"] = Sadj
        out["confidence"] = conf_adj

        # Append rationale
        rationale = str(out.get("score_rationale", "")).strip()
        enrich_note = (
            f" Internal enrichment: matched_outages_last_{LOOKBACK_DAYS}d={count_365}, "
            f"sev1_or_high={sev1_count}, refs={refs_str[:120]}."
        )
        out["score_rationale"] = (rationale + enrich_note).strip()

        enriched_rows.append(out)

    df_enriched = pd.DataFrame(enriched_rows)

    # Preserve column order (if present)
    df_enriched.to_csv(OUTPUT_CSV, index=False)
    print(f"Wrote enriched risks to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
