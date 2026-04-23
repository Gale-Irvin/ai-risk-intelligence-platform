import pandas as pd
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Set, List, Optional, Dict
import math

# ----------------------------
# Config (tune these)
# ----------------------------
RELEVANCE_MIN = 0.60
SCORE_MERGE = 0.72
SCORE_MAYBE = 0.62
ENTITY_OVERLAP_MAYBE = 0.25

# Default time window (days) for INCIDENT-style clustering
TIME_WINDOW_DAYS_DEFAULT = 7

# Optionally override by event_type_hint (example)
TIME_WINDOW_BY_EVENT_TYPE = {
    "OUTAGE_IDENTITY": 7,
    "OUTAGE_CLOUD_REGION": 7,
    "OUTAGE_APPLICATION": 7,
    "SECURITY_RANSOMWARE": 14,
    "SECURITY_BREACH": 14,
    "REGULATORY_ENFORCEMENT": 90,
    "SUPPLIER_FAILURE": 90,
}

SOURCE_TYPE_RANK = {
    "status_page": 5,
    "regulator": 4,
    "advisory": 3,
    "report": 2,
    "news": 1,
}

# ----------------------------
# Helpers
# ----------------------------
def parse_date(val: str) -> Optional[datetime]:
    if pd.isna(val) or str(val).strip() == "":
        return None
    # Accept YYYY-MM-DD or ISO timestamps
    try:
        return datetime.fromisoformat(str(val).replace("Z", ""))
    except Exception:
        # fallback attempt
        try:
            return datetime.strptime(str(val)[:10], "%Y-%m-%d")
        except Exception:
            return None

def split_set(val: str) -> Set[str]:
    if pd.isna(val) or str(val).strip() == "":
        return set()
    return {x.strip() for x in str(val).split(",") if x.strip()}

def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a.intersection(b))
    union = len(a.union(b))
    return inter / union if union else 0.0

def title_similarity(a: str, b: str) -> float:
    a = (a or "").strip()
    b = (b or "").strip()
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

def date_proximity_score(days_diff: int) -> float:
    if days_diff <= 1:
        return 1.0
    if 2 <= days_diff <= 3:
        return 0.8
    if 4 <= days_diff <= 7:
        return 0.5
    if 8 <= days_diff <= 14:
        return 0.2
    return 0.0

def score_pair(item_a: Dict, item_b: Dict) -> float:
    # Score(A,B)=0.35T + 0.25E + 0.20K + 0.20D
    T = title_similarity(item_a["normalized_title"], item_b["normalized_title"])
    E = jaccard(item_a["entities"], item_b["entities"]) if (item_a["entities"] or item_b["entities"]) else 0.0
    K = jaccard(item_a["keywords"], item_b["keywords"]) if (item_a["keywords"] or item_b["keywords"]) else 0.0

    da = item_a["published_date"]
    db = item_b["published_date"]
    if da is None or db is None:
        D = 0.0
    else:
        days_diff = abs((da - db).days)
        D = date_proximity_score(days_diff)

    return 0.35 * T + 0.25 * E + 0.20 * K + 0.20 * D

def choose_better_anchor(candidate: Dict, current: Dict) -> bool:
    # Higher source rank wins; tie-breaker higher relevance_score
    cand_rank = SOURCE_TYPE_RANK.get(candidate.get("source_type", "").strip(), 0)
    curr_rank = SOURCE_TYPE_RANK.get(current.get("source_type", "").strip(), 0)
    if cand_rank != curr_rank:
        return cand_rank > curr_rank

    cand_rel = candidate.get("relevance_score", 0.0) or 0.0
    curr_rel = current.get("relevance_score", 0.0) or 0.0
    return cand_rel > curr_rel

def majority_vote(values: List[str]) -> str:
    vals = [v for v in values if v and str(v).strip() != ""]
    if not vals:
        return ""
    counts = {}
    for v in vals:
        counts[v] = counts.get(v, 0) + 1
    return sorted(counts.items(), key=lambda x: (-x[1], x[0]))[0][0]

def top_terms(terms: List[str], n: int = 2) -> str:
    counts = {}
    for t in terms:
        if not t:
            continue
        counts[t] = counts.get(t, 0) + 1
    top = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:n]
    return ",".join([t[0] for t in top])

def evidence_strength(anchor_source_type: str, evidence_count: int) -> str:
    anchor_source_type = (anchor_source_type or "").strip()
    if (anchor_source_type in ("status_page", "regulator") and evidence_count >= 2) or evidence_count >= 3:
        return "Strong"
    if evidence_count == 2:
        return "Medium"
    return "Weak"

# ----------------------------
# Cluster structure
# ----------------------------
@dataclass
class Cluster:
    cluster_id: str
    anchor: Dict
    items: List[Dict] = field(default_factory=list)
    entity_union: Set[str] = field(default_factory=set)
    keyword_union: Set[str] = field(default_factory=set)
    profile_ids: Set[str] = field(default_factory=set)
    scores_vs_anchor: List[float] = field(default_factory=list)

    def add_item(self, item: Dict, score_vs_anchor: Optional[float] = None):
        self.items.append(item)
        self.profile_ids.add(item.get("profile_id", ""))
        self.entity_union |= item["entities"]
        self.keyword_union |= item["keywords"]
        if score_vs_anchor is not None:
            self.scores_vs_anchor.append(score_vs_anchor)

# ----------------------------
# Main clustering routine
# ----------------------------
def cluster_from_evidence(df: pd.DataFrame) -> List[Cluster]:
    # Pre-filter
    df = df.copy()
    df["relevance_score"] = pd.to_numeric(df.get("relevance_score", 0.0), errors="coerce").fillna(0.0)
    df = df[df["relevance_score"] >= RELEVANCE_MIN]

    # Parse dates
    df["published_dt"] = df["published_date"].apply(parse_date)

    # Build normalized items list
    items = []
    for _, row in df.iterrows():
        entities = split_set(row.get("entity_keywords", ""))
        event_k = split_set(row.get("event_keywords", ""))
        asset_k = split_set(row.get("asset_keywords", ""))
        keywords = event_k | asset_k

        norm_title = row.get("normalized_title")
        if pd.isna(norm_title) or str(norm_title).strip() == "":
            norm_title = str(row.get("title", "")).lower().strip()

        item = {
            "evidence_id": str(row.get("evidence_id", "")).strip(),
            "profile_id": str(row.get("profile_id", "")).strip(),
            "source_type": str(row.get("source_type", "")).strip(),
            "publisher": str(row.get("publisher", "")).strip(),
            "title": str(row.get("title", "")).strip(),
            "normalized_title": str(norm_title).strip(),
            "published_date": row.get("published_dt"),
            "event_type_hint": str(row.get("event_type_hint", "")).strip(),
            "business_function_hint": str(row.get("business_function_hint", "")).strip(),
            "entities": entities,
            "keywords": keywords,
            "event_terms": list(event_k),
            "asset_terms": list(asset_k),
            "relevance_score": float(row.get("relevance_score", 0.0) or 0.0),
        }
        if item["evidence_id"]:
            items.append(item)

    # Sort by published date (oldest first); unknown dates last
    items.sort(key=lambda x: x["published_date"] or datetime.max)

    clusters: List[Cluster] = []
    cluster_counter = 1

    for item in items:
        # Determine time window for this item
        tw = TIME_WINDOW_BY_EVENT_TYPE.get(item.get("event_type_hint", ""), TIME_WINDOW_DAYS_DEFAULT)

        best_cluster = None
        best_score = -1.0

        for c in clusters:
            if c.anchor.get("published_date") is None or item.get("published_date") is None:
                # If missing dates, still allow but require stronger match later
                days_diff = 9999
            else:
                days_diff = abs((item["published_date"] - c.anchor["published_date"]).days)

            # Hard gate on time (if both dates exist)
            if days_diff != 9999 and days_diff > tw:
                continue

            s = score_pair(item, c.anchor)
            ent_overlap = jaccard(item["entities"], c.entity_union)

            eligible = (s >= SCORE_MERGE) or (s >= SCORE_MAYBE and ent_overlap >= ENTITY_OVERLAP_MAYBE)

            # If missing dates, tighten eligibility a bit
            if days_diff == 9999:
                eligible = eligible and (s >= 0.75)

            if eligible and s > best_score:
                best_score = s
                best_cluster = c

        if best_cluster is None:
            cid = f"CL-{cluster_counter:06d}"
            cluster_counter += 1
            c_new = Cluster(cluster_id=cid, anchor=item)
            c_new.add_item(item, score_vs_anchor=None)
            clusters.append(c_new)
        else:
            best_cluster.add_item(item, score_vs_anchor=best_score)
            # Maybe promote anchor
            if choose_better_anchor(item, best_cluster.anchor):
                best_cluster.anchor = item

    return clusters

def clusters_to_dataframe(clusters: List[Cluster]) -> pd.DataFrame:
    rows = []
    now_iso = datetime.now().isoformat(timespec="seconds")

    for c in clusters:
        published_dates = [it["published_date"] for it in c.items if it["published_date"] is not None]
        start_date = min(published_dates).date().isoformat() if published_dates else ""
        end_date = max(published_dates).date().isoformat() if published_dates else ""

        evidence_ids = [it["evidence_id"] for it in c.items]
        profile_ids = sorted({it.get("profile_id", "") for it in c.items if it.get("profile_id", "")})

        # Normalize event_type and business function
        event_type = majority_vote([it.get("event_type_hint", "") for it in c.items]) or c.anchor.get("event_type_hint", "")
        business_function = majority_vote([it.get("business_function_hint", "") for it in c.items]) or c.anchor.get("business_function_hint", "")

        # Pick primary asset/service as most common asset keyword
        all_asset_terms = []
        for it in c.items:
            all_asset_terms.extend(it.get("asset_terms", []))
        primary_asset = top_terms(all_asset_terms, n=1) or "UNKNOWN"

        # Impact keywords: top event terms
        all_event_terms = []
        for it in c.items:
            all_event_terms.extend(it.get("event_terms", []))
        impact_k = top_terms(all_event_terms, n=3)

        # Entity summary
        entity_summary = ",".join(sorted(list(c.entity_union))[:5])

        # Evidence strength
        strength = evidence_strength(c.anchor.get("source_type", ""), len(c.items))

        # Confidence score: average score vs anchor for merged items; if only one item, base on relevance
        if c.scores_vs_anchor:
            conf = sum(c.scores_vs_anchor) / len(c.scores_vs_anchor)
        else:
            conf = max(0.50, min(0.85, float(c.anchor.get("relevance_score", 0.0) or 0.0)))

        # Cluster summary (template-based for prototype)
        cluster_summary = (
            f"Clustered {len(c.items)} source(s) reporting {event_type or 'an event'} "
            f"affecting {primary_asset} in {business_function or 'a business function'}."
        )

        rows.append({
            "cluster_id": c.cluster_id,
            "cluster_type": "INCIDENT",
            "profile_ids": ",".join(profile_ids),
            "event_type": event_type,
            "primary_asset_or_service": primary_asset,
            "business_function": business_function,
            "start_date": start_date,
            "end_date": end_date,
            "evidence_ids": ",".join(evidence_ids),
            "evidence_count": len(c.items),
            "anchor_evidence_id": c.anchor.get("evidence_id", ""),
            "evidence_strength": strength,
            "entity_summary": entity_summary,
            "impact_keywords": impact_k,
            "cluster_summary": cluster_summary,
            "confidence_score": round(conf, 3),
            "last_updated": now_iso,
        })

    return pd.DataFrame(rows)

# ----------------------------
# Run (edit filenames as needed)
# ----------------------------
if __name__ == "__main__":
    evidence_path = "EvidenceCache.csv"
    clusters_path = "IncidentClusters.csv"

    df_evidence = pd.read_csv(evidence_path)
    clusters = cluster_from_evidence(df_evidence)
    df_clusters = clusters_to_dataframe(clusters)

    df_clusters.to_csv(clusters_path, index=False)
    print(f"Wrote {len(df_clusters)} clusters to {clusters_path}")
