import pandas as pd
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Set, List, Optional, Dict

EVIDENCE_CACHE = "EvidenceCache.csv"
OUT_CLUSTERS = "IncidentClusters.csv"

RELEVANCE_MIN = 0.2
SCORE_MERGE = 0.72
SCORE_MAYBE = 0.62
ENTITY_OVERLAP_MAYBE = 0.25

TIME_WINDOW_DAYS_DEFAULT = 7
TIME_WINDOW_BY_EVENT_TYPE = {
    "OUTAGE_IDENTITY": 7,
    "OUTAGE_CLOUD_REGION": 7,
    "OUTAGE_APPLICATION": 7,
    "OUTAGE_NETWORK": 7,
    "INTEGRATION_FAILURE": 7,
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

def parse_date(val: str) -> Optional[datetime]:
    if pd.isna(val) or str(val).strip() == "":
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", ""))
    except Exception:
        try:
            return datetime.strptime(str(val)[:10], "%Y-%m-%d")
        except Exception:
            return None

def split_set_commas(val: str) -> Set[str]:
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
        if item.get("profile_id"):
            self.profile_ids.add(item.get("profile_id"))
        self.entity_union |= item["entities"]
        self.keyword_union |= item["keywords"]
        if score_vs_anchor is not None:
            self.scores_vs_anchor.append(score_vs_anchor)

def cluster_from_evidence(df: pd.DataFrame) -> List[Cluster]:
    df = df.copy()

    # normalize column names if needed
    if "relevance_score" not in df.columns:
        df["relevance_score"] = 0.0

    df["relevance_score"] = pd.to_numeric(df["relevance_score"], errors="coerce").fillna(0.0)
    df = df[df["relevance_score"] >= RELEVANCE_MIN].copy()

    df["published_dt"] = df.get("published_date", "").apply(parse_date)

    items = []
    for _, row in df.iterrows():
        entities = split_set_commas(row.get("entity_keywords", ""))
        event_k = split_set_commas(row.get("event_keywords", ""))
        asset_k = split_set_commas(row.get("asset_keywords", ""))
        keywords = event_k | asset_k

        norm_title = row.get("normalized_title", "")
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
            "url": str(row.get("url", "")).strip(),
        }
        if item["evidence_id"]:
            items.append(item)

    # sort by date oldest->newest; unknown dates last
    items.sort(key=lambda x: x["published_date"] or datetime.max)

    clusters: List[Cluster] = []
    counter = 1

    for item in items:
        tw = TIME_WINDOW_BY_EVENT_TYPE.get(item.get("event_type_hint", ""), TIME_WINDOW_DAYS_DEFAULT)

        best_cluster = None
        best_score = -1.0

        for c in clusters:
            if c.anchor.get("published_date") is None or item.get("published_date") is None:
                days_diff = 9999
            else:
                days_diff = abs((item["published_date"] - c.anchor["published_date"]).days)

            if days_diff != 9999 and days_diff > tw:
                continue
            if item.get("profile_id") != c.anchor.get("profile_id"):
                continue
            s = score_pair(item, c.anchor)
            ent_overlap = jaccard(item["entities"], c.entity_union)

            eligible = (s >= SCORE_MERGE) or (s >= SCORE_MAYBE and ent_overlap >= ENTITY_OVERLAP_MAYBE)
            if days_diff == 9999:
                eligible = eligible and (s >= 0.75)

            if eligible and s > best_score:
                best_score = s
                best_cluster = c

        if best_cluster is None:
            cid = f"CL-{counter:06d}"
            counter += 1
            c_new = Cluster(cluster_id=cid, anchor=item)
            c_new.add_item(item)
            clusters.append(c_new)
        else:
            best_cluster.add_item(item, score_vs_anchor=best_score)
            if choose_better_anchor(item, best_cluster.anchor):
                best_cluster.anchor = item

    return clusters

def dedupe_preserve_order(items):
    seen = set()
    out = []
    for x in items:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
        return out


def clusters_to_df(clusters: List[Cluster]) -> pd.DataFrame:
    now_iso = datetime.now().isoformat(timespec="seconds")
    rows = []

    for c in clusters:
        dates = [it["published_date"] for it in c.items if it["published_date"] is not None]
        start_date = min(dates).date().isoformat() if dates else ""
        end_date = max(dates).date().isoformat() if dates else ""

        evidence_ids = [it["evidence_id"] for it in c.items]
        profile_ids = sorted({it.get("profile_id","") for it in c.items if it.get("profile_id","")})

        event_type = majority_vote([it.get("event_type_hint","") for it in c.items]) or c.anchor.get("event_type_hint","")
        business_function = majority_vote([it.get("business_function_hint","") for it in c.items]) or c.anchor.get("business_function_hint","")

        all_asset = []
        all_event = []
        pubs = []
        urls = []
        for it in c.items:
            asset_vals = it.get("asset_terms", [])
            event_vals = it.get("event_terms", [])

            all_asset.extend(asset_vals)
            all_event.extend(event_vals)

            if it.get("publisher"):
                pubs.append(it["publisher"])
            if it.get("url"):
                urls.append(it["url"])

        urls = dedupe_preserve_order(urls)

        primary_asset = top_terms(all_asset, n=1) or "UNKNOWN"
        if primary_asset in {"device", "devices", "endpoint", "endpoints"}:
            primary_asset = "endpoints"
        elif primary_asset in {"system", "systems", "server", "servers", "platform", "environment", "infrastructure"}:
            primary_asset = "systems"

        if primary_asset == "UNKNOWN" and event_type == "DESTRUCTIVE_CYBER_ATTACK":
            primary_asset = "systems"

        if primary_asset == "UNKNOWN" and event_type == "OUTAGE_APPLICATION":
            primary_asset = "applications"
            
        impact_k = top_terms(all_event, n=3)
        entity_summary = ",".join(sorted(list(c.entity_union))[:8])
        strength = evidence_strength(c.anchor.get("source_type",""), len(c.items))

        conf = (sum(c.scores_vs_anchor)/len(c.scores_vs_anchor)) if c.scores_vs_anchor else max(0.50, min(0.85, float(c.anchor.get("relevance_score", 0.0) or 0.0)))

        cluster_summary = f"{event_type or 'INCIDENT'} affecting {primary_asset} in {business_function or 'Unknown Function'}."

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
            "anchor_evidence_id": c.anchor.get("evidence_id",""),
            "anchor_source_type": c.anchor.get("source_type",""),
            "evidence_strength": strength,
            "entity_summary": entity_summary,
            "impact_keywords": impact_k,
            "cluster_summary": cluster_summary,
            "confidence_score": round(conf, 3),
            "publishers": ";".join(sorted(set(pubs))[:8]),
            "urls": ";".join(urls[:8]),
            "last_updated": now_iso,
        })

    return pd.DataFrame(rows)

def main():
    df = pd.read_csv(EVIDENCE_CACHE)

    clusters = cluster_from_evidence(df)
    out = clusters_to_df(clusters)

    out.to_csv(OUT_CLUSTERS, index=False)
    print(f"Wrote {len(out)} clusters to {OUT_CLUSTERS}")

if __name__ == "__main__":
    main()
