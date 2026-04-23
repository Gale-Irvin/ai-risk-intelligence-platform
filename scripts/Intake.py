import pandas as pd
import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import hashlib
import re
import os
from typing import List, Dict, Optional, Set

SEARCH_PROFILES_CSV = "SearchProfiles.csv"
EVIDENCE_CACHE_CSV = "EvidenceCache.csv"

# ------------ Controlled vocab (MVP) ------------
EVENT_TERMS = {
    "outage", "downtime", "incident", "disruption", "degradation", "latency",
    "breach", "leak", "exposed", "ransomware", "extortion",
    "enforcement", "fine", "penalty", "regulator"
}

ASSET_TERMS = {
    "sso", "iam", "identity", "directory", "authentication", "login",
    "erp", "wms", "edi", "api", "gateway", "integration",
    "cloud", "region", "availability", "zone",
    "network", "dns", "vpn",
    "device", "devices", "endpoint", "endpoints", "system", "systems",
    "infrastructure", "servers", "server", "environment", "platform"
}

STOPWORDS = set("""
a an the and or but to of in for on with from by as at is are was were be been being
this that these those it its their our your you we they
""".split())

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def normalize_text(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def tokenize(s: str) -> List[str]:
    s = normalize_text(s)
    toks = [t for t in s.split() if t and t not in STOPWORDS]
    return toks

def extract_terms(text: str, vocab: Set[str]) -> List[str]:
    toks = set(tokenize(text))
    hits = sorted(list(toks.intersection(vocab)))
    return hits

def infer_source_type(url: str, publisher: str) -> str:
    u = (url or "").lower()
    p = (publisher or "").lower()
    if "status" in u or "status" in p:
        return "status_page"
    if any(x in u for x in ["gov", "regulator", "commission", "attorneygeneral"]):
        return "regulator"
    if any(x in u for x in ["advisory", "bulletin", "alert"]):
        return "advisory"
    if any(x in u for x in ["report", "whitepaper", "annual"]):
        return "report"
    return "news"

def event_type_hint(event_keywords: List[str], asset_keywords: List[str], text: str) -> str:
    t = normalize_text(text)
    t_low = t.lower()
    ev = set(x.lower() for x in event_keywords if x)
    ev_text = " ".join(ev)
    a = set(x.lower() for x in asset_keywords if x)

    if any(x in t_low for x in ["cyberattack", "cyber attack", "hackers", "hacker attack"]) and any(x in t_low for x in [
    "disrupted",
    "disruption",
    "continuing",
    "halted",
    "shipping",
    "manufacturing",
    "order processing",
    "operations"
]):
        return "CYBER_OPERATIONAL_DISRUPTION"

    if "ransomware" in ev_text or "ransomware" in t_low:
        return "SECURITY_RANSOMWARE"

    destructive_terms = [
        "wiper",
        "wiper attack",
        "wiper malware",
        "device wipe",
        "wiped",
        "wipe",
        "wipes",
        "disk wipe",
        "system wipe",
        "system wiping",
        "data wiping",
        "destructive malware",
        "data destruction",
        "takedown"
    ]

    if any(x in t_low for x in destructive_terms) or any(x in ev_text for x in destructive_terms):
        return "DESTRUCTIVE_CYBER_ATTACK"

    if any(x in t_low for x in ["breach", "exposed", "leak", "leaked"]) or "breach" in ev_text:
        return "SECURITY_BREACH"

    if ({"sso", "identity", "directory", "authentication", "login"} & a) and ({"outage", "incident", "disruption", "downtime"} & ev):
        return "OUTAGE_IDENTITY"

    if ("cloud" in a or "region" in a or "availability" in a) and ("outage" in ev or "incident" in ev):
        return "OUTAGE_CLOUD_REGION"

    if ({"edi", "api", "integration", "gateway"} & a) and (
        {"failure", "disruption", "outage", "incident"} & set(tokenize(text) + list(ev))
    ):
        return "INTEGRATION_FAILURE"

    if ({"network", "dns", "vpn"} & a) and ("outage" in ev or "incident" in ev):
        return "OUTAGE_NETWORK"

    if any(x in t_low for x in ["regulatory", "enforcement", "fine", "penalty"]):
        return "REGULATORY_ENFORCEMENT"

    if "outage" in ev or "downtime" in ev or "incident" in ev:
        return "OUTAGE_APPLICATION"

    return "UNKNOWN"

def make_evidence_id(url: str) -> str:
    h = hashlib.sha1((url or "").encode("utf-8")).hexdigest()[:10].upper()
    return f"EV-{h}"

def compute_recency_days(published_dt: Optional[datetime]) -> Optional[int]:
    if published_dt is None:
        return None
    delta = datetime.now(timezone.utc) - published_dt.astimezone(timezone.utc)
    return int(delta.total_seconds() // 86400)

def relevance_score(profile_row: pd.Series, title: str, snippet: str, pub_dt: Optional[datetime]) -> float:
    prim = str(profile_row.get("primary_keywords", "") or "")
    sec = str(profile_row.get("secondary_keywords", "") or "")
    recency_days = int(profile_row.get("recency_days", 180) or 180)

    text = f"{title} {snippet}"
    tnorm = normalize_text(text)

    score = 0.0
    # Primary keyword match
    if prim and normalize_text(prim) in tnorm:
        score += 0.35
    else:
        # allow partial: any token overlap with primary phrase
        prim_tokens = set(tokenize(prim))
        if prim_tokens and prim_tokens.intersection(set(tokenize(text))):
            score += 0.25

    # Secondary match
    sec_tokens = set(tokenize(sec))
    if sec_tokens and sec_tokens.intersection(set(tokenize(text))):
        score += 0.20

    # Event + asset hints
    ev_hits = extract_terms(text, EVENT_TERMS)
    as_hits = extract_terms(text, ASSET_TERMS)
    if ev_hits:
        score += 0.20
    if as_hits:
        score += 0.15

    # Recency
    rd = compute_recency_days(pub_dt)
    if rd is not None and rd <= recency_days:
        score += 0.10

    return min(1.0, score)

# ------------ Provider adapters (start with RSS) ------------

def rss_search(query: str, max_items: int = 10) -> List[Dict]:
    """
    MVP approach: use a few curated RSS endpoints that accept query params.
    In real usage, you’ll define RSS endpoints per domain/source.
    This stub demonstrates how items flow through intake.

    Replace/extend with your chosen feeds.
    """
    results = []

    # Example: Google News RSS query endpoint (commonly used)
    # NOTE: If you prefer not to rely on this, replace with curated vendor/regulator feeds.
    gn_url = f"https://news.google.com/rss/search?q={requests.utils.quote(query)}&hl=en-US&gl=US&ceid=US:en"
    feed = feedparser.parse(gn_url)

    for entry in feed.entries[:max_items]:
        results.append({
            "title": entry.get("title", ""),
            "url": entry.get("link", ""),
            "publisher": entry.get("source", {}).get("title", "") if isinstance(entry.get("source", {}), dict) else "",
            "published": entry.get("published", ""),
            "summary": BeautifulSoup(entry.get("summary", "") or "", "html.parser").get_text(" ", strip=True),
        })

    return results

def parse_rss_date(s: str) -> Optional[datetime]:
    if not s:
        return None
    # feedparser usually gives 'published_parsed'
    # but we only have string here; do a best-effort parse:
    try:
        # feedparser can parse into struct_time if needed; simplest fallback:
        dt = datetime.strptime(s[:25], "%a, %d %b %Y %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

# ------------ Intake runner ------------

def load_profiles() -> pd.DataFrame:
    df = pd.read_csv(SEARCH_PROFILES_CSV)
    df = df[df["active"].astype(str).str.upper() == "TRUE"].copy()
    return df

def load_existing_cache() -> pd.DataFrame:
    if os.path.exists(EVIDENCE_CACHE_CSV):
        return pd.read_csv(EVIDENCE_CACHE_CSV)
    return pd.DataFrame(columns=[
        "evidence_id","profile_id","search_query","source_type","publisher","title","published_date",
        "ingested_date","url","normalized_title","raw_snippet","normalized_snippet",
        "event_keywords","asset_keywords","entity_keywords","business_function_hint","event_type_hint",
        "recency_days","is_duplicate_flag","relevance_score"
    ])

def is_duplicate(new_url: str, new_norm_title: str, new_publisher: str, new_pub_date: str, cache_df: pd.DataFrame) -> bool:
    if cache_df.empty:
        return False
    # URL match
    if "url" in cache_df.columns and new_url and (cache_df["url"] == new_url).any():
        return True
    # Title+publisher+date proximity (simple string)
    if new_norm_title and new_publisher and new_pub_date:
        subset = cache_df[
            (cache_df.get("normalized_title","").astype(str) == new_norm_title) &
            (cache_df.get("publisher","").astype(str).str.lower() == str(new_publisher).lower())
        ]
        if not subset.empty:
            return True
    return False

def run_intake():
    profiles = load_profiles()
    cache = load_existing_cache()

    new_rows = []

    for _, p in profiles.iterrows():
        profile_id = str(p.get("profile_id","")).strip()
        business_function = str(p.get("business_function","")).strip()
        recency_days = int(p.get("recency_days", 180) or 180)

        # Query generation (MVP)
        q_primary = str(p.get("primary_keywords","")).strip()
        q_secondary = str(p.get("secondary_keywords","")).strip()
        queries = []

        if q_primary:
            queries.append(q_primary)
        if q_primary and q_secondary:
            queries.append(f'"{q_primary}" "{q_secondary}"')
        if q_secondary:
            queries.append(q_secondary)

        # Deduplicate queries
        queries = list(dict.fromkeys([q for q in queries if q]))

        for q in queries:
            items = rss_search(q, max_items=10)

            for it in items:
                title = it.get("title","")
                url = it.get("url","")
                publisher = it.get("publisher","") or ""
                snippet = it.get("summary","") or ""

                pub_dt = parse_rss_date(it.get("published","") or "")
                pub_date_iso = pub_dt.date().isoformat() if pub_dt else ""

                norm_title = normalize_text(title)
                norm_snip = normalize_text(snippet)

                ev_terms = extract_terms(f"{title} {snippet}", EVENT_TERMS)
                as_terms = extract_terms(f"{title} {snippet}", ASSET_TERMS)

                # Entity extraction (MVP: empty or from maintained dictionary later)
                entity_terms = []  # placeholder for EntityDictionary-based extraction

                et_hint = event_type_hint(ev_terms, as_terms, f"{title} {snippet}")
                src_type = infer_source_type(url, publisher)

                rel = relevance_score(p, title, snippet, pub_dt)
                rd = compute_recency_days(pub_dt)

                dup = is_duplicate(url, norm_title, publisher, pub_date_iso, cache)

                row = {
                    "evidence_id": make_evidence_id(url) if url else f"EV-{hashlib.sha1((title+publisher).encode()).hexdigest()[:10].upper()}",
                    "profile_id": profile_id,
                    "search_query": q,
                    "source_type": src_type,
                    "publisher": publisher,
                    "title": title,
                    "published_date": pub_date_iso,
                    "ingested_date": now_iso(),
                    "url": url,
                    "normalized_title": norm_title,
                    "raw_snippet": snippet,
                    "normalized_snippet": norm_snip,
                    "event_keywords": ",".join(ev_terms),
                    "asset_keywords": ",".join(as_terms),
                    "entity_keywords": ",".join(entity_terms),
                    "business_function_hint": business_function,
                    "event_type_hint": et_hint,
                    "recency_days": rd if rd is not None else "",
                    "is_duplicate_flag": bool(dup),
                    "relevance_score": round(rel, 3),
                }

                new_rows.append(row)

    if not new_rows:
        print("No new evidence rows found.")
        return

    df_new = pd.DataFrame(new_rows)

    df_new.to_csv(EVIDENCE_CACHE_CSV, index=False)
    print(f"Wrote {len(df_new)} rows to {EVIDENCE_CACHE_CSV} (fresh run).")

if __name__ == "__main__":
    run_intake()
