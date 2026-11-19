"""
feature_extractor.py - URL feature engineering + heuristic URL analysis.

Two responsibilites, kept deliberately separate in spirit:

1) EXTRACT_FEATURES - the exact 28-column vector that powers the ML
   classifiers. Order is fixed by FEATURE_NAMES and MUST stay aligned with
   models/feature_names.json. Any change here requires retraining.

2) HEURISTIC SCORE - a pure-rule, explainable 0-1 risk score computed from
   URL text characteristics (Section 9 of the FYP brief). Every feature is
   documented below. This is a SEPARATE signal from machine learning - it is
   used by threat verification and confidence scoring, never fused into the
   ML feature vector.

The heuristic does NOT decide "phishing vs legitimate" on its own. It
produces evidence; decisioning lives in threat_verification / confidence.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Config - tunable signals.
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login", "verify", "signin", "sign-in", "account", "secure", "update",
    "billing", "password", "passwd", "confirm", "banking", "wallet", "auth",
    "token", "unlock", "suspended", "alert", "invoice", "reward", "prize",
    "gift", "webscr", "recover", "authenticate", "security",
)

LEGITIMATE_DOMAINS: Tuple[str, ...] = (
    "paypal.com", "google.com", "gmail.com", "apple.com", "amazon.com",
    "netflix.com", "microsoft.com", "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com", "ebay.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "coinbase.com", "github.com", "dropbox.com",
    "yahoo.com", "outlook.com", "whatsapp.com",
)

BRAND_ROOTS: Tuple[str, ...] = tuple(d.split(".")[0] for d in LEGITIMATE_DOMAINS)

TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
    "org.au", "co.in", "com.br", "com.mx", "co.nz", "com.sg", "com.my",
    "co.id", "com.pk", "com.bd", "com.tr", "co.za", "com.hk", "com.tw",
    "com.cn", "com.ph", "com.vn", "co.th", "com.eg", "com.sa", "com.ng",
    "com.ke", "org.za", "com.ar", "com.co",
})

LOOKALIKE_MAX_DIST = 2
IPV4_RE = re.compile(r"^(\d{1,3})(\.\d{1,3}){3}$")


# ===========================================================================
# Domain helpers
# ===========================================================================


def normalise_domain(url: object) -> str:
    """Lowercased hostname without scheme/port/userinfo ('' if unusable)."""
    s = str(url or "").strip()
    if not s:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s):
        s = "https://" + s
    try:
        return (urlparse(s).hostname or "").lower()
    except ValueError:
        return ""


def _split_host(host: str) -> Tuple[str, str, str]:
    """Return (public_suffix, registrable_domain, subdomains).

    Uses the small TWO_PART_TLDS heuristic; the approximation is visible
    and explainable (no external PSL dependency per project brief).
    """
    parts = host.split(".") if host else []
    if len(parts) == 0:
        return "", "", ""
    if (
        len(parts) >= 3
        and f"{parts[-2]}.{parts[-1]}" in TWO_PART_TLDS
    ):
        suffix = f"{parts[-2]}.{parts[-1]}"
        registrable = parts[-3] + "." + suffix if len(parts) >= 3 else suffix
    else:
        suffix = parts[-1]
        registrable = parts[-2] + "." + suffix if len(parts) >= 2 else parts[-1]
    sub = ".".join(parts[: -registrable.count(".") - 1]) if len(parts) > registrable.count(".") + 1 else ""
    return suffix, registrable, sub


def levenshtein(a: str, b: str, cap: Optional[int] = None) -> int:
    """Levenshtein edit distance between two strings (optional early exit)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if cap is not None and abs(la - lb) > cap:
        return cap + 1
    prev: List[int] = list(range(lb + 1))
    for i in range(1, la + 1):
        cur: List[int] = [i]
        a_i = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if a_i == b[j - 1] else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        if cap is not None and min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[lb]


def similarity_ratio(a: str, b: str) -> float:
    """1 - dist/max(len) : 1.0 = identical, 0.0 = totally unrelated."""
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    return 1.0 - levenshtein(a, b) / float(max(la, lb))


def _segment_lookalike_count(host: str) -> int:
    count = 0
    for seg in re.findall(r"[a-z0-9]{4,}", host):
        for b in BRAND_ROOTS:
            if len(b) >= 4 and levenshtein(seg, b, cap=LOOKALIKE_MAX_DIST) <= LOOKALIKE_MAX_DIST:
                count += 1
                break
    return count


def _substitution_flagged(host: str) -> bool:
    for seg in re.findall(r"[a-z0-9]{4,}", host):
        if any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            return True
    return False


def domain_similarity(url: object) -> Dict[str, float]:
    """Edit-distance / fuzzy match of the input host against LEGITIMATE_DOMAINS."""
    host = normalise_domain(url)
    best = {"min_levenshtein_dist": float("inf"),
            "max_domain_similarity": 0.0,
            "best_match_domain": "",
            "best_match_is_legit": 0,
            "near_legit_lookalike": 0}
    if not host:
        best["min_levenshtein_dist"] = -1.0
        return best

    _, registrable, _ = _split_host(host)
    is_legit = int(bool(registrable) and registrable in LEGITIMATE_DOMAINS)
    best["best_match_is_legit"] = is_legit
    best["best_match_domain"] = registrable if is_legit else ""

    best_legit, dist, ratio = "", float("inf"), 0.0
    for legit in LEGITIMATE_DOMAINS:
        d = levenshtein(host, legit)
        if d < dist:
            dist, ratio = d, similarity_ratio(host, legit)
            best_legit = legit
    best["min_levenshtein_dist"] = float(dist)
    best["max_domain_similarity"] = ratio
    if best["best_match_domain"] == "":
        best["best_match_domain"] = best_legit

    if not is_legit:
        if (dist <= LOOKALIKE_MAX_DIST
                or any(b in host for b in BRAND_ROOTS)
                or _segment_lookalike_count(host) > 0):
            best["near_legit_lookalike"] = 1
    return best


# ===========================================================================
# Main ML feature extractor
# ===========================================================================


# The ML feature vector is now defined ONCE, in the canonical src/features.py,
# and re-exported here so the retired modules/ tree cannot drift from the models
# in models/ (which are trained on src/features.py values). Previously this file
# duplicated the 28-feature vector and silently produced the WRONG column count
# after src/features.py grew.
import sys as _sys
from pathlib import Path as _Path

_SRC = _Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in _sys.path:
    _sys.path.insert(0, str(_SRC))

from features import FEATURE_NAMES as _CANONICAL_NAMES  # noqa: E402
from features import extract_features as _canonical_extract  # noqa: E402

FEATURE_NAMES: Tuple[str, ...] = tuple(_CANONICAL_NAMES)


def extract_features(url: object) -> Dict[str, float]:
    """Compute the full numeric ML vector for one URL (canonical src/features).

    Delegates to src/features.py - the single source of truth the models in
    models/ are trained on. Do not change semantics without retraining.
    """
    return _canonical_extract(url)


def best_match_domain(url: object) -> Tuple[str, float]:
    """Return (closest legit domain, similarity ratio) for explainability."""
    sim = domain_similarity(url)
    return sim["best_match_domain"], sim["max_domain_similarity"]


def build_feature_matrix(df, url_col: str = "url") -> "pd.DataFrame":
    """Vectorise a DataFrame of urls into a feature matrix (same row order)."""
    import pandas as pd

    records = []
    for url in df[url_col]:
        try:
            records.append(extract_features(url))
        except Exception:
            records.append({k: float("nan") for k in FEATURE_NAMES})
    return pd.DataFrame(records, index=df.index, columns=list(FEATURE_NAMES))


# ===========================================================================
# Heuristic URL analysis (Section 9 of the FYP brief)
# ===========================================================================
#
# Each feature is normalised to [0,1] with a documented reason, then combined
# with HEURISTIC_WEIGHTS. The weights are an explainable baseline - they are
# NOT tuned and are documented as such in the project report.
#
# Feature map:
#   url length        long URLs are used to bury the payload            threshold 100
#   dots              many labels = obfuscation                        threshold 4
#   hyphens           hyphens inside the hostname obscure the brand    threshold 3
#   subdomains        extra layers mislead the user                    threshold 2
#   special chars     unusual characters in host                      any count
#   digits in host    homoglyph substitution (paypa1)                  ratio
#   no https          missing transport security                       0/1
#   IP address host   raw IP hosting is a strong phishing signal       0/1
#   @ symbol          userinfo tricks the user                         0/1
#   suspicious kw     login/verify/secure... density                   0/1 presence
#   path length       long nested paths are suspicious                 threshold 50
#   query length      encoded payloads hide in query strings           threshold 50

HEURISTIC_FEATURES = (
    "url_length", "dots", "hyphens", "subdomains", "special_chars",
    "host_digit_density", "no_https", "ip_address", "at_symbol",
    "suspicious_keywords", "lookalike_brand", "path_length", "query_length",
)

# Weights sum to 1.0. Baseline only - not claimed optimal.
HEURISTIC_WEIGHTS: Dict[str, float] = {
    "url_length": 0.09,
    "dots": 0.07,
    "hyphens": 0.07,
    "subdomains": 0.07,
    "special_chars": 0.05,
    "host_digit_density": 0.09,
    "no_https": 0.05,
    "ip_address": 0.12,
    "at_symbol": 0.10,
    "suspicious_keywords": 0.08,
    "lookalike_brand": 0.11,
    "path_length": 0.05,
    "query_length": 0.05,
}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def heuristic_components(url: object) -> Dict[str, float]:
    """Compute the raw normalized 0-1 heuristic sub-scores for a URL."""
    s = str(url or "").strip()
    parsed = urlparse(s if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s) else "https://" + s)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    ip_host = bool(IPV4_RE.match(host.split(":")[0]))

    comps = {
        "url_length": _clamp01((len(s) - 40) / 60.0),          # >100 -> 1.0
        "dots": _clamp01((host.count(".") - 1) / 3.0),         # >=4 dots -> 1.0
        "hyphens": _clamp01(host.count("-") / 3.0),            # >=3 hyphens -> 1.0
        "subdomains": _clamp01((len(host.split(".")) - 2) / 2.0),  # >=4 labels -> 1.0
        "special_chars": _clamp01(sum(1 for c in host if not c.isalnum() and c not in ".-")
                                  / 2.0),
        "host_digit_density": sum(c.isdigit() for c in host) / float(max(len(host), 1)),
        "no_https": 1.0 if (parsed.scheme or "").lower() != "https" else 0.0,
        "ip_address": 1.0 if ip_host else 0.0,
        "at_symbol": 1.0 if "@" in host or "@" in s else 0.0,
        "suspicious_keywords": 1.0 if any(k in s.lower() for k in SUSPICIOUS_KEYWORDS)
                               else 0.0,
        "lookalike_brand": 1.0 if (domain_similarity(s).get("near_legit_lookalike")
                                   or _substitution_flagged(host)) else 0.0,
        "path_length": _clamp01((len(path) - 10) / 40.0),      # >=50 chars -> 1.0
        "query_length": _clamp01((len(query) - 10) / 40.0),    # >=50 chars -> 1.0
    }
    return comps


def heuristic_score(url: object) -> Dict[str, float]:
    """Weighted, explainable 0-1 risk score plus the component breakdown."""
    comps = heuristic_components(url)
    score = sum(HEURISTIC_WEIGHTS[k] * comps[k] for k in HEURISTIC_FEATURES)
    return {
        "score": _clamp01(score),
        "components": comps,
        "weights": dict(HEURISTIC_WEIGHTS),
    }