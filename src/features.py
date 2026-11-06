"""
features.py - Step 2: Feature engineering.

Two feature families are computed, deliberately mirroring the two questions
the whole system asks:

1) LEXICAL / STRUCTURAL features - cheap signals computed purely from the URL
   string (length, token counts, hyphen/subdomain counts, suspicious-keyword
   density, character substitution, IP-host detection...). These power the
   Stage B classifiers.

2) DOMAIN-SIMILARITY features - Levenshtein / edit-distance and fuzzy-match
   against a small whitelist of well-known legitimate domains. A near-match to
   a brand ("paypa1.com") is a strong phishing flag, and it is ALSO useful to
   Stage A: a lookalike that does not resolve is exactly the kind of
   hallucinated URL an LLM produces.

WHY FEATURE EXTRACTION MAKES NO JUDGMENT
----------------------------------------
This module is deliberately question-agnostic. It computes *signals only* and
feeds both Stage A (grounding / existence) and Stage B (maliciousness). The
decisions "does it exist?" and "is it malicious?" are made exclusively in
hallucination_detector.py and the Stage B modules. Keeping the signal layer
separate from the decision layer is what makes the Stage A/Stage B separation
airtight and easy to defend in the viva.

All outputs are flat, numeric (int/float) dicts - they drop directly into a
pandas DataFrame and scikit-learn estimators with no encoding step.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Config - tunable signals, kept at the top for the report/viva.
# ---------------------------------------------------------------------------

# Words that appear all over phishing / hallucinated lookalike pages.
# A dense presence of these is a strong lexical red flag.
SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login", "verify", "signin", "sign-in", "account", "secure", "update",
    "billing", "password", "passwd", "confirm", "banking", "wallet", "auth",
    "token", "unlock", "suspended", "alert", "invoice", "reward", "prize",
    "gift", "webscr", "recover", "authenticate", "security",
)

# Small whitelist of well-known legitimate domains used for similarity
# scoring. Kept small per the project brief (no external PSL dependency).
LEGITIMATE_DOMAINS: Tuple[str, ...] = (
    "paypal.com", "google.com", "gmail.com", "apple.com", "amazon.com",
    "netflix.com", "microsoft.com", "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com", "ebay.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "coinbase.com", "github.com", "dropbox.com",
    "yahoo.com", "outlook.com", "whatsapp.com",
    # Malaysian brands/banks so local lookalikes ("maybank2u-login.com",
    # "cimbclicks.co") are fingerprinted instead of being treated as unknown.
    "maybank2u.com.my", "cimbclicks.com.my", "rhbgroup.com", "hlb.com.my",
    "publicbank.com.my", "bankislam.com.my", "bsn.com.my", "affinbank.com.my",
    "ambank.com.my", "grab.com", "touchngo.com.my", "shopeemobile.com",
    "lazada.com.my", "gov.my", "myeg.com.my", "tnb.com.my",
)

# Brand names (registration roots) for substring fingerprinting.
BRAND_ROOTS: Tuple[str, ...] = tuple(d.split(".")[0] for d in LEGITIMATE_DOMAINS)

# Multi-label TLDs so subdomain counting is sane without a full PSL list:
# "shop.paypal.co.uk" -> tld = "co.uk", one subdomain "shop".
TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
    "org.au", "co.in", "com.br", "com.mx", "co.nz", "com.sg", "com.my",
    "co.id", "com.pk", "com.bd", "com.tr", "co.za", "com.hk", "com.tw",
    "com.cn", "com.ph", "com.vn", "co.th", "com.eg", "com.sa", "com.ng",
    "com.ke", "org.za", "com.ar", "com.co",
    # Malaysian second-level domains - previously missing, so "maybank2u.com.my"
    # was parsed as registrable "com.my" with "maybank2u" as a SUBdomain, which
    # corrupted tld_length / subdomain_count and defeated the whitelist match.
    "gov.my", "org.my", "edu.my", "mil.my", "net.my",
})

# An edit distance <= LOOKALIKE_MAX_DIST to a legit brand flags a lookalike.
LOOKALIKE_MAX_DIST = 2
# Brand-name typo matching is stricter: one edit ("paypa1" -> "paypal") is a
# typo, two edits can turn an unrelated word into a brand ("gxbank" -> "ambank").
BRAND_TYPO_MAX_DIST = 1

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

    Uses the small TWO_PART_TLDS heuristic; clear naming makes the
    approximation visible and explainable.
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


# ===========================================================================
# Edit distance / similarity
# ===========================================================================


def levenshtein(a: str, b: str, cap: Optional[int] = None) -> int:
    """Levenshtein edit distance between two strings (optional early exit).

    Standard DP. `cap` lets the caller bound the work for hot loops: any
    distance known to exceed `cap` returns `cap + 1` instead.
    """
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
    """Count hostname tokens that are edits-away from a brand root.

    Whole-host Levenshtein is diluted by extra path segments
    ("paypa1-secure-login.invalid" -> 20 edits away from "paypal.com"), so we
    also scan each word token independently: "paypa1" is 1 edit from "paypal"
    and is the token that actually betrays the lookalike.
    """
    count = 0
    for seg in re.findall(r"[a-z0-9]{4,}", host):
        for b in BRAND_ROOTS:
            if len(b) >= 4 and levenshtein(seg, b, cap=LOOKALIKE_MAX_DIST) <= LOOKALIKE_MAX_DIST:
                count += 1
                break
    return count


def _substitution_flagged(host: str) -> bool:
    """Heuristic proxy for character substitution ('paypa1', 'app1e').

    True when a word token of the host mixes letters and digits AND is not
    itself a known brand/root. Plain homoglyph substitution almost always
    produces a digit-mixed token; the more precise signal (token is edits-away
    from a real brand) is caught by `near_legit_lookalike`, so this boolean is
    a cheap, recall-friendly backup.

    Legit brands that legitimately contain digits (e.g. "maybank2u",
    "touchngo", "yahoo") must NOT be flagged - an exact match to a known brand
    root short-circuits the check.
    """
    known = set(LEGITIMATE_DOMAINS) | set(BRAND_ROOTS)
    for seg in re.findall(r"[a-z0-9]{4,}", host):
        if seg in known:
            continue
        if any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            return True
    return False


def domain_similarity(url: object) -> Dict[str, float]:
    """Edit-distance / fuzzy match of the input host against LEGITIMATE_DOMAINS.

    Returns numeric features plus the best-match hostname (the latter is kept
    for human-readable "reason" strings, not fed to the models).
    """
    host = normalise_domain(url)
    best = {"min_levenshtein_dist": float("inf"),
            "max_domain_similarity": 0.0,
            "best_match_domain": "",
            "best_match_is_legit": 0,
            "near_legit_lookalike": 0}
    if not host:
        best["min_levenshtein_dist"] = -1.0
        return best

    # Legitimacy is decided on the REGISTRABLE domain, not the raw host:
    # www.paypal.com and accounts.paypal.com are both paypal.com. Matching the
    # raw host against the whitelist would flag every subdomain as a lookalike.
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

    # Lookalike := registrable domain is NOT a whitelisted legit domain but the
    # host is KNOWN to be a near-copy of one: whole-host edit distance, brand
    # substring fingerprint ("paypal-secure."), or a per-segment edit match
    # ("paypa1"). A strong signal for BOTH stages.
    if not is_legit:
        if (dist <= LOOKALIKE_MAX_DIST
                or any(b in host for b in BRAND_ROOTS)
                or _segment_lookalike_count(host) > 0):
            best["near_legit_lookalike"] = 1
    return best


# ===========================================================================
# Main feature extractor
# ===========================================================================


def extract_features(url: object) -> Dict[str, float]:
    """Compute the full numeric feature vector for one URL.

    Returns a flat dict of int/float values - directly consumable by pandas
    or scikit-learn. Two families: lexical/structural + domain-similarity.
    """
    s = str(url or "").strip()
    if not s:
        s = "https://"  # degenerate input; features will be all-empty/explicit
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s):
        s = "https://" + s

    p = urlparse(s)
    host = (p.hostname or "").lower()
    path = unquote(p.path or "")
    query = unquote(p.query or "")
    full = s.lower()

    feats: Dict[str, float] = {}

    # ---- 1) lexical / structural ---------------------------------------
    feats["url_length"] = float(len(s))
    feats["hostname_length"] = float(len(host))
    feats["path_length"] = float(len(path))
    feats["query_length"] = float(len(query))
    feats["num_query_params"] = float(len(parse_qs(p.query)))
    feats["is_https"] = float((p.scheme or "").lower() == "https")

    tokens = re.findall(r"[a-z0-9]+", f"{host}/{path}")
    feats["token_count"] = float(len(tokens))

    total_digits = sum(c.isdigit() for c in s)
    feats["digit_ratio"] = total_digits / float(max(len(s), 1))
    host_digits = sum(c.isdigit() for c in host)
    feats["hostname_digit_ratio"] = host_digits / float(max(len(host), 1))

    feats["hyphen_count"] = float(s.count("-"))
    feats["underscore_count"] = float(s.count("_"))
    feats["at_symbol_count"] = float(s.count("@"))
    feats["special_char_count"] = float(
        sum(1 for c in s if c in set("!#$%&'*+,;=[]^{|}~`")))
    feats["double_slash_after_scheme"] = float(
        (re.search(r"://[^/]*//", s) is not None))

    feats["has_ip_address"] = float(bool(IPV4_RE.match(host.split(":")[0])))
    feats["punycode_present"] = float("xn--" in host)

    suffix, _, sub = _split_host(host)
    feats["tld_length"] = float(len(suffix))
    feats["subdomain_count"] = float(len(sub.split("."))) if sub else 0.0

    kw_hits = sum(full.count(k) for k in SUSPICIOUS_KEYWORDS)
    feats["suspicious_keyword_count"] = float(kw_hits)
    feats["suspicious_keyword_present"] = float(kw_hits > 0)

    # Brand substring fingerprinting: "paypal-secure.invalid" mentions paypal.
    host_brand_hits = sum(1 for b in BRAND_ROOTS if len(b) >= 4 and b in host)
    feats["hostname_brand_hits"] = float(host_brand_hits)
    feats["brand_present"] = float(host_brand_hits > 0)

    # CRUCIAL separation (the PhiUSIIL->Malaysia gap): the model must be able to
    # tell "the brand owns this domain" from "the brand is pasted into someone
    # else's domain". PhiUSIIL's brand+non-.com pattern is mostly phishing, so a
    # legit bank on its OWN domain (maybank2u.com.my) was previously scored as
    # phishing. We expose the distinction explicitly:
    #   brand_on_own_domain     - brand root inside the REGISTRABLE domain
    #                             (maybank2u.com.my -> "maybank2u.com.my")
    #   brand_on_foreign_domain - brand root in the host but NOT in the
    #                             registrable domain (maybank2u-secure.com)
    _, registrable, _ = _split_host(host)
    reg_root = registrable.split(".")[0] if registrable else ""
    brand_words = [b for b in BRAND_ROOTS if len(b) >= 4]
    # EXACT core match: "maybank2u.com.my" -> reg_root "maybank2u" == brand root.
    # A longer fake core ("maybank2u-secure-login") must NOT count as owning the
    # brand - only an exact registrable core does.
    own = int(reg_root in brand_words)
    foreign = int(host_brand_hits > 0 and not own)
    feats["brand_on_own_domain"] = float(own)
    feats["brand_on_foreign_domain"] = float(foreign)

    # Character substitution: an ordinary URL rarely mixes letters and digits
    # inside a single word-token; a homoglyph ('paypa1', 'app1e') almost
    # always does. The edits-away-from-a-brand check reinforces this below.
    feats["character_substitution_flagged"] = float(_substitution_flagged(host))

    # ---- 2) domain-similarity (Levenshtein / fuzzy vs whitelist) --------
    sim = domain_similarity(s)
    feats["min_levenshtein_dist"] = sim["min_levenshtein_dist"]
    feats["max_domain_similarity"] = sim["max_domain_similarity"]
    feats["best_match_is_legit"] = sim["best_match_is_legit"]
    feats["near_legit_lookalike"] = sim["near_legit_lookalike"]
    # Per-segment lookalikes only matter for hosts whose registrable domain is
    # NOT already whitelisted; "paypal" inside www.paypal.com is not a red flag.
    feats["segment_lookalike_count"] = float(
        0 if sim["best_match_is_legit"] else _segment_lookalike_count(host))
    feats["character_substitution_flagged"] = float(
        _substitution_flagged(host) or (feats["segment_lookalike_count"] > 0))

    return feats


# Deterministic column order - critical so train and predict always align.
FEATURE_NAMES: Tuple[str, ...] = (
    "url_length", "hostname_length", "path_length", "query_length",
    "num_query_params", "is_https", "token_count", "digit_ratio",
    "hostname_digit_ratio", "hyphen_count", "underscore_count",
    "at_symbol_count", "special_char_count", "double_slash_after_scheme",
    "has_ip_address", "punycode_present", "tld_length", "subdomain_count",
    "suspicious_keyword_count", "suspicious_keyword_present",
    "hostname_brand_hits", "brand_present",
    "brand_on_own_domain", "brand_on_foreign_domain",
    "character_substitution_flagged",
    "min_levenshtein_dist", "max_domain_similarity", "best_match_is_legit",
    "near_legit_lookalike", "segment_lookalike_count",
)


def best_match_domain(url: object) -> Tuple[str, float]:
    """Return (closest legit domain, similarity ratio) for explainability.

    Directly reused by the pipeline "reason" strings - the models never see
    the string, only the numeric feature columns above.
    """
    sim = domain_similarity(url)
    return sim["best_match_domain"], sim["max_domain_similarity"]


# ===========================================================================
# Brand impersonation / official-verification (Stage B verdict hints)
#
# These helpers are NOT part of the 28-dimension classifier vector. They back
# the Stage B decision layer (risk_scoring.decide_verdict): a positive
# "official match" is the exact-match confirmation that earns a VERIFIED label,
# and an "impersonation" flag floors the label at SUSPICIOUS.
# ===========================================================================

# Official registrable domains per brand (the "blessed" list). Non-exhaustive
# and educational; extend per the target brands in the report.
BRAND_OFFICIAL_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com",),
    "apple": ("apple.com",),
    "amazon": ("amazon.com",),
    "google": ("google.com", "googleusercontent.com"),
    "microsoft": ("microsoft.com",),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "netflix": ("netflix.com",),
    "ebay": ("ebay.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "coinbase": ("coinbase.com",),
    "github": ("github.com",),
    "dropbox": ("dropbox.com",),
    # Malaysian banks / brands (the PhiUSIIL model has never seen these as
    # legitimate, so they must be confirmed by exact official-domain match).
    "maybank": ("maybank2u.com.my", "maybank.com.my", "maybank.com"),
    "maybank2u": ("maybank2u.com.my",),
    "cimb": ("cimbclicks.com.my", "cimb.com.my", "cimb.com"),
    "cimbclicks": ("cimbclicks.com.my",),
    "rhb": ("rhbgroup.com", "rhb.com.my"),
    "hlb": ("hlb.com.my",),
    "hongleong": ("hlb.com.my", "hongleong.com"),
    "publicbank": ("pbebank.com", "publicbank.com.my"),
    "pbebank": ("pbebank.com",),
    "bankislam": ("bankislam.com.my", "bankislam.com"),
    "bsn": ("bsn.com.my",),
    "ambank": ("ambank.com.my", "ambankgroup.com"),
    "affinbank": ("affinbank.com.my",),
    "touchngo": ("touchngo.com.my", "tngdigital.com.my"),
    "tng": ("touchngo.com.my", "tngdigital.com.my"),
    "grab": ("grab.com",),
    "airasia": ("airasia.com",),
    "lazada": ("lazada.com.my", "lazada.com"),
    "shopee": ("shopee.com.my", "shopee.com"),
    # Major global sites whose official domains are not in the brand list above.
    "wikipedia": ("wikipedia.org", "wikimedia.org"),
    "youtube": ("youtube.com", "youtu.be"),
    "reddit": ("reddit.com",),
    "bing": ("bing.com",),
    "cloudflare": ("cloudflare.com",),
    "mozilla": ("mozilla.org", "firefox.com"),
    "stackoverflow": ("stackoverflow.com",),
    "twitter": ("twitter.com", "x.com"),
}


def _detected_brands(host: str) -> List[str]:
    """Brands whose root appears as a host substring OR as an edits-away
    token ('paypa1' ~ 'paypal'). Used to decide impersonation."""
    found, seen = [], set()
    tokens = re.findall(r"[a-z0-9]{4,}", host)
    for brand in BRAND_OFFICIAL_DOMAINS:
        if len(brand) < 4:
            continue
        if brand in host:
            found.append(brand)
            continue
        if any(levenshtein(t, brand, cap=BRAND_TYPO_MAX_DIST) <= BRAND_TYPO_MAX_DIST
               for t in tokens):
            found.append(brand)
    return found


def brand_profile(url: object) -> Dict:
    """Verdict hints: does the URL claim a brand, and is it the real one?

    Returns:
        official_match     True  -> registrable domain IS on the brand's
                                    official list (positive confirmation)
        official_brand     matched brand when official_match
        impersonation      1     -> brand present in host but registrable
                                    domain is NOT official for that brand
        matched_brand       brand signal that fired (or "")
    """
    host = normalise_domain(url)
    _, registrable, _ = _split_host(host)
    profile = {"official_match": False, "official_brand": "",
               "impersonation": 0, "matched_brand": ""}
    if not host or not registrable:
        return profile

    brands = _detected_brands(host)
    for brand in brands:
        if registrable in BRAND_OFFICIAL_DOMAINS.get(brand, ()):
            profile["official_match"] = True
            profile["official_brand"] = brand
            profile["matched_brand"] = brand
            return profile
    if brands:
        # A brand is being claimed but the domain is not that brand's.
        profile["impersonation"] = 1
        profile["matched_brand"] = brands[0]
    return profile


# Verified official sites (research, see data/regression): Malaysian banks and
# government portals. Allowlist only - kept out of BRAND_OFFICIAL_DOMAINS so the
# brand-detection features (and the trained models) stay unchanged.
OFFICIAL_EXTRA_DOMAINS: Tuple[str, ...] = (
    "bankrakyat.com.my", "alliancebank.com.my", "ocbc.com.my", "uob.com.my",
    "hsbc.com.my", "bnm.gov.my", "sc.com.my", "imi.gov.my", "spr.gov.my",
    "mycert.org.my", "jpn.gov.my", "malaysia.gov.my", "mof.gov.my", "motac.gov.my",
    # AmBank promotions site: linked from the official ambank.com.my (verified).
    "ambankspot.com",
)

# Every official domain, flattened once, for the exact-match fast path.
_ALL_OFFICIAL_DOMAINS = frozenset(
    d for domains in BRAND_OFFICIAL_DOMAINS.values() for d in domains
) | frozenset(LEGITIMATE_DOMAINS) | frozenset(OFFICIAL_EXTRA_DOMAINS)


def is_known_legit_domain(url: object) -> bool:
    """Exact registrable-domain match against a curated official-domain list.

    TRUE only when the URL's REGISTRABLE domain is exactly an official domain
    (e.g. "maybank2u.com.my", "www.maybank2u.com.my/login"). FALSE for
    lookalikes ("maybank2u-secure-login.com") and for embedded-host tricks
    ("maybank2u.com.my.evil.net"), because the registrable domain there is
    "secure-login.com" / "evil.net", not the official one.

    This is the positive-override signal: a curated official domain must never
    be flagged by the PhiUSIIL-trained model, which has never seen Malaysian
    banks as legitimate.
    """
    host = normalise_domain(url)
    if not host:
        return False
    _, registrable, _ = _split_host(host)
    return bool(registrable) and registrable in _ALL_OFFICIAL_DOMAINS


def build_feature_matrix(df, url_col: str = "url") -> "pd.DataFrame":
    """Vectorise a DataFrame of urls into a feature matrix (same row order).

    Rows whose url fails to parse become all-NaN feature rows, so the caller
    can decide whether to drop or impute. Feature column order is fixed by
    FEATURE_NAMES.
    """
    import pandas as pd

    records = []
    for url in df[url_col]:
        try:
            records.append(extract_features(url))
        except Exception:
            records.append({k: float("nan") for k in FEATURE_NAMES})
    return pd.DataFrame(records, index=df.index, columns=list(FEATURE_NAMES))